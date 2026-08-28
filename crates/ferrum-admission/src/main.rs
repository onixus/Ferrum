//! Admission webhook and offline FADM evaluator. Not a compiler.

#![deny(unsafe_code)]

use ferrum_admission::{
    admit_bytes, load_path, parse_trust_root, poll_bundle_file, poll_exceptions_file,
    poll_serving_cert, serve_listener, verify_exceptions_fsig, AdmissionSubject, ClusterLabels,
    LabelSource, ReviewConfig, StaticLabels, TlsSource, WebhookState,
};
use ferrum_api::PolicyExceptionSpec;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("review") => cmd_review(&args[2..]),
        Some("serve") => cmd_serve(&args[2..]),
        _ => cmd_eval(&args),
    }
}

fn cmd_eval(args: &[String]) {
    if args.len() != 3 {
        eprintln!("usage: ferrum-admission <program.fadm> <subject.json>");
        eprintln!("       ferrum-admission review --bundle <fsig> --trust-root <32-byte-hex> [--exceptions <exceptions.fsig> --policy-name <name>] <admissionreview.json>");
        eprintln!("       ferrum-admission serve --listen 127.0.0.1:8443 --bundle <fsig|secret.json|dir> --trust-root <32-byte-hex> [--exceptions <mount> --policy-name <name>] [--tls-cert --tls-key] [--reload-ms 1000] [--apiserver [host:port]] [--cluster-label k=v]");
        eprintln!("missing or invalid compiled program denies the request (fail closed)");
        exit(2);
    }

    let program = match std::fs::read(&args[1]) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("error: read {}: {err}", args[1]);
            exit(2);
        }
    };
    let subject_raw = match std::fs::read_to_string(&args[2]) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("error: read {}: {err}", args[2]);
            exit(2);
        }
    };
    let subject: AdmissionSubject = match serde_json::from_str(&subject_raw) {
        Ok(subject) => subject,
        Err(err) => {
            eprintln!("error: subject json: {err}");
            exit(2);
        }
    };

    let decision = admit_bytes(&program, &subject, &[], chrono::Utc::now());
    match serde_json::to_string_pretty(&decision) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("error: encode decision: {err}");
            exit(2);
        }
    }
    if decision.allowed {
        exit(0);
    }
    exit(1);
}

fn cmd_review(args: &[String]) {
    let flags = parse_flags(args);
    let bundle_path = require_flag(&flags, "bundle");
    let trust_hex = require_flag(&flags, "trust-root");
    let review_path = flags.positional.first().cloned().unwrap_or_else(|| {
        die("usage: review --bundle <fsig> --trust-root <hex> <admissionreview.json>")
    });

    let trust_root = match parse_trust_root(&trust_hex) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("error: trust-root: {err}");
            exit(2);
        }
    };
    let program = match load_path(Path::new(&bundle_path), &trust_root) {
        Ok((p, _)) => p,
        Err(err) => {
            eprintln!("error: bundle: {err}");
            exit(2);
        }
    };
    let (exceptions, cfg) = exceptions_and_config(&flags, &trust_root);
    let body = read_file(&review_path);
    let reply = cfg.handle_bytes(&body, Some(&program), &exceptions, chrono::Utc::now());
    match serde_json::from_slice::<serde_json::Value>(&reply.body) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default()),
        Err(_) => {
            let _ = std::io::Write::write_all(&mut std::io::stdout(), &reply.body);
        }
    }
    let allowed = reply.status == 200
        && serde_json::from_slice::<serde_json::Value>(&reply.body)
            .ok()
            .and_then(|v| v["response"]["allowed"].as_bool())
            .unwrap_or(false);
    if allowed {
        exit(0);
    }
    exit(1);
}

fn cmd_serve(args: &[String]) {
    let flags = parse_flags(args);
    let bundle_path = require_flag(&flags, "bundle");
    let trust_hex = require_flag(&flags, "trust-root");
    let listen = flags
        .get("listen")
        .filter(|s| !s.is_empty())
        .unwrap_or("127.0.0.1:8443")
        .to_string();

    let trust_root = match parse_trust_root(&trust_hex) {
        Ok(k) => k,
        Err(err) => {
            eprintln!("error: trust-root: {err}");
            exit(2);
        }
    };
    let watch_path = std::path::PathBuf::from(&bundle_path);
    let program = match load_path(&watch_path, &trust_root) {
        Ok((p, _)) => p,
        Err(err) => {
            eprintln!("error: bundle: {err}");
            exit(2);
        }
    };
    // In serve mode --exceptions is a mount, not a static file: the list is
    // hot-reloaded alongside the bundle. Missing file = empty list.
    let mut cfg = review_config(&flags);
    cfg.labels = label_source(&flags);
    let exceptions_path = flags
        .get("exceptions")
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);
    if exceptions_path.is_some() && cfg.policy_name.is_empty() {
        die("--policy-name is required when --exceptions is set");
    }
    let tls = match (flags.get("tls-cert"), flags.get("tls-key")) {
        (Some(cert), Some(key)) if !cert.is_empty() && !key.is_empty() => {
            // An expired or unreadable serving certificate is a hard start
            // failure: under failurePolicy: Fail a handshake the API server
            // rejects stops Pod creation cluster-wide.
            match TlsSource::load(cert, key) {
                Ok(source) => Some(source),
                Err(err) => {
                    eprintln!("error: tls: {err}");
                    exit(2);
                }
            }
        }
        (None, None) => None,
        _ => {
            eprintln!("error: --tls-cert and --tls-key must be provided together");
            exit(2);
        }
    };

    let reload_ms: u64 = match flags.get("reload-ms") {
        Some(s) if !s.is_empty() => s.parse().unwrap_or_else(|_| die("invalid --reload-ms")),
        _ => 1000,
    };

    let state = Arc::new(WebhookState::new(program, trust_root, Vec::new(), cfg));
    if let Some(path) = &exceptions_path {
        if let Err(err) = state.try_reload_exceptions_path(path) {
            eprintln!("ferrum-admission: exceptions load failed, starting with empty list: {err}");
        }
    }
    let listener = match std::net::TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(err) => {
            eprintln!("error: bind {listen}: {err}");
            exit(2);
        }
    };
    eprintln!("ferrum-admission listening on {listen}");
    poll_bundle_file(
        watch_path,
        Duration::from_millis(reload_ms),
        Arc::clone(&state),
    );
    if let Some(path) = exceptions_path {
        poll_exceptions_file(path, Duration::from_millis(reload_ms), Arc::clone(&state));
    }
    if let Some(source) = &tls {
        poll_serving_cert(Arc::clone(source), Duration::from_millis(reload_ms));
    }
    if let Err(err) = serve_listener(listener, state, tls) {
        eprintln!("error: serve: {err}");
        exit(2);
    }
}

/// Every occurrence of every flag, in argv order.
///
/// `None` inside the vector is "the flag was written and no value followed
/// it" — end of argv, or a next token that is itself a flag. That used to be
/// flattened into an empty string, which is a *different* thing an operator
/// can also write, and for `--cluster-label` the two mean opposite things:
/// `--cluster-label ""` states a cluster carrying no labels, so a cluster
/// selector is answered with a miss, while `--cluster-label --apiserver kube`
/// is a typo whose value was eaten by the next flag. Both reached
/// `ClusterLabels::stated({})`, so a slip of the shell turned a fail-closed
/// selector into a silent non-match.
///
/// Keeping every occurrence rather than the last is the second half: the map
/// was last-wins, so `--cluster-label a=1 --cluster-label b=2` dropped `a=1`
/// with nothing said. `ferrum-cli`'s FD025 finds that shape in a manifest for
/// the flags an install *joins* against a Secret name; it is not this, and
/// nothing under `deploy/` passes `--cluster-label` at all, so the argv that
/// carries it is one a human typed and only this parser ever sees.
struct Flags {
    occurrences: BTreeMap<String, Vec<Option<String>>>,
    positional: Vec<String>,
}

impl Flags {
    /// The value the process runs with. Last occurrence wins and a flag whose
    /// value was eaten reads as empty — the behaviour every other flag here
    /// has always had, and the behaviour `ferrum-cli`'s `parse_argv` models
    /// when it proves a join. Flags that must not lose an occurrence read
    /// [`Flags::occurrences`] instead.
    fn get(&self, name: &str) -> Option<&str> {
        self.occurrences
            .get(name)
            .and_then(|all| all.last())
            .map(|value| value.as_deref().unwrap_or(""))
    }

    /// Every occurrence, so a repeatable flag can accumulate and a swallowed
    /// value can be told from an empty one.
    fn occurrences(&self, name: &str) -> &[Option<String>] {
        self.occurrences.get(name).map(Vec::as_slice).unwrap_or(&[])
    }
}

fn parse_flags(args: &[String]) -> Flags {
    let mut occurrences: BTreeMap<String, Vec<Option<String>>> = BTreeMap::new();
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(rest) = a.strip_prefix("--") {
            let (key, value) = match rest.split_once('=') {
                Some((k, v)) => (k.to_string(), Some(v.to_string())),
                None => match args.get(i + 1) {
                    Some(val) if !val.starts_with("--") => {
                        i += 1;
                        (rest.to_string(), Some(val.clone()))
                    }
                    _ => (rest.to_string(), None),
                },
            };
            occurrences.entry(key).or_default().push(value);
        } else {
            positional.push(a.clone());
        }
        i += 1;
    }
    Flags {
        occurrences,
        positional,
    }
}

fn require_flag(flags: &Flags, name: &str) -> String {
    match flags.get(name) {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => die(&format!("missing --{name}")),
    }
}

fn review_config(flags: &Flags) -> ReviewConfig {
    ReviewConfig {
        policy_name: flags.get("policy-name").unwrap_or_default().to_string(),
        policy_namespace: flags
            .get("policy-namespace")
            .unwrap_or_default()
            .to_string(),
        ..Default::default()
    }
}

/// `--cluster-label k=v`, repeatable as `k=v,k2=v2`. MVP-1 has no cluster
/// object to read these from; they are operator-stated, not discovered.
///
/// This is the one caller that knows whether the flag was *passed*, so it is
/// the one that must say so. `--cluster-label ""` states a cluster with no
/// labels: the operator was heard, and a cluster selector answers with a miss
/// rather than failing closed. No flag at all is `unstated`, and a policy
/// carrying a cluster selector still denies.
fn cluster_labels(flags: &Flags) -> ClusterLabels {
    match parse_cluster_labels(flags.occurrences("cluster-label")) {
        Ok(labels) => labels,
        Err(msg) => die(&msg),
    }
}

/// The parse, split off `cluster_labels` so it can be asserted instead of
/// exiting the process.
///
/// Three refusals, and each of them used to be a silent `stated({})` — a
/// cluster the webhook believes it was told about, carrying no labels, so
/// every cluster selector answers with a miss instead of failing closed:
///
///   * a flag with no value at all (`--cluster-label --apiserver kube`, or
///     `--cluster-label` at the end of argv);
///   * the same key twice with different values;
///   * a repeat, where the last-wins map dropped every earlier occurrence.
///     Repeats now accumulate, which is what `k=v,k2=v2` already meant within
///     one occurrence.
///
/// `--cluster-label ""` and `--cluster-label=` stay what they were: the
/// operator was heard and named a cluster with no labels.
fn parse_cluster_labels(occurrences: &[Option<String>]) -> Result<ClusterLabels, String> {
    if occurrences.is_empty() {
        return Ok(ClusterLabels::unstated());
    }
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for occurrence in occurrences {
        let Some(raw) = occurrence else {
            return Err(
                "--cluster-label was given no value: the next argument is another flag, or the                  flag ends the command line. To state a cluster that carries no labels, write                  --cluster-label='' — silently reading a typo as that is how a fail-closed                  cluster selector becomes a miss"
                    .into(),
            );
        };
        for pair in raw.split(',').filter(|s| !s.trim().is_empty()) {
            match pair.split_once('=') {
                Some((k, v)) if !k.trim().is_empty() => {
                    let (key, value) = (k.trim().to_string(), v.trim().to_string());
                    if let Some(previous) = out.get(&key) {
                        if previous != &value {
                            return Err(format!(
                                "--cluster-label states {key}={previous:?} and {key}={value:?}:                                  one of the two is a label this cluster does not carry"
                            ));
                        }
                    }
                    out.insert(key, value);
                }
                _ => return Err(format!("--cluster-label expects k=v, got {pair:?}")),
            }
        }
    }
    Ok(ClusterLabels::stated(out))
}

/// Live namespace/ServiceAccount labels, or a cold source that denies every
/// policy with such a selector until the watch lists.
#[cfg(feature = "apiserver")]
fn label_source(flags: &Flags) -> Arc<dyn LabelSource> {
    use ferrum_k8smeta::watch::{ApiserverConfig, LabelWatcher};

    let cluster = cluster_labels(flags);
    let Some(target) = flags.get("apiserver") else {
        eprintln!(
            "ferrum-admission: --apiserver not set; policies with a namespace or \
             ServiceAccount selector will fail closed"
        );
        return Arc::new(StaticLabels::cluster(cluster));
    };
    let mut config = match ApiserverConfig::cluster_wide() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("error: apiserver: {err}");
            exit(2);
        }
    };
    if !target.is_empty() {
        match target.rsplit_once(':') {
            Some((host, port)) => {
                config.host = host.to_string();
                config.port = port
                    .parse()
                    .unwrap_or_else(|_| die("invalid --apiserver port"));
            }
            None => config.host = target.to_string(),
        }
    }
    let watcher = LabelWatcher::new(config);
    let source = ferrum_admission::WatchedLabels::new(
        watcher.namespaces(),
        watcher.service_accounts(),
        cluster,
    );
    watcher.spawn();
    // The watcher owns nothing the caches need; the threads keep the Arcs alive.
    Arc::new(source)
}

#[cfg(not(feature = "apiserver"))]
fn label_source(flags: &Flags) -> Arc<dyn LabelSource> {
    if flags.get("apiserver").is_some() {
        die("--apiserver requires the `apiserver` feature at build time");
    }
    eprintln!(
        "ferrum-admission: built without the `apiserver` feature; policies with a namespace or \
         ServiceAccount selector will fail closed"
    );
    Arc::new(StaticLabels::cluster(cluster_labels(flags)))
}

fn exceptions_and_config(
    flags: &Flags,
    trust_root: &[u8],
) -> (Vec<PolicyExceptionSpec>, ReviewConfig) {
    let exceptions = load_exceptions(flags.get("exceptions"), trust_root);
    let cfg = review_config(flags);
    if !exceptions.is_empty() && cfg.policy_name.is_empty() {
        die("--policy-name is required when --exceptions is set");
    }
    (exceptions, cfg)
}

/// `--exceptions` must be a signed `exceptions.fsig` verified against the
/// same trust root as the bundle; plain JSON is rejected (fail closed).
fn load_exceptions(path: Option<&str>, trust_root: &[u8]) -> Vec<PolicyExceptionSpec> {
    let Some(path) = path else {
        return Vec::new();
    };
    if path.is_empty() {
        return Vec::new();
    }
    let raw = read_file(path);
    let payload = match verify_exceptions_fsig(&raw, trust_root) {
        Ok(payload) => payload,
        Err(err) => {
            eprintln!("error: exceptions: {err}");
            exit(2);
        }
    };
    match serde_json::from_slice::<Vec<PolicyExceptionSpec>>(&payload) {
        Ok(list) => list,
        Err(err) => {
            eprintln!("error: exceptions payload json: {err}");
            exit(2);
        }
    }
}

fn read_file(path: &str) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("error: read {path}: {err}");
            exit(2);
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(argv: &[&str]) -> Flags {
        parse_flags(&argv.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    fn stated(argv: &[&str]) -> Result<Option<BTreeMap<String, String>>, String> {
        parse_cluster_labels(flags(argv).occurrences("cluster-label"))
            .map(|labels| labels.observed().cloned())
    }

    /// A flag whose value was the next flag is not a stated cluster.
    ///
    /// Measured before the fix: `--cluster-label --apiserver kubernetes`
    /// produced `stated({})`, which is the same answer as the deliberate
    /// `--cluster-label ""`. The deliberate one is a decision — the cluster
    /// carries no labels, so a cluster selector misses — and the typo turned
    /// the fail-closed half into that same miss with nothing printed.
    #[test]
    fn a_cluster_label_whose_value_was_eaten_is_refused_not_stated() {
        let err = stated(&["--cluster-label", "--apiserver", "kubernetes"])
            .expect_err("a swallowed value must not read as a stated cluster");
        assert!(err.contains("no value"), "{err}");
        assert!(err.contains("--cluster-label=''"), "{err}");

        // Same shape at the end of argv.
        assert!(stated(&["--apiserver", "kubernetes", "--cluster-label"]).is_err());

        // And the neighbouring flag still parses: the refusal is about the
        // value, not about the line.
        assert_eq!(
            flags(&["--cluster-label", "--apiserver", "kubernetes"]).get("apiserver"),
            Some("kubernetes")
        );
    }

    /// The two spellings that mean "this cluster carries no labels" keep
    /// meaning it. Without this the fix above could be a blanket refusal of
    /// the empty value, which would delete the distinction it exists to keep.
    #[test]
    fn an_explicitly_empty_cluster_label_is_still_a_stated_cluster() {
        assert_eq!(stated(&["--cluster-label", ""]), Ok(Some(BTreeMap::new())));
        assert_eq!(stated(&["--cluster-label="]), Ok(Some(BTreeMap::new())));
        // And no flag at all stays unstated, which is what fails closed.
        assert_eq!(stated(&["--apiserver", "kubernetes"]), Ok(None));
    }

    /// Repeats accumulate instead of the last one winning.
    ///
    /// Measured before the fix: `--cluster-label a=1 --cluster-label b=2`
    /// stated `{b: 2}` and dropped `a=1` with nothing printed, so a policy
    /// selecting on `a` answered a miss on a cluster the operator had said
    /// carries it.
    #[test]
    fn repeated_cluster_labels_accumulate_and_disagreements_are_refused() {
        assert_eq!(
            stated(&["--cluster-label", "a=1", "--cluster-label", "b=2"]),
            Ok(Some(
                [
                    ("a".to_string(), "1".to_string()),
                    ("b".to_string(), "2".to_string())
                ]
                .into_iter()
                .collect()
            ))
        );
        // The comma form within one occurrence is unchanged.
        assert_eq!(
            stated(&["--cluster-label", "a=1,b=2"]),
            stated(&["--cluster-label", "a=1", "--cluster-label", "b=2"])
        );
        // Restating the same pair is not a conflict.
        assert_eq!(
            stated(&["--cluster-label", "a=1", "--cluster-label", "a=1"]),
            Ok(Some(
                [("a".to_string(), "1".to_string())].into_iter().collect()
            ))
        );
        let err = stated(&["--cluster-label", "a=1", "--cluster-label", "a=2"])
            .expect_err("two values for one key is not a cluster");
        assert!(err.contains('a'), "{err}");
    }

    /// Every other flag keeps last-wins and keeps reading an eaten value as
    /// empty: that is the behaviour `ferrum-cli`'s `parse_argv` models when it
    /// proves a manifest's joins, and changing it here would make FD024 and
    /// FD025 describe a binary that no longer exists.
    #[test]
    fn other_flags_keep_the_semantics_the_deploy_lint_models() {
        let parsed = flags(&["--policy-name", "a", "--policy-name", "b"]);
        assert_eq!(parsed.get("policy-name"), Some("b"));
        assert_eq!(parsed.occurrences("policy-name").len(), 2);
        assert_eq!(
            flags(&["--listen", "--bundle", "x"]).get("listen"),
            Some("")
        );
        assert_eq!(flags(&["--k=v"]).get("k"), Some("v"));
        assert!(flags(&["serve", "--k=v"])
            .positional
            .contains(&"serve".to_string()));
    }
}
