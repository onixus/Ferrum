//! Break-glass, and the runbook that tells an operator how to use it.
//!
//! Two subjects in one file because they fail the same way: both are read by
//! somebody under pressure who cannot check them first.
//!
//! # The runbook
//!
//! `docs/runbooks/README.md` is an operational document, not a description of
//! one. Its whole value is that at 03:00 the command in it can be pasted. A
//! runbook whose commands have drifted from the tree is worse than no runbook:
//! it costs the minutes it takes to discover that the object was renamed, and
//! it spends them at the moment those minutes are most expensive. Nothing about
//! that drift is visible in review — a renamed Deployment, a metric family that
//! moved, a reason id that was reworded, a kustomize root that was split — and
//! nothing anywhere goes red.
//!
//! So the runbook is held against the tree the way
//! `deploy_gate.rs::release_supply_chain` holds the README's verification
//! procedure against the workflow that performs it: by deriving the true answer
//! from the code and comparing, rather than by reading both and hoping.
//! Five directions:
//!
//!  1. every path the runbook tells an operator to `apply -k`/`-f` exists;
//!  2. every `ferrum_agent_*` / `ferrum_admission_*` family it names is one a
//!     binary really publishes, obtained by rendering both binaries;
//!  3. every degradation reason it names is one the agent can raise — and,
//!     in the other direction, every reason the agent can raise is named,
//!     so a new one cannot appear with no operator guidance at all;
//!  4. every number in «Радиус поражения» equals the constant it came from;
//!  5. every Kubernetes object it names exists in `deploy/**`.
//!
//! What none of that checks is whether the procedure *works*. That is a human
//! duty, and §7 of the runbook says which parts of it have never been executed.
//!
//! # Break-glass
//!
//! The mechanism is exercised rather than described: a real `WebhookState` over
//! the shipped policy, a real Ed25519 grant, a real AdmissionReview that the
//! policy denies — and the assertion is that the deny becomes an allow while
//! the grant holds, stops being one when the window closes, and that the
//! journal left behind verifies and names who did it.
//!
//! And the two refusals that make it worth having are asserted as refusals: a
//! grant cannot be open-ended (its ceiling is checked against the `expiresAt`
//! ceiling the policy invariants already impose on an exception), and the
//! default install cannot arm it by accident.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{Duration, Utc};
use ferrum_admission::{
    encode_fsig, load_bundle, AdmissionProgram, BreakGlass, ReviewConfig, StaticLabels,
    WebhookState, GRANT_FILE, SIGNATURE_FILE,
};
use ferrum_api::{ClusterSecurityPolicy, PolicyMode};
use ferrum_breakglass::{
    Grant, Journal, GRANT_SCHEMA, GRANT_SCHEMA_VERSION, MAX_GRANT_SECONDS, README_BOUNDARY,
    SCOPE_ADMISSION,
};
use ferrum_compiler::{bundle_digest_material, compile_cluster_policy};
use ferrum_crypto::{public_key_from_secret, sign_break_glass};
use ferrum_ids::{ADMISSION_ABI, AGENT_ABI};
use serde_json::{json, Value};

const RUNBOOK: &str = "docs/runbooks/README.md";
const OVERLAY: &str = "overlays/break-glass/kustomization.yaml";
const BLAST_HEADING: &str = "## 1. Радиус поражения";

/// RFC 8032 §7.1 test-1 seed: fixture only, not a prod key.
const SK: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// The break-glass key is a *different* key, and the gate uses a different seed
/// for it so that a test which accidentally signed a grant with the bundle seed
/// would fail rather than pass.
const BREAK_GLASS_SK: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0x60, 0x5a, 0xfe, 0xff, 0xd1,
];

const NS: &str = "payments";
const IMAGE: &str = "registry.internal.example/app@sha256:\
                     0000000000000000000000000000000000000000000000000000000000000000";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root")
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --- the runbook, held against the tree -------------------------------------

/// Every fenced shell block, concatenated. The prose around them names objects
/// too, so most checks read the whole document; this one exists for the checks
/// that must only look at what an operator would paste.
fn shell_blocks(doc: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for line in doc.lines() {
        if line.starts_with("```") {
            inside = line.trim_end() == "```sh";
            continue;
        }
        if inside {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(
        out.lines().count() > 20,
        "{RUNBOOK} has almost no shell blocks ({} lines); either the fences changed or the \
         commands were removed, and every check below reads nothing",
        out.lines().count()
    );
    out
}

/// Paths every `-k` and `-f` in the runbook names, minus the ones that are not
/// repository paths: `/tmp` scratch files an operator creates in the procedure
/// itself, and `-`, which is stdin.
fn applied_paths(shell: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let tokens: Vec<&str> = shell.split_whitespace().collect();
    for (i, token) in tokens.iter().enumerate() {
        if *token != "-k" && *token != "-f" {
            continue;
        }
        let Some(next) = tokens.get(i + 1) else {
            continue;
        };
        let next = next.trim_end_matches(['\\', '|']);
        if next.is_empty() || next.starts_with('-') || next.starts_with("/tmp/") {
            continue;
        }
        out.insert(next.to_string());
    }
    out
}

/// Every metric family the two shipped binaries publish, rendered from the
/// binaries rather than listed here.
fn exported_families() -> BTreeSet<String> {
    let agent = {
        use ferrum_agent::{Agent, AgentConfig};
        use ferrum_export::MemorySink;
        let agent = Agent::new(AgentConfig::default());
        let sink = MemorySink::new();
        let state = agent.degraded_snapshot_at(std::time::Instant::now());
        ferrum_agent::exposition(&agent, None, Some(&sink), &state).family_names()
    };
    let admission = {
        use ferrum_api::{AdmitSpec, PolicySelector, SupplySpec};
        let program = AdmissionProgram {
            abi: ADMISSION_ABI,
            mode: PolicyMode::Enforce,
            disabled: false,
            priority: 0,
            supply: SupplySpec::default(),
            admit: AdmitSpec::default(),
            selector: PolicySelector::default(),
        };
        let state = WebhookState::new(program, vec![0u8; 32], Vec::new(), ReviewConfig::default());
        ferrum_admission::exposition(&state).family_names()
    };
    agent.into_iter().chain(admission).collect()
}

/// `ferrum_agent_*` and `ferrum_admission_*` tokens in the document, folded
/// back onto their family: `_bucket`, `_sum` and `_count` are how one histogram
/// is spelled on the wire, not three families.
fn named_families(doc: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes: Vec<char> = doc.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if !bytes[i].is_ascii_alphabetic() && bytes[i] != '_' {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == '_') {
            i += 1;
        }
        let word: String = bytes[start..i].iter().collect();
        if !word.starts_with("ferrum_agent_") && !word.starts_with("ferrum_admission_") {
            continue;
        }
        // A trailing underscore is a grep prefix — `grep ^ferrum_agent_` — and
        // not the name of anything. Checking it as a family would fail on a
        // document that is correct.
        if word.ends_with('_') {
            continue;
        }
        let family = ["_bucket", "_sum", "_count"]
            .iter()
            .find_map(|suffix| word.strip_suffix(*suffix))
            .unwrap_or(&word)
            .to_string();
        out.insert(family);
    }
    out
}

/// An operator pastes these. A path that moved makes the paste a no-op with an
/// error message about a directory, three commands into an outage.
#[test]
fn every_path_the_runbook_tells_an_operator_to_apply_exists() {
    let doc = read(RUNBOOK);
    let paths = applied_paths(&shell_blocks(&doc));
    assert!(
        paths.len() >= 3,
        "the scan found {} appliable paths in {RUNBOOK}; it is not finding them",
        paths.len()
    );
    for path in &paths {
        let full = repo_root().join(path);
        assert!(
            full.exists(),
            "{RUNBOOK} tells an operator to apply {path}, which is not in this tree"
        );
    }
    // The two roots the procedures depend on, by name: a rename that also
    // renamed them in the runbook would satisfy the loop above while changing
    // what the document is about.
    assert!(
        paths.contains("overlays/break-glass"),
        "the runbook no longer arms break-glass with overlays/break-glass: {paths:?}"
    );
    assert!(
        paths.contains("deploy/agent"),
        "the runbook no longer names deploy/agent, which is how respond is put back: {paths:?}"
    );
}

/// A metric family that moved turns a diagnostic step into `grep` finding
/// nothing, which reads exactly like the healthy case.
#[test]
fn every_metric_family_the_runbook_names_is_one_a_binary_publishes() {
    let doc = read(RUNBOOK);
    let named = named_families(&doc);
    let exported = exported_families();
    assert!(
        named.len() >= 10,
        "the scan found {} metric names in {RUNBOOK}: it is not finding them",
        named.len()
    );
    let missing: Vec<&String> = named.difference(&exported).collect();
    assert!(
        missing.is_empty(),
        "{RUNBOOK} tells an operator to grep for families no binary publishes: {missing:#?}\n\
         A grep that finds nothing reads the same as a healthy node."
    );
    // Control: the set this is compared against is not empty and not a
    // superset of everything, or the assertion above passes vacuously.
    assert!(
        exported.contains("ferrum_admission_break_glass_active"),
        "the rendered expositions do not carry the break-glass families, so the check above \
         compared against the wrong thing"
    );
}

/// Both directions. A reason with no operator guidance is a page nobody can
/// act on, and it is added exactly as easily as a reason with one.
#[test]
fn the_runbook_names_every_degradation_reason_the_agent_can_raise() {
    let doc = read(RUNBOOK);
    let ids: BTreeSet<&str> = ferrum_agent::DEGRADED_REASON_IDS
        .iter()
        .map(|(_, id)| *id)
        .collect();
    assert!(
        ids.len() > 25,
        "the agent's reason table has {} entries; the scan is broken rather than the table",
        ids.len()
    );

    let missing: Vec<&&str> = ids
        .iter()
        .filter(|id| !doc.contains(&format!("`{id}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "{RUNBOOK} names no guidance for these degradation reasons: {missing:#?}\nEvery one of \
         them can put a node on somebody's dashboard, and a reason an operator cannot look up is \
         an alert with no next step. Put it in the table in §3, or in the paragraph after it \
         that names the ones which belong to an incident review rather than to a shift."
    );

    // The other direction: a backticked lower-case token in §3's table that is
    // not a reason id at all would be a row about nothing.
    let section = section_of(&doc, "## 3. Runbook: агент degraded");
    for line in section.lines().filter(|l| l.starts_with("| `")) {
        let id = line
            .trim_start_matches("| `")
            .split('`')
            .next()
            .expect("id")
            .to_string();
        assert!(
            ids.contains(id.as_str()),
            "{RUNBOOK} §3 has a row for {id:?}, which is not a reason this agent can raise"
        );
    }
}

/// The text between a heading and the next one at the same level.
fn section_of(doc: &str, heading: &str) -> String {
    let at = doc
        .find(heading)
        .unwrap_or_else(|| panic!("{RUNBOOK} has no {heading:?} section"));
    let rest = &doc[at + heading.len()..];
    match rest.find("\n## ") {
        Some(end) => rest[..end].to_string(),
        None => rest.to_string(),
    }
}

/// Numbers in the blast-radius section are quoted from the tree, and the tree
/// is where they must keep coming from.
///
/// This is the half of the runbook an operator uses to *decide* — whether to
/// wait, whether to break glass, whether a webhook is what is slowing the
/// cluster down. A number that has drifted is worse than an absent one: it is
/// consulted with confidence.
#[test]
fn the_numbers_in_the_blast_radius_section_are_the_ones_the_tree_carries() {
    let doc = read(RUNBOOK);
    let section = section_of(&doc, BLAST_HEADING);

    let deployment = read("deploy/admission/deployment.yaml");
    let pdb = read("deploy/admission/pdb.yaml");
    let webhook = read("deploy/admission/validatingwebhookconfiguration.tmpl.yaml");

    for (needle, source, why) in [
        (
            "timeoutSeconds: 5",
            webhook.as_str(),
            "the API server's own timeout, which is what a blocked request costs",
        ),
        (
            "replicas: 2",
            deployment.as_str(),
            "how many replicas have to fail before the cluster notices",
        ),
        (
            "maxUnavailable: 1",
            pdb.as_str(),
            "how many a voluntary eviction may take",
        ),
    ] {
        assert!(
            source.contains(needle),
            "the manifest no longer says {needle:?} ({why}); the runbook's blast-radius section \
             quotes it"
        );
        assert!(
            section.contains(needle),
            "{RUNBOOK} § {BLAST_HEADING} does not quote {needle:?}, which is {why}"
        );
    }

    // The latency budget, as the number and as the constant that carries it.
    // Both, because quoting only the number leaves nothing pointing at where it
    // came from, and quoting only the constant leaves an operator without an
    // answer.
    assert_eq!(
        ferrum_admission::REVIEW_LATENCY_BUDGET_SECONDS,
        0.005,
        "the release budget moved; the runbook says 5 ms"
    );
    assert!(
        section.contains("5 мс"),
        "{RUNBOOK} § {BLAST_HEADING} no longer states the latency budget in milliseconds"
    );
    assert!(
        section.contains("REVIEW_LATENCY_BUDGET_SECONDS"),
        "{RUNBOOK} § {BLAST_HEADING} states a number and does not name the constant it came \
         from, so nothing joins the document to the thing the gate measures"
    );

    // The metrics port, which every diagnostic step in the document forwards.
    assert!(
        deployment.contains("containerPort: 9102"),
        "the webhook's metrics port moved and the runbook's port-forwards name 9102"
    );
    assert!(doc.contains("9102"), "{RUNBOOK} no longer names the port");

    // The two namespaces the webhook exempts. They are the whole reason the
    // repair procedure in §1 works at all.
    for exempt in ["ferrum", "kube-system"] {
        assert!(
            webhook.contains(&format!("\"{exempt}\"")),
            "the webhook configuration no longer exempts {exempt}; the runbook's repair steps \
             assume Pods can still be created there"
        );
        assert!(section.contains(exempt));
    }
}

/// Objects the runbook tells an operator to act on exist in the manifests.
#[test]
fn every_kubernetes_object_the_runbook_names_is_one_this_tree_installs() {
    let doc = read(RUNBOOK);
    let mut manifests = String::new();
    for dir in ["deploy", "overlays"] {
        collect_yaml(&repo_root().join(dir), &mut manifests);
    }
    assert!(
        manifests.len() > 5_000,
        "collected {} bytes of manifests; the walk is broken",
        manifests.len()
    );
    for name in [
        "ferrum-admission",
        "ferrum-controller",
        "ferrum-agent",
        "ferrum-signing-key",
        "ferrum-trust-root",
        "ferrum-admission-tls",
        "ferrum-bundle-cluster-prod-restricted",
        "ferrum-break-glass",
        "ferrum-break-glass-root",
        "app.kubernetes.io/name",
    ] {
        assert!(
            manifests.contains(name),
            "{RUNBOOK} names {name:?} and no manifest under deploy/ or overlays/ does"
        );
        assert!(
            doc.contains(name),
            "{RUNBOOK} stopped naming {name:?}, which the manifests still install; a runbook \
             that has fallen behind the install is the failure this gate is about"
        );
    }
}

fn collect_yaml(dir: &Path, out: &mut String) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_yaml(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            out.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
        }
    }
}

/// The IdP boundary is stated in the runbook in the words the code states it
/// in, and not paraphrased.
///
/// Paraphrase is how a limitation softens. `README_BOUNDARY` is one sentence
/// and it is the difference between "FERRUM knows who broke glass" and "FERRUM
/// knows a key was used"; an operator who reads the second builds a process
/// around the key custody, and one who reads the first does not.
#[test]
fn the_runbook_states_the_idp_boundary_in_the_words_the_code_states_it() {
    let doc = read(RUNBOOK);
    // Blockquote markers are not words: the sentence is quoted in the runbook
    // as a `>` block, which is the right shape for it and would otherwise put a
    // `>` between two of its own tokens.
    let flattened: String = doc
        .lines()
        .map(|line| line.trim_start().trim_start_matches('>'))
        .collect::<Vec<_>>()
        .join(" ");
    let normalised: String = flattened.split_whitespace().collect::<Vec<_>>().join(" ");
    let expected: String = README_BOUNDARY
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        normalised.contains(&expected),
        "{RUNBOOK} does not carry `ferrum_breakglass::README_BOUNDARY` verbatim:\n{expected}"
    );
}

// --- the mechanism ----------------------------------------------------------

/// Every break-glass flag the overlay passes is one the binary parses, and all
/// three arrive together.
///
/// The binary refuses a partial set, so a missing one is a webhook that will
/// not start — a cluster-wide admission outage caused by arming the thing that
/// ends cluster-wide admission outages.
#[test]
fn the_shipped_overlay_arms_break_glass_with_flags_the_binary_parses() {
    let overlay = read(OVERLAY);
    let main = read("crates/ferrum-admission/src/main.rs");
    for flag in [
        "--break-glass",
        "--break-glass-journal",
        "--break-glass-root",
    ] {
        assert!(
            overlay.contains(flag),
            "{OVERLAY} does not pass {flag}; the three are refused unless given together"
        );
        // The parser strips the leading dashes; the name is what it looks up.
        let name = flag.trim_start_matches("--");
        assert!(
            main.contains(&format!("\"{name}\"")),
            "{OVERLAY} passes {flag} and ferrum-admission does not parse {name:?}"
        );
    }
    // The mount and the journal must be different paths, and the journal must
    // be on the writable volume: a journal inside the read-only Secret mount
    // could never be written, which by design means break-glass never arms.
    assert!(
        overlay.contains("/etc/ferrum/break-glass"),
        "{OVERLAY} no longer mounts the grant Secret where it tells the binary to look"
    );
    assert!(
        overlay.contains("/var/lib/ferrum/break-glass.jsonl"),
        "{OVERLAY} no longer puts the journal on the writable volume"
    );
    assert!(
        overlay.contains("emptyDir"),
        "{OVERLAY} no longer gives the journal a writable volume at all"
    );
    // The Secret is optional, and that is load-bearing: a required mount for a
    // Secret that is empty on every healthy cluster leaves both replicas in
    // ContainerCreating.
    assert!(
        overlay.contains("optional: true"),
        "{OVERLAY} makes the grant Secret required; on a healthy cluster it is empty, so both \
         replicas would sit in ContainerCreating"
    );
    // And the file names the binary looks for inside that mount are the ones
    // the runbook tells an operator to create.
    let runbook = read(RUNBOOK);
    for file in [GRANT_FILE, SIGNATURE_FILE] {
        assert!(
            runbook.contains(file),
            "{RUNBOOK} does not tell an operator to create {file}, which is the name the binary \
             looks for"
        );
    }
}

/// The default install cannot arm break-glass, and no root under `deploy/`
/// reaches the overlay that does.
///
/// Arming is safe and is meant to be done in advance — but it is still a
/// decision about a key that does not exist in this repository, in the same
/// sense respond is. An install somebody inherited must not carry it.
#[test]
fn no_default_install_arms_break_glass() {
    let mut roots = String::new();
    collect_yaml(&repo_root().join("deploy"), &mut roots);
    assert!(
        !roots.contains("break-glass"),
        "something under deploy/ names break-glass; arming is a separate, deliberate apply of \
         overlays/break-glass"
    );
    let deployment = read("deploy/admission/deployment.yaml");
    assert!(
        !deployment.contains("--break-glass"),
        "the shipped Deployment passes a break-glass flag; the base install would then require a \
         key this repository does not have"
    );
}

/// The ceiling on a break-glass window is below the ceiling the policy
/// invariants already put on an exception, and there is no way to express one
/// without a ceiling at all.
///
/// The two are the same kind of promise — «this loosening ends» — and the
/// tighter one belongs on the loosening that is unscoped, unreviewed and taken
/// under pressure. A break-glass that could run 90 days would be a policy
/// change with none of the review a policy change gets.
#[test]
fn a_break_glass_window_is_bounded_and_tighter_than_a_waiver() {
    const NINETY_DAYS: i64 = 90 * 24 * 60 * 60;
    assert!(
        MAX_GRANT_SECONDS < NINETY_DAYS,
        "the break-glass ceiling ({MAX_GRANT_SECONDS}s) is not tighter than the exception \
         ceiling ({NINETY_DAYS}s)"
    );
    assert!(
        MAX_GRANT_SECONDS <= 4 * 60 * 60,
        "the break-glass ceiling grew past four hours; the runbook says four hours and an \
         operator plans a handover around it"
    );
    // The invariant the policy layer states for a waiver, quoted from where it
    // is enforced, so this comparison is against the tree and not a literal.
    let policy = read("crates/ferrum-policy/src/lib.rs");
    assert!(
        policy.contains("90"),
        "ferrum-policy no longer carries the 90-day exception ceiling this is compared against"
    );
    let runbook = read(RUNBOOK);
    assert!(
        runbook.contains("четырёх часов"),
        "{RUNBOOK} no longer states the window ceiling"
    );
}

// --- end to end -------------------------------------------------------------

/// compile → sign → load: the shipped policy as the process holds it.
fn shipped_program() -> AdmissionProgram {
    let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
    let mut obj: ClusterSecurityPolicy = serde_yaml::from_str(yaml).expect("example policy");
    obj.spec.mode = PolicyMode::Enforce;
    let pk = public_key_from_secret(&SK).expect("public key");
    obj.spec.supply.trust_roots[0].public_keys = vec![hex(&pk)];
    let bundle = compile_cluster_policy(&obj.spec).expect("compile prod-restricted");
    let frmb = bundle_digest_material(
        AGENT_ABI,
        ADMISSION_ABI,
        &bundle.admission_program,
        &bundle.ebpf_spec,
        &bundle.wasm,
    )
    .expect("frmb material");
    let sig = ferrum_crypto::sign_bundle(&frmb, &SK).expect("sign");
    let fsig = encode_fsig(&frmb, &sig, &pk).expect("fsig");
    load_bundle(&fsig, &pk).expect("verify + parse")
}

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ferrum-bg-gate-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("tmpdir");
    dir
}

fn privileged_pod_review(uid: &str) -> Vec<u8> {
    let object = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "privileged",
            "namespace": NS,
            "labels": {"app": "checkout"},
            "annotations": {}
        },
        "spec": {
            "serviceAccountName": "default",
            "containers": [{
                "name": "app",
                "image": IMAGE,
                "securityContext": {"privileged": true}
            }]
        }
    });
    serde_json::to_vec(&json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": uid,
            "namespace": NS,
            "operation": "CREATE",
            "object": object
        }
    }))
    .expect("review json")
}

fn state_with_break_glass(bg: Arc<BreakGlass>) -> WebhookState {
    let labels = StaticLabels::default()
        .warm()
        .with_namespace(
            NS,
            [("ferrum.io/zone".to_string(), "pci".to_string())]
                .into_iter()
                .collect(),
        )
        .with_service_account(NS, "default", BTreeMap::new());
    WebhookState::new(
        shipped_program(),
        public_key_from_secret(&SK).expect("public key"),
        Vec::new(),
        ReviewConfig {
            policy_name: "prod-restricted".into(),
            policy_namespace: String::new(),
            labels: Arc::new(labels),
        },
    )
    .with_break_glass(bg)
}

fn write_grant(mount: &Path, grant: &Grant, seed: &[u8; 32]) {
    let raw = serde_json::to_vec(grant).expect("serialize");
    let sig = sign_break_glass(&raw, seed).expect("sign");
    std::fs::write(mount.join(GRANT_FILE), &raw).expect("grant");
    std::fs::write(mount.join(SIGNATURE_FILE), hex(&sig)).expect("sig");
}

/// The verdict and everything the API server would show a human: the denial
/// message on a refusal, the warnings on an allow. Both, because break-glass
/// moves the sentence from one to the other and a helper that read only one
/// would report the move as silence.
fn verdict(reply: &ferrum_admission::ReviewReply) -> (bool, String) {
    let doc: Value = serde_json::from_slice(&reply.body).expect("response json");
    let mut said = doc["response"]["status"]["message"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    if let Some(warnings) = doc["response"]["warnings"].as_array() {
        for warning in warnings {
            said.push(' ');
            said.push_str(warning.as_str().unwrap_or_default());
        }
    }
    (
        doc["response"]["allowed"].as_bool().unwrap_or(false),
        said.trim().to_string(),
    )
}

/// The whole mechanism, against the shipped policy and a real signature: a
/// review the policy denies is admitted while a grant holds, the operator
/// running `kubectl` is told which grant did it, and the journal left behind
/// verifies and names who took the decision.
///
/// The unsuspended denial before and after is not decoration. Without it this
/// test would pass on a build that allowed privileged Pods for some other
/// reason, and the thing it claims to measure would be untested.
#[test]
fn a_signed_grant_suspends_a_review_the_shipped_policy_denies() {
    let mount = tmp("suspend");
    let journal_path = mount.join("break-glass.jsonl");
    let pk = public_key_from_secret(&BREAK_GLASS_SK).expect("break-glass public key");
    let bg =
        Arc::new(BreakGlass::arm(&mount, &journal_path, pk, "ferrum-admission/gate").expect("arm"));
    let state = state_with_break_glass(Arc::clone(&bg));

    let (allowed, message) = verdict(&state.handle(&privileged_pod_review("uid-before")));
    assert!(
        !allowed,
        "control: the shipped policy must deny a privileged Pod"
    );
    assert!(
        !message.contains("break-glass"),
        "an unarmed process quoted break-glass in a denial: {message}"
    );

    let now = Utc::now();
    let grant = Grant {
        schema: GRANT_SCHEMA.into(),
        schema_version: GRANT_SCHEMA_VERSION.into(),
        id: "bg-gate-1".into(),
        scope: SCOPE_ADMISSION.into(),
        subject: "sre-oncall@example.test".into(),
        issuer: "sec-arch@example.test".into(),
        ticket: "INC-4471".into(),
        reason: "every replica unschedulable".into(),
        issued_at: now - Duration::seconds(30),
        expires_at: now + Duration::minutes(30),
    };
    write_grant(&mount, &grant, &BREAK_GLASS_SK);
    bg.poll(Utc::now());
    assert!(
        bg.active(Utc::now()).is_some(),
        "the grant did not come into force"
    );

    let (allowed, message) = verdict(&state.handle(&privileged_pod_review("uid-during")));
    assert!(
        allowed,
        "the grant is in force and the privileged Pod was still refused: {message}"
    );
    assert!(
        message.contains("bg-gate-1") && message.contains("INC-4471"),
        "the operator running kubectl was not told which grant admitted this: {message}"
    );
    assert!(
        !message.contains("sre-oncall@example.test"),
        "the subject reached a kubectl response, which lands in CI logs and scrollback: {message}"
    );
    assert_eq!(bg.admits(), 1, "the suspended admit was not counted apart");

    // The journal is the point of the whole mechanism, so it is read back.
    let entries = Journal::verify_path(&journal_path).expect("the chain verifies");
    assert_eq!(entries.len(), 1, "{entries:#?}");
    assert_eq!(entries[0].event, "activated");
    assert_eq!(entries[0].grant_id, "bg-gate-1");
    assert_eq!(entries[0].subject, "sre-oncall@example.test");
    assert_eq!(entries[0].issuer, "sec-arch@example.test");
    assert_eq!(entries[0].ticket, "INC-4471");
    assert_eq!(entries[0].expires_at, Some(grant.expires_at));
    assert_eq!(bg.journal_head(), entries[0].hash);
    let _ = std::fs::remove_dir_all(&mount);
}

/// The window ends by itself. Nothing reloads, nothing is deleted, and the
/// grant is still sitting in the mount — and the next review is refused again.
///
/// A suspension that outlives its `expiresAt` because nobody polled would make
/// the whole TTL argument decorative, so the assertion is made against a
/// process that has been told nothing.
#[test]
fn a_grant_stops_suspending_when_its_window_closes_with_nothing_reloaded() {
    let mount = tmp("expiry");
    let journal_path = mount.join("break-glass.jsonl");
    let pk = public_key_from_secret(&BREAK_GLASS_SK).expect("break-glass public key");
    let bg =
        Arc::new(BreakGlass::arm(&mount, &journal_path, pk, "ferrum-admission/gate").expect("arm"));
    let state = state_with_break_glass(Arc::clone(&bg));

    // A window that is already closing: two seconds wide, issued four seconds
    // ago. Real clock, because `handle` reads `Utc::now()` and a test that
    // injected a time would be measuring a different function.
    let now = Utc::now();
    let grant = Grant {
        schema: GRANT_SCHEMA.into(),
        schema_version: GRANT_SCHEMA_VERSION.into(),
        id: "bg-gate-2".into(),
        scope: SCOPE_ADMISSION.into(),
        subject: "sre-oncall@example.test".into(),
        issuer: "sec-arch@example.test".into(),
        ticket: "INC-4472".into(),
        reason: "short window".into(),
        issued_at: now - Duration::seconds(4),
        expires_at: now + Duration::seconds(2),
    };
    write_grant(&mount, &grant, &BREAK_GLASS_SK);
    bg.poll(Utc::now());
    let (allowed, _) = verdict(&state.handle(&privileged_pod_review("uid-inside")));
    assert!(allowed, "the grant was not in force inside its own window");

    std::thread::sleep(std::time::Duration::from_millis(2_200));
    let (allowed, message) = verdict(&state.handle(&privileged_pod_review("uid-after")));
    assert!(
        !allowed,
        "the review was still admitted after expiresAt, with nothing reloaded: {message}"
    );
    assert!(
        !message.contains("bg-gate-2"),
        "an expired grant is still being quoted at the operator: {message}"
    );
    assert!(
        bg.active(Utc::now()).is_none(),
        "the process still holds an expired grant"
    );

    // And the journal records the close, not just the open.
    bg.poll(Utc::now());
    let entries = Journal::verify_path(&journal_path).expect("verify");
    let events: Vec<&str> = entries.iter().map(|e| e.event.as_str()).collect();
    assert_eq!(
        &events[..2],
        &["activated", "expired"],
        "the journal does not record the window closing: {events:?}"
    );
    let _ = std::fs::remove_dir_all(&mount);
}

/// A grant signed by a key this deployment does not trust changes nothing, and
/// the attempt is on the record.
///
/// The bundle-signing key is the interesting wrong key rather than a random
/// one: it is the key that *is* in the cluster, held by whoever publishes
/// policy, and if the domains were not separated it would open the glass.
#[test]
fn a_grant_signed_with_the_bundle_key_suspends_nothing_and_is_journalled() {
    let mount = tmp("wrongkey");
    let journal_path = mount.join("break-glass.jsonl");
    let pk = public_key_from_secret(&BREAK_GLASS_SK).expect("break-glass public key");
    let bg =
        Arc::new(BreakGlass::arm(&mount, &journal_path, pk, "ferrum-admission/gate").expect("arm"));
    let state = state_with_break_glass(Arc::clone(&bg));

    let now = Utc::now();
    let grant = Grant {
        schema: GRANT_SCHEMA.into(),
        schema_version: GRANT_SCHEMA_VERSION.into(),
        id: "bg-gate-3".into(),
        scope: SCOPE_ADMISSION.into(),
        subject: "attacker".into(),
        issuer: "attacker".into(),
        ticket: "NONE".into(),
        reason: "let me in".into(),
        issued_at: now - Duration::seconds(10),
        expires_at: now + Duration::minutes(30),
    };
    // Signed with the *policy bundle* seed, in the break-glass domain, by a key
    // the deployment trusts for bundles and not for grants.
    write_grant(&mount, &grant, &SK);
    bg.poll(Utc::now());

    assert!(
        bg.active(Utc::now()).is_none(),
        "a foreign key opened the glass"
    );
    let (allowed, _) = verdict(&state.handle(&privileged_pod_review("uid-forged")));
    assert!(
        !allowed,
        "the privileged Pod was admitted under an unverified grant"
    );
    assert_eq!(bg.admits(), 0);
    assert!(bg.rejections() >= 1);

    let entries = Journal::verify_path(&journal_path).expect("verify");
    assert_eq!(entries.len(), 1, "{entries:#?}");
    assert_eq!(entries[0].event, "rejected");
    assert_eq!(
        entries[0].subject, "",
        "the unverified document's own claim about who it is was quoted into the journal"
    );
    assert!(entries[0].detail.contains("signature"), "{:?}", entries[0]);
    let _ = std::fs::remove_dir_all(&mount);
}
