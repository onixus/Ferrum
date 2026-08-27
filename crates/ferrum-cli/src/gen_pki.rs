//! `ferrumctl gen-webhook-pki` — the offline issuance step that turns the
//! webhook template into something `kubectl apply` accepts.
//!
//! There is no cluster call and no controller here: it runs on the operator's
//! machine, before the install and again before the certificate expires.
//! Rotation (`--ca-cert`/`--ca-key`) reissues only the leaf under the CA the
//! cluster already trusts, so the caBundle — and the applied
//! ValidatingWebhookConfiguration — stay exactly as they are.

use anyhow::{bail, Context, Result};
use ferrum_crypto::x509::{
    base64_encode, days_until_expiry, issue_ca, issue_serving_cert, verify_chain, CaMaterial,
    ServingMaterial, MAX_SERVING_CERT_DAYS,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::lint_deploy::{CA_BUNDLE_PLACEHOLDER, WEBHOOK_TLS_SECRET_SUFFIX};

/// Name of the template the rendered configuration is produced from, and of the
/// file that rendering writes next to it.
pub const WEBHOOK_TEMPLATE_FILE: &str = "validatingwebhookconfiguration.tmpl.yaml";
pub const WEBHOOK_RENDERED_FILE: &str = "validatingwebhookconfiguration.yaml";
/// Issued CA, written next to the rendered configuration. `ca.key` is the
/// rotation key: it never reaches a cluster and must not be committed.
pub const CA_CERT_FILE: &str = "ca.crt";
pub const CA_KEY_FILE: &str = "ca.key";

/// Private key material on disk is owner-only, same rule as the export sink.
#[cfg(unix)]
const KEY_FILE_MODE: u32 = 0o600;

pub struct GenPkiArgs {
    pub service: String,
    pub namespace: String,
    pub days: u64,
    pub out_dir: Option<PathBuf>,
    pub template: Option<PathBuf>,
    /// Rotation: reuse this CA instead of issuing one. Both halves or neither.
    pub ca_cert: Option<PathBuf>,
    pub ca_key: Option<PathBuf>,
    /// Rotation: the ValidatingWebhookConfiguration that is applied in the
    /// cluster. Its caBundle is the only statement of which CA the cluster
    /// trusts; without it `--ca-cert` means nothing more than "a CA".
    pub webhook_config: Option<PathBuf>,
}

pub fn gen_webhook_pki(args: &GenPkiArgs) -> Result<()> {
    if args.days == 0 {
        bail!("--days must be at least 1");
    }
    if args.days > MAX_SERVING_CERT_DAYS {
        bail!(
            "--days {} exceeds the {MAX_SERVING_CERT_DAYS}-day maximum for a serving certificate",
            args.days
        );
    }
    let now = SystemTime::now();
    let not_after = now + Duration::from_secs(args.days * 86_400);
    // The CA gets every day the issuance rule allows, not the leaf's lifetime:
    // a CA that ends with its own leaf can never be rotated under, which is the
    // install this command used to produce.
    let ca_not_after = std::cmp::max(
        not_after,
        now + Duration::from_secs(MAX_SERVING_CERT_DAYS * 86_400),
    );

    let ca = match (&args.ca_cert, &args.ca_key) {
        (None, None) => issue_ca(&format!("{}-ca", args.service), ca_not_after)
            .with_context(|| format!("issue CA for {}", args.service))?,
        (Some(cert), Some(key)) => reusable_ca(cert, key, args.days)?,
        _ => bail!("--ca-cert and --ca-key must be given together"),
    };
    let rotating = args.ca_cert.is_some();
    let serving = issue_serving_cert(&ca, &args.service, &args.namespace, not_after)
        .with_context(|| format!("issue serving certificate for {}", args.service))?;
    // The gate is the chain, not the fact that issuance returned.
    verify_chain(&serving, &ca).context("issued chain failed verification")?;

    let secret_name = format!("{}{WEBHOOK_TLS_SECRET_SUFFIX}", args.service);
    let secret_yaml = secret_manifest(&secret_name, &args.namespace, &args.service, &serving);
    let ca_bundle = base64_encode(ca.cert_pem.as_bytes());

    // Rotation exists so the ValidatingWebhookConfiguration can stay applied
    // untouched. A rendered configuration that already trusts a different CA
    // would keep rejecting the new leaf, so refuse before writing anything.
    if rotating {
        require_applied_ca_bundle(args, &ca_bundle)?;
    }

    match &args.out_dir {
        None => {
            print!("{secret_yaml}");
            if rotating {
                print!("{}", rotation_note(&secret_name, &args.namespace));
            } else {
                println!("---");
                print!(
                    "{}",
                    ca_bundle_note(&args.service, &ca_bundle, &secret_name, &args.namespace)
                );
            }
            Ok(())
        }
        Some(dir) => write_out_dir(
            args,
            dir,
            &secret_name,
            &secret_yaml,
            &ca_bundle,
            &ca,
            rotating,
        ),
    }
}

fn ca_dir(args: &GenPkiArgs) -> Option<PathBuf> {
    let parent = args.ca_cert.as_ref()?.parent()?;
    Some(if parent.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        parent.to_path_buf()
    })
}

/// Load the CA the webhook's caBundle already carries. Refuses a CA that
/// expires before the leaf would: `verify_chain` requires the leaf window to
/// nest inside the issuer's, and a CA this close to its own end cannot be
/// rotated under without replacing the caBundle too.
fn reusable_ca(cert_path: &Path, key_path: &Path, days: u64) -> Result<CaMaterial> {
    let ca = CaMaterial {
        cert_pem: fs::read_to_string(cert_path)
            .with_context(|| format!("read CA certificate {}", cert_path.display()))?,
        key_pem: fs::read_to_string(key_path)
            .with_context(|| format!("read CA key {}", key_path.display()))?,
    };
    let left = days_until_expiry(&ca.cert_pem)
        .with_context(|| format!("read validity of {}", cert_path.display()))?;
    // Strictly fewer days than the CA has left, not the same number: the two
    // notAfter values are seconds apart, and `verify_chain` requires the leaf
    // window to nest inside the issuer's.
    if left < 2 {
        bail!(
            "{}: this CA has {left} day(s) of validity left; a leaf can no longer be rotated \
             under it — reissue the CA, and the caBundle in the ValidatingWebhookConfiguration \
             with it",
            cert_path.display()
        );
    }
    if i64::try_from(days).unwrap_or(i64::MAX) >= left {
        bail!(
            "{}: this CA has {left} day(s) left and a leaf may not outlive its issuer; rotate \
             with --days {} or fewer, or reissue the CA and the caBundle with it",
            cert_path.display(),
            left - 1
        );
    }
    Ok(ca)
}

/// Rotation is only safe against the CA the *cluster* trusts, and the applied
/// ValidatingWebhookConfiguration is the only place that says which one that
/// is. `--ca-cert` alone proves nothing: it names whatever CA file was passed.
///
/// The README rotates into an empty directory, so there is usually no rendered
/// configuration lying next to either path — that case is refused rather than
/// silently skipped, and `--webhook-config` is how the operator answers it.
fn require_applied_ca_bundle(args: &GenPkiArgs, ca_bundle: &str) -> Result<()> {
    if let Some(path) = &args.webhook_config {
        return rendered_ca_bundle_matches(path, ca_bundle);
    }
    let mut checked = false;
    for dir in ca_dir(args).iter().chain(args.out_dir.iter()) {
        let path = dir.join(WEBHOOK_RENDERED_FILE);
        if !path.is_file() {
            continue;
        }
        rendered_ca_bundle_matches(&path, ca_bundle)?;
        checked = true;
    }
    if !checked {
        bail!(
            "no applied ValidatingWebhookConfiguration to check --ca-cert against: pass \
             --webhook-config <the {WEBHOOK_RENDERED_FILE} that is applied in the cluster>. \
             Rotating a leaf under a CA the cluster does not trust leaves the API server \
             rejecting every handshake, and with failurePolicy: Fail that stops Pod creation \
             cluster-wide"
        );
    }
    Ok(())
}

/// The rendered configuration at `path` must already trust `ca_bundle`.
fn rendered_ca_bundle_matches(path: &Path, ca_bundle: &str) -> Result<()> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read applied webhook configuration {}", path.display()))?;
    let Some(current) = raw
        .lines()
        .find_map(|l| l.trim().strip_prefix("caBundle:"))
        .map(str::trim)
    else {
        bail!(
            "{}: carries no caBundle, so it cannot say which CA the cluster trusts",
            path.display()
        );
    };
    if current != ca_bundle {
        bail!(
            "{}: its caBundle is not the CA given as --ca-cert. Rotating the leaf under a \
             different CA leaves the applied webhook trusting the wrong issuer",
            path.display()
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_out_dir(
    args: &GenPkiArgs,
    dir: &Path,
    secret_name: &str,
    secret_yaml: &str,
    ca_bundle: &str,
    ca: &CaMaterial,
    rotating: bool,
) -> Result<()> {
    if !dir.is_dir() {
        bail!("{}: --out-dir must be an existing directory", dir.display());
    }
    let secret_path = dir.join(format!("{secret_name}.secret.yaml"));
    if rotating {
        // No ca.crt, no rendered configuration: rotation reissues the leaf and
        // nothing else, which is what keeps the applied webhook valid.
        if secret_path.exists() {
            bail!(
                "{}: refusing to overwrite existing PKI output; rotate into an empty directory",
                secret_path.display()
            );
        }
        write_private(&secret_path, secret_yaml.as_bytes())?;
        println!("wrote {}", secret_path.display());
        print!("{}", rotation_note(secret_name, &args.namespace));
        return Ok(());
    }

    let template = args
        .template
        .clone()
        .unwrap_or_else(|| dir.join(WEBHOOK_TEMPLATE_FILE));
    let raw = fs::read_to_string(&template)
        .with_context(|| format!("read webhook template {}", template.display()))?;
    if !raw.contains(CA_BUNDLE_PLACEHOLDER) {
        bail!(
            "{}: template does not carry the {CA_BUNDLE_PLACEHOLDER} token, nothing to render",
            template.display()
        );
    }

    let rendered_path = dir.join(WEBHOOK_RENDERED_FILE);
    let ca_path = dir.join(CA_CERT_FILE);
    let ca_key_path = dir.join(CA_KEY_FILE);
    // Refuse rather than overwrite: the old key is the only thing that can
    // still serve the certificate the API server is pinned to.
    for path in [&secret_path, &rendered_path, &ca_path, &ca_key_path] {
        if path.exists() {
            bail!(
                "{}: refusing to overwrite existing PKI output; remove it deliberately first",
                path.display()
            );
        }
    }

    write_private(&secret_path, secret_yaml.as_bytes())?;
    fs::write(
        &rendered_path,
        raw.replace(CA_BUNDLE_PLACEHOLDER, ca_bundle),
    )
    .with_context(|| format!("write {}", rendered_path.display()))?;
    fs::write(&ca_path, ca.cert_pem.as_bytes())
        .with_context(|| format!("write {}", ca_path.display()))?;
    // The issuing key. Nothing applies it to a cluster; it exists so the leaf
    // can be rotated later without moving the caBundle. Keep it offline.
    write_private(&ca_key_path, ca.key_pem.as_bytes())?;

    println!("wrote {}", secret_path.display());
    println!("wrote {}", rendered_path.display());
    println!("wrote {}", ca_path.display());
    println!("wrote {}", ca_key_path.display());
    Ok(())
}

/// Creates the file owner-only *before* any bytes reach it; a chmod after the
/// write leaves a window where the key is world-readable.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(KEY_FILE_MODE);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(data)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", path.display()))
}

pub fn secret_manifest(
    secret_name: &str,
    namespace: &str,
    service: &str,
    serving: &ServingMaterial,
) -> String {
    format!(
        "apiVersion: v1\n\
         kind: Secret\n\
         metadata:\n  \
           name: {secret_name}\n  \
           namespace: {namespace}\n  \
           labels:\n    \
             app.kubernetes.io/name: {service}\n    \
             app.kubernetes.io/part-of: ferrum\n\
         type: kubernetes.io/tls\n\
         data:\n  \
           tls.crt: {}\n  \
           tls.key: {}\n",
        base64_encode(serving.cert_pem.as_bytes()),
        base64_encode(serving.key_pem.as_bytes()),
    )
}

fn rotation_note(secret_name: &str, namespace: &str) -> String {
    format!(
        "# Rotation: same CA, new leaf. The caBundle and the applied\n\
         # ValidatingWebhookConfiguration do not change.\n\
         # kubectl -n {namespace} apply -f <this Secret>, then restart the webhook Pods\n\
         # (or wait for kubelet to refresh the mount; the server reloads it in place).\n\
         # Secret: {secret_name}\n"
    )
}

fn ca_bundle_note(service: &str, ca_bundle: &str, secret_name: &str, namespace: &str) -> String {
    format!(
        "# caBundle for the ValidatingWebhookConfiguration; substitutes\n\
         # {CA_BUNDLE_PLACEHOLDER} in {WEBHOOK_TEMPLATE_FILE}.\n\
         # kubectl -n {namespace} create -f - <<< the Secret above, then apply the rendered file.\n\
         # Secret: {secret_name}   Service: {service}\n\
         caBundle: {ca_bundle}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_crypto::x509::{base64_decode, verify_issued_pair};

    fn args(dir: Option<PathBuf>) -> GenPkiArgs {
        GenPkiArgs {
            service: "ferrum-admission".into(),
            namespace: "ferrum".into(),
            days: 365,
            out_dir: dir,
            template: None,
            ca_cert: None,
            ca_key: None,
            webhook_config: None,
        }
    }

    fn rotation_args(dir: &Path, out: Option<PathBuf>, days: u64) -> GenPkiArgs {
        GenPkiArgs {
            days,
            ca_cert: Some(dir.join(CA_CERT_FILE)),
            ca_key: Some(dir.join(CA_KEY_FILE)),
            ..args(out)
        }
    }

    fn leaf_pem(secret: &Path) -> String {
        let raw = fs::read_to_string(secret).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        String::from_utf8(base64_decode(doc["data"]["tls.crt"].as_str().unwrap()).unwrap()).unwrap()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("ferrum-genpki-{tag}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn template_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/admission")
            .join(WEBHOOK_TEMPLATE_FILE)
    }

    fn seed(dir: &Path) {
        fs::copy(template_path(), dir.join(WEBHOOK_TEMPLATE_FILE)).unwrap();
    }

    #[test]
    fn ca_bundle_decodes_byte_for_byte_to_the_ca_pem() {
        let dir = temp_dir("bundle");
        seed(&dir);
        gen_webhook_pki(&args(Some(dir.clone()))).unwrap();
        let ca_pem = fs::read(dir.join("ca.crt")).unwrap();
        let rendered = fs::read_to_string(dir.join(WEBHOOK_RENDERED_FILE)).unwrap();
        let value = rendered
            .lines()
            .find_map(|l| l.trim().strip_prefix("caBundle: "))
            .expect("rendered caBundle");
        assert_eq!(base64_decode(value).unwrap(), ca_pem);
        assert!(!rendered.contains(CA_BUNDLE_PLACEHOLDER));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn secret_carries_the_issued_pair() {
        let dir = temp_dir("secret");
        seed(&dir);
        gen_webhook_pki(&args(Some(dir.clone()))).unwrap();
        let raw = fs::read_to_string(dir.join("ferrum-admission-tls.secret.yaml")).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
        assert_eq!(doc["type"].as_str(), Some("kubernetes.io/tls"));
        assert_eq!(
            doc["metadata"]["name"].as_str(),
            Some("ferrum-admission-tls")
        );
        let crt = base64_decode(doc["data"]["tls.crt"].as_str().unwrap()).unwrap();
        let key = base64_decode(doc["data"]["tls.key"].as_str().unwrap()).unwrap();
        assert!(String::from_utf8(crt)
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(String::from_utf8(key).unwrap().contains("PRIVATE KEY"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_second_run_refuses_to_overwrite() {
        let dir = temp_dir("overwrite");
        seed(&dir);
        gen_webhook_pki(&args(Some(dir.clone()))).unwrap();
        let err = gen_webhook_pki(&args(Some(dir.clone())))
            .expect_err("existing output must not be overwritten");
        assert!(err.to_string().contains("refusing to overwrite"), "{err}");
        fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn the_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        seed(&dir);
        gen_webhook_pki(&args(Some(dir.clone()))).unwrap();
        let mode = fs::metadata(dir.join("ferrum-admission-tls.secret.yaml"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, KEY_FILE_MODE);
        fs::remove_dir_all(&dir).ok();
    }

    /// The point of rotation: a second leaf from the same CA, and a caBundle
    /// the ValidatingWebhookConfiguration never has to be re-applied for.
    #[test]
    fn rotation_reissues_only_the_leaf() {
        let dir = temp_dir("rotate");
        seed(&dir);
        gen_webhook_pki(&args(Some(dir.clone()))).unwrap();
        let rendered_before = fs::read(dir.join(WEBHOOK_RENDERED_FILE)).unwrap();
        let ca_before = fs::read_to_string(dir.join(CA_CERT_FILE)).unwrap();
        let first = leaf_pem(&dir.join("ferrum-admission-tls.secret.yaml"));

        let out = dir.join("rotated");
        fs::create_dir_all(&out).unwrap();
        gen_webhook_pki(&rotation_args(&dir, Some(out.clone()), 365)).unwrap();

        assert!(
            !out.join(CA_CERT_FILE).exists(),
            "rotation must not reissue the CA"
        );
        assert!(
            !out.join(WEBHOOK_RENDERED_FILE).exists(),
            "rotation must not re-render the webhook configuration"
        );
        assert_eq!(
            fs::read(dir.join(WEBHOOK_RENDERED_FILE)).unwrap(),
            rendered_before,
            "the caBundle must not change byte for byte"
        );

        let second = leaf_pem(&out.join("ferrum-admission-tls.secret.yaml"));
        assert_ne!(first, second, "rotation must issue a new leaf");
        verify_issued_pair(&ca_before, &second).expect("leaf 2 must verify against the same CA");
        fs::remove_dir_all(&dir).ok();
    }

    /// The CA is issued for the maximum lifetime, so a leaf asking for more
    /// than what is left of it is the case that has to be refused.
    #[test]
    fn a_leaf_outliving_the_ca_is_refused() {
        let dir = temp_dir("rotate-short-ca");
        seed(&dir);
        gen_webhook_pki(&args(Some(dir.clone()))).unwrap();

        let out = dir.join("rotated");
        fs::create_dir_all(&out).unwrap();
        let err = gen_webhook_pki(&rotation_args(&dir, Some(out), MAX_SERVING_CERT_DAYS))
            .expect_err("a leaf may not outlive its issuer");
        assert!(err.to_string().contains("day(s) left"), "{err}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotation_under_a_foreign_ca_is_refused() {
        let mine = temp_dir("rotate-mine");
        seed(&mine);
        gen_webhook_pki(&args(Some(mine.clone()))).unwrap();
        let other = temp_dir("rotate-other");
        seed(&other);
        gen_webhook_pki(&args(Some(other.clone()))).unwrap();

        // The rendered configuration in `mine` trusts the CA of `mine`, not this one.
        let err = gen_webhook_pki(&rotation_args(&other, Some(mine.clone()), 365))
            .expect_err("a CA the applied webhook does not trust must be refused");
        assert!(err.to_string().contains("caBundle is not the CA"), "{err}");
        fs::remove_dir_all(&mine).ok();
        fs::remove_dir_all(&other).ok();
    }

    /// The README's own rotation goes into an empty directory. If nothing there
    /// states which CA the cluster trusts, "rotate under the right CA" is not
    /// checked at all — so the command has to say so instead of proceeding.
    #[test]
    fn rotation_without_an_applied_configuration_is_refused() {
        let dir = temp_dir("rotate-no-config");
        seed(&dir);
        gen_webhook_pki(&args(Some(dir.clone()))).unwrap();
        // The operator keeps the applied configuration elsewhere, as step 3
        // applied it and step 1's output was moved out of the tree.
        fs::remove_file(dir.join(WEBHOOK_RENDERED_FILE)).unwrap();

        let out = dir.join("rotated");
        fs::create_dir_all(&out).unwrap();
        let err = gen_webhook_pki(&rotation_args(&dir, Some(out.clone()), 365))
            .expect_err("an unchecked CA must not be rotated under");
        assert!(err.to_string().contains("--webhook-config"), "{err}");
        assert!(
            !out.join("ferrum-admission-tls.secret.yaml").exists(),
            "nothing may be written before the CA is checked"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_explicit_webhook_config_decides_which_ca_is_trusted() {
        let mine = temp_dir("rotate-explicit-mine");
        seed(&mine);
        gen_webhook_pki(&args(Some(mine.clone()))).unwrap();
        let other = temp_dir("rotate-explicit-other");
        seed(&other);
        gen_webhook_pki(&args(Some(other.clone()))).unwrap();
        let applied = mine.join(WEBHOOK_RENDERED_FILE);

        let out = mine.join("rotated");
        fs::create_dir_all(&out).unwrap();
        let mut ok = rotation_args(&mine, Some(out.clone()), 365);
        ok.webhook_config = Some(applied.clone());
        gen_webhook_pki(&ok).expect("the CA the applied configuration trusts");

        let out2 = other.join("rotated");
        fs::create_dir_all(&out2).unwrap();
        let mut wrong = rotation_args(&other, Some(out2), 365);
        wrong.webhook_config = Some(applied);
        let err = gen_webhook_pki(&wrong).expect_err("a CA the cluster does not trust");
        assert!(err.to_string().contains("caBundle is not the CA"), "{err}");
        fs::remove_dir_all(&mine).ok();
        fs::remove_dir_all(&other).ok();
    }

    #[test]
    fn a_webhook_config_without_a_ca_bundle_is_refused() {
        let dir = temp_dir("rotate-empty-config");
        seed(&dir);
        gen_webhook_pki(&args(Some(dir.clone()))).unwrap();
        let applied = dir.join("applied.yaml");
        fs::write(&applied, "kind: ValidatingWebhookConfiguration\n").unwrap();

        let out = dir.join("rotated");
        fs::create_dir_all(&out).unwrap();
        let mut a = rotation_args(&dir, Some(out), 365);
        a.webhook_config = Some(applied);
        let err = gen_webhook_pki(&a).expect_err("a file with no caBundle answers nothing");
        assert!(err.to_string().contains("carries no caBundle"), "{err}");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn one_half_of_the_ca_is_refused() {
        let mut a = args(None);
        a.ca_cert = Some(PathBuf::from("ca.crt"));
        let err = gen_webhook_pki(&a).expect_err("half a CA is not a CA");
        assert!(err.to_string().contains("must be given together"), "{err}");
    }

    #[test]
    fn a_lifetime_past_the_cab_forum_limit_is_refused() {
        let mut a = args(None);
        a.days = 400;
        let err = gen_webhook_pki(&a).expect_err("400 days must fail");
        assert!(err.to_string().contains("398"), "{err}");
    }

    #[test]
    fn a_template_without_the_token_is_refused() {
        let dir = temp_dir("notoken");
        fs::write(
            dir.join(WEBHOOK_TEMPLATE_FILE),
            "kind: ValidatingWebhookConfiguration\n",
        )
        .unwrap();
        let err = gen_webhook_pki(&args(Some(dir.clone()))).expect_err("no token, nothing to do");
        assert!(err.to_string().contains(CA_BUNDLE_PLACEHOLDER), "{err}");
        fs::remove_dir_all(&dir).ok();
    }
}
