//! `ferrumctl gen-webhook-pki` — the offline issuance step that turns the
//! webhook template into something `kubectl apply` accepts.
//!
//! There is no cluster call and no controller here: this runs once, before the
//! install, on the operator's machine. Rotation is not this command's job.

use anyhow::{bail, Context, Result};
use ferrum_crypto::x509::{
    base64_encode, issue_ca, issue_serving_cert, verify_chain, CaMaterial, ServingMaterial,
    MAX_SERVING_CERT_DAYS,
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

/// Private key material on disk is owner-only, same rule as the export sink.
#[cfg(unix)]
const KEY_FILE_MODE: u32 = 0o600;

pub struct GenPkiArgs {
    pub service: String,
    pub namespace: String,
    pub days: u64,
    pub out_dir: Option<PathBuf>,
    pub template: Option<PathBuf>,
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
    let not_after = SystemTime::now() + Duration::from_secs(args.days * 86_400);

    let ca = issue_ca(&format!("{}-ca", args.service), not_after)
        .with_context(|| format!("issue CA for {}", args.service))?;
    let serving = issue_serving_cert(&ca, &args.service, &args.namespace, not_after)
        .with_context(|| format!("issue serving certificate for {}", args.service))?;
    // The gate is the chain, not the fact that issuance returned.
    verify_chain(&serving, &ca).context("issued chain failed verification")?;

    let secret_name = format!("{}{WEBHOOK_TLS_SECRET_SUFFIX}", args.service);
    let secret_yaml = secret_manifest(&secret_name, &args.namespace, &args.service, &serving);
    let ca_bundle = base64_encode(ca.cert_pem.as_bytes());

    match &args.out_dir {
        None => {
            print!("{secret_yaml}");
            println!("---");
            print!(
                "{}",
                ca_bundle_note(&args.service, &ca_bundle, &secret_name, &args.namespace)
            );
            Ok(())
        }
        Some(dir) => write_out_dir(args, dir, &secret_name, &secret_yaml, &ca_bundle, &ca),
    }
}

fn write_out_dir(
    args: &GenPkiArgs,
    dir: &Path,
    secret_name: &str,
    secret_yaml: &str,
    ca_bundle: &str,
    ca: &CaMaterial,
) -> Result<()> {
    if !dir.is_dir() {
        bail!("{}: --out-dir must be an existing directory", dir.display());
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

    let secret_path = dir.join(format!("{secret_name}.secret.yaml"));
    let rendered_path = dir.join(WEBHOOK_RENDERED_FILE);
    let ca_path = dir.join("ca.crt");
    // Refuse rather than overwrite: the old key is the only thing that can
    // still serve the certificate the API server is pinned to.
    for path in [&secret_path, &rendered_path, &ca_path] {
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

    println!("wrote {}", secret_path.display());
    println!("wrote {}", rendered_path.display());
    println!("wrote {}", ca_path.display());
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
    use ferrum_crypto::x509::base64_decode;

    fn args(dir: Option<PathBuf>) -> GenPkiArgs {
        GenPkiArgs {
            service: "ferrum-admission".into(),
            namespace: "ferrum".into(),
            days: 365,
            out_dir: dir,
            template: None,
        }
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
