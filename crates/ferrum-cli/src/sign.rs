use crate::fsig;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

/// `ferrumctl sign <frmb> --key <hexfile> -o <fsig>`. The key file holds a
/// 32-byte Ed25519 seed as hex; prod key formats (KMS, cosign) are out of MVP-1.
pub fn sign_file(input: &Path, key: &Path, output: &Path) -> Result<()> {
    let raw = fs::read(input).with_context(|| format!("read {}", input.display()))?;
    if raw.starts_with(&fsig::SIGNED_MAGIC) {
        bail!(
            "{} уже FSIG; подписывается FRMB, не обёртка",
            input.display()
        );
    }
    if !raw.starts_with(&ferrum_compiler::BUNDLE_MAGIC) {
        bail!("{} не FRMB PolicyBundle", input.display());
    }
    let secret = read_secret_key(key)?;
    let public_key = ferrum_crypto::public_key_from_secret(&secret).map_err(anyhow::Error::from)?;
    let signature = ferrum_crypto::sign_bundle(&raw, &secret).map_err(anyhow::Error::from)?;
    let signed = fsig::encode_fsig(&raw, &signature, &public_key)?;
    fs::write(output, signed).with_context(|| format!("write {}", output.display()))?;
    println!(
        "signed: {} digest={}",
        output.display(),
        ferrum_crypto::bundle_digest(&raw).as_str()
    );
    Ok(())
}

fn read_secret_key(path: &Path) -> Result<Vec<u8>> {
    let hex = fs::read_to_string(path).with_context(|| format!("read key {}", path.display()))?;
    let secret = fsig::hex_decode(&hex)?;
    if secret.len() != ferrum_crypto::ED25519_SECRET_KEY_LEN {
        bail!(
            "key file must hold {} hex bytes, got {}",
            ferrum_crypto::ED25519_SECRET_KEY_LEN,
            secret.len()
        );
    }
    Ok(secret)
}
