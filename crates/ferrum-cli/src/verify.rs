use crate::fsig;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

/// `ferrumctl verify <fsig> --trust-root <hex>`. The pin is the only trust
/// root; the key embedded in the FSIG may only equal it. Failure is a
/// non-zero exit, never a warning.
pub fn verify_file(input: &Path, trust_root_hex: &str) -> Result<()> {
    let bytes = fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let trust_root = parse_trust_root(trust_root_hex)?;
    let (public_key, signature, raw) = fsig::decode_fsig(&bytes)?;
    if public_key != trust_root {
        bail!("embedded FSIG public key does not match caller trust-root pin");
    }
    let digest = ferrum_crypto::verify_bundle_signature(&raw, &signature, &trust_root)
        .map_err(anyhow::Error::from)?;
    println!("verified: {} digest={}", input.display(), digest.as_str());
    Ok(())
}

fn parse_trust_root(hex: &str) -> Result<Vec<u8>> {
    let pin = fsig::hex_decode(hex)?;
    if pin.len() != ferrum_crypto::ED25519_PUBLIC_KEY_LEN {
        bail!(
            "trust-root pin must be {} hex bytes, got {}",
            ferrum_crypto::ED25519_PUBLIC_KEY_LEN,
            pin.len()
        );
    }
    if pin.iter().all(|b| *b == 0) {
        bail!("trust-root pin must not be all zeros");
    }
    Ok(pin)
}
