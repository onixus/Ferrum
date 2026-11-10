//! `ferrumctl sign-mapping`: Ed25519 over the mapping file's own bytes.
//!
//! Not FSIG and not the bundle signer. The YAML is not parsed, so a comment
//! or a key written inside it cannot be stripped before the signature. The
//! public key is printed; this command does not write `mapping-trust-root`.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

/// `ferrumctl sign-mapping <yaml> --key <seedfile> -o <file.sig>`.
///
/// `seedfile` is a 32-byte Ed25519 seed as hex. The signature file is
/// lowercase hex of the 64-byte signature and nothing else.
pub fn sign_mapping_file(input: &Path, key: &Path, output: &Path) -> Result<()> {
    let raw = fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let secret = read_secret_key(key)?;
    let public_key = ferrum_crypto::public_key_from_secret(&secret).map_err(anyhow::Error::from)?;
    let signature = ferrum_crypto::sign_mapping(&raw, &secret).map_err(anyhow::Error::from)?;
    fs::write(output, hex_encode(&signature))
        .with_context(|| format!("write {}", output.display()))?;
    println!("signed: {}", output.display());
    println!("publicKey: {}", hex_encode(&public_key));
    Ok(())
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn read_secret_key(path: &Path) -> Result<Vec<u8>> {
    let text = fs::read_to_string(path).with_context(|| format!("read key {}", path.display()))?;
    let secret = crate::fsig::hex_decode(&text)?;
    if secret.len() != ferrum_crypto::ED25519_SECRET_KEY_LEN {
        bail!(
            "key file must hold {} hex bytes, got {}",
            ferrum_crypto::ED25519_SECRET_KEY_LEN,
            secret.len()
        );
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrum-sign-map-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    struct Rm(std::path::PathBuf);

    impl Drop for Rm {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn sign_mapping_signs_file_bytes_and_does_not_write_a_trust_root() {
        let dir = temp_dir("bytes");
        let _rm = Rm(dir.clone());
        let input = dir.join("mitre-attack-mapping.yaml");
        // A comment and an embedded key must survive. Reserializing would drop
        // the comment, and the signature would then not match these bytes.
        let raw = b"# keep this comment\nschemaVersion: 2\npublicKey: not-the-pin\n".to_vec();
        fs::write(&input, &raw).expect("yaml");
        let seed = [0x5a_u8; 32];
        let key = dir.join("seed.hex");
        fs::write(&key, hex_encode(&seed)).expect("seed");
        let output = dir.join("mitre-attack-mapping.yaml.sig");
        sign_mapping_file(&input, &key, &output).expect("sign");

        assert_eq!(fs::read(&input).expect("yaml bytes"), raw);
        let sig_text = fs::read_to_string(&output).expect("sig");
        assert_eq!(sig_text.len(), ferrum_crypto::ED25519_SIGNATURE_LEN * 2);
        assert!(sig_text
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        let sig = crate::fsig::hex_decode(&sig_text).expect("hex");
        let public_key = ferrum_crypto::public_key_from_secret(&seed).expect("pk");
        ferrum_crypto::verify_mapping_signature(&raw, &sig, &public_key).expect("verify");
        let bundle = ferrum_crypto::sign_bundle(&raw, &seed).expect("bundle domain");
        assert_ne!(sig, bundle);
        assert!(!dir.join("mapping-trust-root").exists());
        assert!(!dir.join("policies/mapping/mapping-trust-root").exists());
    }

    #[test]
    fn sign_mapping_rejects_a_short_seed_without_writing_the_signature() {
        let dir = temp_dir("short");
        let _rm = Rm(dir.clone());
        let input = dir.join("mapping.yaml");
        let raw = b"schemaVersion: 2\n";
        fs::write(&input, raw).expect("yaml");
        let key = dir.join("seed.hex");
        fs::write(&key, "abcd").expect("seed");
        let output = dir.join("mapping.yaml.sig");
        let err = sign_mapping_file(&input, &key, &output).expect_err("short seed");
        assert!(format!("{err:#}").contains("hex bytes"), "{err:#}");
        assert_eq!(fs::read(&input).expect("yaml"), raw);
        assert!(!output.exists());
    }
}
