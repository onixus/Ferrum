use crate::validate;
use anyhow::{bail, Context, Result};
use ferrum_api::{ClusterSecurityPolicy, SecurityPolicy};
use ferrum_compiler::{bundle_digest_material, compile_cluster_policy, compile_namespaced_policy};
use ferrum_ids::{ADMISSION_ABI, AGENT_ABI};
use ferrum_policy::{validate_cluster_policy, validate_namespaced_policy};
use std::fs;
use std::path::Path;

/// `ferrumctl compile <yaml> -o <frmb>`: validate, compile, write the FRMB
/// digest material. The output is unsigned; agents refuse it until `sign`.
pub fn compile_file(input: &Path, output: &Path) -> Result<()> {
    let raw = fs::read_to_string(input).with_context(|| format!("read {}", input.display()))?;
    let (frmb, digest) = compile_yaml(&raw)?;
    fs::write(output, frmb).with_context(|| format!("write {}", output.display()))?;
    println!("compiled: {} digest={digest}", output.display());
    Ok(())
}

pub fn compile_yaml(raw: &str) -> Result<(Vec<u8>, String)> {
    let meta = validate::typed_meta(raw)?;
    let bundle = match meta.kind.as_str() {
        "ClusterSecurityPolicy" => {
            let obj: ClusterSecurityPolicy =
                validate::parse_resource(raw, ClusterSecurityPolicy::new)?;
            validate_cluster_policy(&obj.spec).map_err(anyhow::Error::from)?;
            compile_cluster_policy(&obj.spec).map_err(anyhow::Error::from)?
        }
        "SecurityPolicy" => {
            let obj: SecurityPolicy = validate::parse_resource(raw, SecurityPolicy::new)?;
            validate_namespaced_policy(&obj.spec).map_err(anyhow::Error::from)?;
            compile_namespaced_policy(&obj.spec).map_err(anyhow::Error::from)?
        }
        other => bail!("kind {other} не компилируется в PolicyBundle"),
    };
    let frmb = bundle_digest_material(
        AGENT_ABI,
        ADMISSION_ABI,
        &bundle.admission_program,
        &bundle.ebpf_spec,
        &bundle.wasm,
    )
    .map_err(anyhow::Error::from)?;
    let written = ferrum_crypto::bundle_digest(&frmb);
    if written != bundle.digest {
        bail!(
            "digest расходится: compile={} material={}",
            bundle.digest.as_str(),
            written.as_str()
        );
    }
    Ok((frmb, bundle.digest.as_str().to_string()))
}
