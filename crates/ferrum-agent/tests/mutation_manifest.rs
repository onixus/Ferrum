//! The floor under `tests/mutations/run.sh`.
//!
//! That script iterates `"$here"/*.patch` and asserts nothing about how many
//! patches it found. Delete `02`…`06` and keep `01`: one mutation is measured,
//! `survivors=0`, `unmeasured=0`, and `Jenkinsfile::BPF join mutations` prints
//! "ok: every mutation beside this script makes tests/attach_join.rs fail" and
//! goes green having measured a sixth of what the boundary document claims for
//! it. Nothing else in this tree reads that directory, so the six exist only as
//! prose in `docs/MVP-1-BOUNDARY.md`.
//!
//! This is the same "green having run almost nothing" shape the `BPF attach`
//! and `BPF join` stages closed by deriving their counts from the source, left
//! in place in the third stage of the same triple. The count belongs in the
//! tree rather than in the harness that would have to notice its own absence:
//! `run.sh` reads the list below and refuses to run against a directory that
//! does not match it, and this test — which needs no kernel, no nightly and no
//! bpf-linker — fails under a plain `cargo test --workspace` the moment a patch
//! is deleted, renamed, or added without being registered.
//!
//! Deleting *all* the patches happens to fail today, because the unmatched glob
//! reaches `git apply` as a literal and is counted STALE. That is an accident
//! of `sh` and not a control, and it says nothing about deleting five.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Every mutation the join gate is measured against. Each deletes one thing the
/// join is supposed to prove; the names are the claims, and `run.sh`'s output
/// is read by them.
///
/// A patch added here without a file beside it, or a file added without a line
/// here, fails below — a mutation set is only evidence about the gate if what
/// ran and what was meant to run are the same list.
const MUTATIONS: [&str; 6] = [
    "01-react-reports-executed-without-signalling.patch",
    "02-signal-responder-claims-a-kill-it-never-sent.patch",
    "03-stale-target-guard-removed.patch",
    "04-emit-never-flags-a-truncated-path.patch",
    "05-decoder-trusts-the-truncation-flag.patch",
    "06-the-node-that-can-never-signal-reports-healthy.patch",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root")
}

fn mutations_dir() -> PathBuf {
    repo_root().join("crates/ferrum-agent/tests/mutations")
}

fn patch_files() -> BTreeSet<String> {
    let dir = mutations_dir();
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("directory entry").path();
        if path.extension().map(|e| e == "patch").unwrap_or(false) {
            out.insert(
                path.file_name()
                    .and_then(|n| n.to_str())
                    .expect("patch file name")
                    .to_string(),
            );
        }
    }
    out
}

/// The directory holds exactly these mutations.
#[test]
fn the_mutation_set_is_the_one_the_gate_is_measured_against() {
    let found = patch_files();
    let declared: BTreeSet<String> = MUTATIONS.iter().map(|m| m.to_string()).collect();
    assert_eq!(
        found, declared,
        "the patches in tests/mutations/ are not the set this workspace claims to \
         measure its join gate against. `run.sh` iterates whatever it finds and asserts \
         nothing about how many, so a deleted patch is a mutation the gate is no longer \
         measured against and a stage that still prints ok. Re-anchor a drifted patch or \
         register a new one here; do not delete one to make this pass."
    );
}

/// Each patch still points at a file in this tree.
///
/// `run.sh` reports a patch that no longer applies as STALE and fails, which is
/// the right answer on a machine that can run the harness. This is the part of
/// it that a plain `cargo test` can check: a patch anchored to a path another
/// slice has since deleted or moved can never be measured again, and the sooner
/// that is a failing test the smaller the re-anchoring is.
#[test]
fn every_mutation_targets_a_file_that_still_exists() {
    let root = repo_root();
    for name in MUTATIONS {
        let path = mutations_dir().join(name);
        let body = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
        let targets: Vec<&str> = body
            .lines()
            .filter_map(|line| line.strip_prefix("--- a/"))
            .map(str::trim)
            .collect();
        assert!(
            !targets.is_empty(),
            "{name} carries no `--- a/<path>` header, so it patches nothing and \
             `git apply` would refuse it: a mutation that cannot be applied measures \
             nothing about the gate"
        );
        for target in targets {
            assert!(
                root.join(target).is_file(),
                "{name} is anchored to {target}, which is not in this tree. It can never \
                 apply again, so the property it measures is no longer measured — \
                 re-anchor it to the current source rather than deleting it."
            );
        }
    }
}

/// `run.sh` reads the list above rather than counting what it finds.
///
/// The harness is the thing that cannot notice its own directory shrinking, so
/// the floor has to come from outside it — and this asserts the two have not
/// come apart, which is the failure mode of every derived count: the deriver
/// stops matching the source and starts reporting zero.
#[test]
fn the_runner_derives_its_floor_from_this_file() {
    let script = std::fs::read_to_string(mutations_dir().join("run.sh")).expect("run.sh");
    let anchor = "crates/ferrum-agent/tests/mutation_manifest.rs";
    assert!(
        script.contains(anchor),
        "tests/mutations/run.sh no longer reads {anchor}, so it is back to measuring \
         whatever patches happen to be on disk and reporting ok for one of six"
    );
    // The expression the script greps with, run here against this file: if it
    // stops matching, the script's floor silently becomes zero and every count
    // check in it passes.
    let this = std::fs::read_to_string(file!())
        .or_else(|_| std::fs::read_to_string(repo_root().join(file!())))
        .expect("this source file");
    let matched = this
        .lines()
        .filter(|line| {
            let line = line.trim();
            line.starts_with('"') && line.ends_with(".patch\",")
        })
        .count();
    assert_eq!(
        matched,
        MUTATIONS.len(),
        "the shape run.sh greps for no longer matches MUTATIONS: it would derive a floor \
         of {matched} instead of {}. Keep one quoted patch name per line.",
        MUTATIONS.len()
    );
}
