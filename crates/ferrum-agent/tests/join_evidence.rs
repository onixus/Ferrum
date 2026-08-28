//! The evidence set of the `BPF join` stage, anchored outside the file the
//! stage reads it from.
//!
//! `Jenkinsfile::BPF join` requires one `waitpid`-confirmed line per §D row
//! that ends in a kill, and derived the *set* of lines it requires by grepping
//! `signalled("…")` out of `tests/attach_join.rs`. That count is derived from
//! the source deliberately and for a stated reason; the set has the same
//! self-lowering property one level finer, and is cheaper to hit. Gut the kill
//! half of one test — keep the record and decode assertions, drop the responder
//! call and its `signalled(…)` — and the test still passes, the passed count
//! still equals the expected count, the required set silently shrinks from four
//! labels to three, both kernel stages stay green, and the §D row that test
//! covers keeps a `K` witness that no longer carries a record to a signal.
//! `boundary_gate` cannot see it either: the `fn` it cites still exists.
//!
//! So the set lives here, in a file no edit to a join test touches, and this
//! test holds all three ends together:
//!
//!   * every row below still has a `#[test]` in `attach_join.rs` whose body
//!     reaches a confirmed SIGKILL and prints its evidence line;
//!   * every `signalled(…)` label in that file is a row below, so a kill that
//!     is added or renamed is registered here rather than silently widening
//!     what the stage happens to require;
//!   * every row below is cited by `docs/MVP-1-BOUNDARY.md`, which is where the
//!     §D claim these tests are the witness for is written down.
//!
//! This runs under a plain `cargo test --workspace`. It asserts nothing about
//! the kernel — it reads the join's source as text — which is the point: the
//! stage that runs the join is exactly the one that cannot be trusted to notice
//! its own evidence set getting smaller.

use std::path::{Path, PathBuf};

/// One §D row whose witness ends in a real SIGKILL, and the line the join
/// prints once `waitpid` has confirmed it.
struct Kill {
    test: &'static str,
    evidence: &'static str,
}

/// `Jenkinsfile::BPF join` reads this list — the `evidence:` lines — rather
/// than `attach_join.rs`. Keep the shape: one field per line, the label last.
const REQUIRED_KILLS: [Kill; 4] = [
    Kill {
        test: "a_kernel_execve_of_a_shell_is_killed_by_the_signed_bundle",
        evidence: "no-shell",
    },
    Kill {
        test: "a_kernel_openat_of_docker_sock_is_killed_by_the_signed_bundle",
        evidence: "no-runtime-sock",
    },
    Kill {
        test: "a_truncated_docker_sock_path_still_kills_and_says_the_match_was_asserted",
        evidence: "no-runtime-sock (truncated path)",
    },
    Kill {
        test: "a_kernel_record_stripped_of_the_flag_is_still_read_as_truncated",
        evidence: "no-runtime-sock (flagless truncated path)",
    },
];

/// What a test body has to contain to be carrying a record to a signal, and
/// what each one is: the verdict is a kill, the process died, the death was a
/// SIGKILL and not an exit, and the line the stage greps was printed from the
/// far end of that. Dropping any one of them is the bypass this file exists
/// for; the audit's version dropped all four at once.
const KILL_HALF: [(&str, &str); 4] = [
    ("assert_killed(", "the verdict is asserted to be a kill"),
    ("wait_for_death(", "the probe is reaped and its status read"),
    ("libc::SIGKILL", "the death is asserted to be a SIGKILL"),
    ("signalled(", "the evidence line is printed after that"),
];

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

fn join_source() -> String {
    read("crates/ferrum-agent/tests/attach_join.rs")
}

/// The body of `#[test] fn <name>` in `attach_join.rs`.
///
/// The tests live one level in, inside `mod gate`, so the function opens at
/// four spaces and closes on a line that is exactly four spaces and a brace.
/// `None` when there is no such definition, which is a different failure from
/// a body that has lost its kill and is reported as one.
fn test_body<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    let at = source.find(&format!("\n    fn {name}("))? + 1;
    let rest = &source[at..];
    let end = rest.find("\n    }\n")? + "\n    }\n".len();
    Some(&rest[..end])
}

/// Every `signalled("…")` label in the join, in source order.
fn signalled_labels(source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find("signalled(\"") {
        rest = &rest[at + "signalled(\"".len()..];
        let Some(end) = rest.find('"') else { break };
        out.push(rest[..end].to_string());
        rest = &rest[end..];
    }
    out
}

/// Each row's test is still there, and still carries a record to a signal.
#[test]
fn every_required_kill_still_reaches_a_confirmed_sigkill() {
    let source = join_source();
    for kill in &REQUIRED_KILLS {
        let body = test_body(&source, kill.test).unwrap_or_else(|| {
            panic!(
                "attach_join.rs defines no `fn {}`. `Jenkinsfile::BPF join` requires the \
                 evidence line {:?} of a test that is not there, so the stage would fail on \
                 a missing line rather than on the missing §D witness — and if the line is \
                 printed from anywhere else, on nothing at all.",
                kill.test, kill.evidence
            )
        });
        for (needle, what) in KILL_HALF {
            assert!(
                body.contains(needle),
                "attach_join.rs::{} no longer contains `{needle}`, so {what} is gone. The \
                 test can still pass on its record and decode assertions alone: the §D row \
                 it witnesses would keep a K citation that never reaches a signal, the join \
                 stage's passed count would not move, and the evidence line {:?} would stop \
                 being required by a stage that reads its own requirements out of this file.",
                kill.test,
                kill.evidence
            );
        }
        let line = format!("signalled(\"{}\"", kill.evidence);
        assert!(
            body.contains(&line),
            "attach_join.rs::{} does not print the evidence line {:?} that \
             `Jenkinsfile::BPF join` requires of it",
            kill.test,
            kill.evidence
        );
    }
}

/// And nothing prints an evidence line that is not a row above.
///
/// The other direction, and the one that keeps this file from becoming prose: a
/// kill added to the join has to be registered here, or the stage would require
/// a line this list does not know about and this list would stop describing the
/// §D rows the join covers.
#[test]
fn the_join_prints_exactly_the_evidence_lines_this_file_requires() {
    let source = join_source();
    let printed: std::collections::BTreeSet<String> =
        signalled_labels(&source).into_iter().collect();
    let required: std::collections::BTreeSet<String> = REQUIRED_KILLS
        .iter()
        .map(|k| k.evidence.to_string())
        .collect();
    assert!(
        !printed.is_empty(),
        "no `signalled(\"…\")` call site is left in attach_join.rs. Every §D kill row's \
         witness has stopped emitting the one line that says a signal was confirmed, and \
         `Jenkinsfile::BPF join` derives its required set from those call sites: it would \
         require nothing and pass."
    );
    assert_eq!(
        printed, required,
        "the evidence lines attach_join.rs prints and the ones this file requires have \
         drifted apart. A kill added to the join must be registered in REQUIRED_KILLS \
         beside the §D row it witnesses; one removed is a §D row losing its K witness."
    );
}

/// Each row is a claim the boundary document makes, not one this file invented.
#[test]
fn every_required_kill_is_a_row_the_boundary_document_cites() {
    let doc = read("docs/MVP-1-BOUNDARY.md");
    for kill in &REQUIRED_KILLS {
        assert!(
            doc.contains(&format!("attach_join.rs::{}", kill.test)),
            "docs/MVP-1-BOUNDARY.md cites no `attach_join.rs::{}`. This list is the §D \
             rows whose witness is a real SIGKILL; a row that is not in the document is \
             this file requiring something on its own authority.",
            kill.test
        );
    }
}

/// The readers above, against bodies whose answer is known.
///
/// Without this, "no kill is missing" is equally what a `test_body` that has
/// stopped finding anything reports — and an extractor that returns the whole
/// file would find every needle in every test.
#[test]
fn the_body_reader_finds_one_test_and_notices_a_gutted_one() {
    let source =
        "mod gate {\n    #[test]\n    fn kills() {\n        assert_killed(&e, \"r\", t);\n\
         \x20       let s = probe.wait_for_death(\"r\");\n        assert_eq!(x, libc::SIGKILL);\n\
         \x20       signalled(\"r\", probe.pid);\n    }\n\n    #[test]\n    fn decodes_only() {\n\
         \x20       assert_probe_record(&e, &c, t);\n    }\n}\n";
    let killer = test_body(source, "kills").expect("the kill test is found");
    for (needle, _) in KILL_HALF {
        assert!(
            killer.contains(needle),
            "{needle} is in the kill test's body"
        );
    }
    let gutted = test_body(source, "decodes_only").expect("the other test is found");
    for (needle, _) in KILL_HALF {
        assert!(
            !gutted.contains(needle),
            "{needle} leaked in from the neighbouring test: an extractor that runs past \
             one body's closing brace finds every needle in every test and would report \
             a gutted test as intact"
        );
    }
    assert!(test_body(source, "no_such_test").is_none());
    assert_eq!(signalled_labels(source), vec!["r".to_string()]);
}
