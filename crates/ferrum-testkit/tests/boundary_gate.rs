//! `docs/MVP-1-BOUNDARY.md` may not outlive its evidence.
//!
//! The document is the one artifact in this tree that a status meeting reads
//! instead of the code, so it is the one artifact whose failure mode is a
//! sentence. Three things are mechanical here, and nothing else is:
//!
//! 1. Every citation in the «Делает» section resolves to a `fn` in a file
//!    under `crates/` or to a `stage('...')` in the `Jenkinsfile`. A renamed
//!    or deleted test takes the claim it carried down with it.
//! 2. The §D case list in the document is exactly `AcceptanceCase::ALL` —
//!    same set, same size, each once. Same shape as the completeness gates in
//!    `acceptance.rs` and `replay.rs`, and for the same reason: a §D case must
//!    not be droppable by leaving it out.
//! 3. Every `DEG_*` constant in `ferrum-agent` is named in the document.
//!    Sixteen degradation reasons went eight cycles with no reader because
//!    nothing required them to be written down anywhere.
//!
//! The fail-open this gate exists to refuse is an evidence column of English.
//! So the cell grammar is closed: `—`, or `K`/`U` markers each followed by one
//! backticked `source::name`, separated by `·`, and nothing else. A cell
//! carrying the word "covered" does not parse, and a claim that cannot cite
//! cannot be made in that section.
//!
//! What it cannot do: it checks that a cited `fn` exists, not that the `fn`
//! asserts what the row says, and not that it is a `#[test]`. The marker is
//! the author's word for where the test ran. Neither is closable by grep, and
//! pretending otherwise here would be this project's own defect, one level up.

use ferrum_testkit::AcceptanceCase;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The section whose rows must cite. Renaming it in the document empties the
/// section, and the §D check below then fails rather than passing quietly.
const DOES_HEADING: &str = "## Делает";
const NOT_EXECUTED: &str = "—";
const ENTRY_SEPARATOR: char = '·';

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/<crate> has two ancestors")
        .to_path_buf()
}

fn document() -> String {
    let path = repo_root().join("docs/MVP-1-BOUNDARY.md");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// One data row of one markdown table, with the section heading it sits under.
#[derive(Debug)]
struct Row {
    section: String,
    line: usize,
    cells: Vec<String>,
}

fn is_table_line(line: &str) -> bool {
    let t = line.trim();
    t.starts_with('|') && t.ends_with('|') && t.len() > 1
}

fn cells_of(line: &str) -> Vec<String> {
    let t = line.trim();
    let inner = &t[1..t.len() - 1];
    inner.split('|').map(|c| c.trim().to_string()).collect()
}

fn is_separator_row(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
}

/// Every data row of every table, tagged with its `##` section. `###`
/// subheadings do not change the section: the whole «Делает» section is
/// gated, however many tables it grows.
fn rows(doc: &str) -> Vec<Row> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut past_separator = false;
    for (i, line) in doc.lines().enumerate() {
        if line.starts_with("## ") {
            section = line.trim_end().to_string();
        }
        if !is_table_line(line) {
            past_separator = false;
            continue;
        }
        let cells = cells_of(line);
        if is_separator_row(&cells) {
            past_separator = true;
            continue;
        }
        if past_separator {
            out.push(Row {
                section: section.clone(),
                line: i + 1,
                cells,
            });
        }
    }
    out
}

/// One `K \`src::name\`` citation.
#[derive(Debug)]
struct Citation {
    marker: char,
    source: String,
    name: String,
}

/// Parses an evidence cell, or says why it is not evidence.
///
/// `—` is the empty citation list and the only accepted prose. Everything
/// else is markers and backticks; a cell with a word in it fails here, which
/// is the whole point of the section.
fn parse_evidence(cell: &str) -> Result<Vec<Citation>, String> {
    if cell == NOT_EXECUTED {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for raw in cell.split(ENTRY_SEPARATOR) {
        let entry = raw.trim();
        if entry.is_empty() {
            return Err(format!("empty citation in {cell:?}"));
        }
        let mut chars = entry.chars();
        let marker = chars.next().expect("non-empty");
        if marker != 'K' && marker != 'U' {
            return Err(format!(
                "citation {entry:?} must begin with the marker K or U, not {marker:?}"
            ));
        }
        let rest = chars.as_str();
        let Some(rest) = rest.strip_prefix(' ') else {
            return Err(format!(
                "citation {entry:?}: marker must be followed by a space"
            ));
        };
        let rest = rest.trim();
        if rest.matches('`').count() != 2 || !rest.starts_with('`') || !rest.ends_with('`') {
            return Err(format!(
                "citation {entry:?}: the identifier must be one backticked `source::name`, and \
                 nothing may sit outside the backticks — prose is not evidence"
            ));
        }
        let token = &rest[1..rest.len() - 1];
        let Some((source, name)) = token.split_once("::") else {
            return Err(format!(
                "citation {token:?}: expected `source::name`, e.g. `acceptance.rs::a_test` or \
                 `Jenkinsfile::BPF attach`"
            ));
        };
        if source.is_empty() || name.is_empty() {
            return Err(format!("citation {token:?}: empty source or name"));
        }
        out.push(Citation {
            marker,
            source: source.to_string(),
            name: name.to_string(),
        });
    }
    Ok(out)
}

/// The row-level marker the evidence implies: the markers present, sorted and
/// joined, or `—`. Written out in its own column so a row cannot summarise
/// three citations as one letter.
fn derived_marker(citations: &[Citation]) -> String {
    let mut seen: Vec<char> = citations.iter().map(|c| c.marker).collect();
    seen.sort_unstable();
    seen.dedup();
    if seen.is_empty() {
        return NOT_EXECUTED.to_string();
    }
    seen.iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("+")
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Resolves `source` to a file: a path under `crates/`, or a unique basename
/// there. An ambiguous basename is an error, not a first match — `lib.rs`
/// names fifteen files and a citation to one of them has to say which.
fn resolve(source: &str, sources: &[PathBuf], crates: &Path) -> Result<PathBuf, String> {
    let direct = crates.join(source);
    if direct.is_file() {
        return Ok(direct);
    }
    let suffix = format!("/{source}");
    let matches: Vec<&PathBuf> = sources
        .iter()
        .filter(|p| p.to_string_lossy().ends_with(&suffix))
        .collect();
    match matches.len() {
        0 => Err(format!(
            "no file under crates/ is named {source:?}: the citation names a source that is \
             not in this tree"
        )),
        1 => Ok(matches[0].clone()),
        _ => Err(format!(
            "{source:?} is ambiguous ({} files); qualify it, e.g. ferrum-agent/src/{source}",
            matches.len()
        )),
    }
}

/// Every citation in «Делает» resolves, and every row's marker column is the
/// one its citations imply.
#[test]
fn every_claim_in_the_does_section_cites_something_that_exists() {
    let doc = document();
    let root = repo_root();
    let crates = root.join("crates");
    let jenkinsfile = fs::read_to_string(root.join("Jenkinsfile")).expect("Jenkinsfile");
    let mut sources = Vec::new();
    rs_files(&crates, &mut sources);
    assert!(
        sources.len() > 10,
        "found {} rust sources under crates/: this gate would resolve nothing",
        sources.len()
    );

    let rows = rows(&doc);
    let does: Vec<&Row> = rows.iter().filter(|r| r.section == DOES_HEADING).collect();
    assert!(
        !does.is_empty(),
        "no table rows under {DOES_HEADING:?}: either the section was renamed or the claims \
         were removed, and this gate is checking nothing"
    );

    let mut failures: Vec<String> = Vec::new();
    for row in does {
        let at = format!("MVP-1-BOUNDARY.md:{}", row.line);
        if row.cells.len() < 3 {
            failures.push(format!(
                "{at}: a row in «Делает» needs at least three columns, the last two being the \
                 marker and the evidence; got {:?}",
                row.cells
            ));
            continue;
        }
        let marker = &row.cells[row.cells.len() - 2];
        let evidence = &row.cells[row.cells.len() - 1];
        let citations = match parse_evidence(evidence) {
            Ok(c) => c,
            Err(why) => {
                failures.push(format!("{at}: {why}"));
                continue;
            }
        };
        let expected = derived_marker(&citations);
        if marker != &expected {
            failures.push(format!(
                "{at}: marker column says {marker:?}, the evidence says {expected:?}"
            ));
        }
        for citation in &citations {
            if citation.source == "Jenkinsfile" {
                let stage = format!("stage('{}')", citation.name);
                if !jenkinsfile.contains(&stage) {
                    failures.push(format!(
                        "{at}: the Jenkinsfile has no {stage} — the stage this claim rests on \
                         was renamed or removed"
                    ));
                }
                continue;
            }
            let path = match resolve(&citation.source, &sources, &crates) {
                Ok(p) => p,
                Err(why) => {
                    failures.push(format!("{at}: {why}"));
                    continue;
                }
            };
            let body = fs::read_to_string(&path).expect("source file");
            if !body.contains(&format!("fn {}(", citation.name)) {
                failures.push(format!(
                    "{at}: {} has no `fn {}` — the claim outlived the test that carried it",
                    path.strip_prefix(&root).unwrap_or(&path).display(),
                    citation.name
                ));
            }
        }
    }

    assert!(failures.is_empty(), "\n{}\n", failures.join("\n"));
}

/// The §D case list in the document is `AcceptanceCase::ALL` and nothing else.
/// Same gate `acceptance.rs` and `replay.rs` already run against their own
/// coverage, applied to the document: a case cannot be quietly dropped from
/// the boundary by leaving its row out.
#[test]
fn the_document_lists_exactly_the_rfc_d_cases() {
    let doc = document();
    let rows = rows(&doc);
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for row in rows.iter().filter(|r| r.section == DOES_HEADING) {
        let first = row.cells.first().map(String::as_str).unwrap_or_default();
        if let Some(case) = AcceptanceCase::ALL.iter().find(|c| c.label() == first) {
            *seen.entry(case.label()).or_insert(0) += 1;
        }
    }

    let missing: Vec<&str> = AcceptanceCase::ALL
        .iter()
        .map(|c| c.label())
        .filter(|l| !seen.contains_key(l))
        .collect();
    assert!(
        missing.is_empty(),
        "§D cases with no row in the boundary document: {missing:?}. The label must be the \
         first cell, spelled exactly as `AcceptanceCase::label()`."
    );
    let duplicated: Vec<&&str> = seen
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(l, _)| l)
        .collect();
    assert!(
        duplicated.is_empty(),
        "§D cases listed twice: {duplicated:?}"
    );
    assert_eq!(
        seen.len(),
        AcceptanceCase::ALL.len(),
        "the document lists {} of the {} §D cases",
        seen.len(),
        AcceptanceCase::ALL.len()
    );
}

/// Every degradation reason the agent can raise is named in the document.
/// A reason nobody wrote down is a reason nobody reads, which is how twenty-two
/// counters spent eight cycles without one.
#[test]
fn every_degraded_reason_the_agent_can_raise_is_named_in_the_document() {
    let doc = document();
    let agent = fs::read_to_string(repo_root().join("crates/ferrum-agent/src/lib.rs"))
        .expect("ferrum-agent/src/lib.rs");

    let mut constants: Vec<String> = Vec::new();
    for line in agent.lines() {
        let Some(rest) = line.trim_start().strip_prefix("pub const DEG_") else {
            continue;
        };
        let tail: String = rest
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        if !tail.is_empty() {
            constants.push(format!("DEG_{tail}"));
        }
    }
    constants.sort();
    constants.dedup();
    assert!(
        constants.len() >= 16,
        "found {} DEG_ constants in ferrum-agent; the scan is broken, not the agent",
        constants.len()
    );

    let unnamed: Vec<&String> = constants
        .iter()
        .filter(|c| !doc.contains(c.as_str()))
        .collect();
    assert!(
        unnamed.is_empty(),
        "degradation reasons the agent can raise and the boundary document does not name: \
         {unnamed:?}"
    );
}

#[cfg(test)]
mod grammar {
    use super::*;

    /// The gate's own fail-open: a cell of English that parses. If these ever
    /// become `Ok`, the «Делает» section can say anything.
    #[test]
    fn prose_is_not_evidence() {
        for cell in [
            "covered by the acceptance suite",
            "implemented",
            "U covered by `acceptance.rs::x` and reviewed",
            "`acceptance.rs::x`",
            "K acceptance.rs::x",
            "K `acceptance.rs`",
            "partially proven",
        ] {
            assert!(parse_evidence(cell).is_err(), "{cell:?} parsed as evidence");
        }
    }

    #[test]
    fn a_marker_summarises_every_citation_it_covers() {
        let one = parse_evidence("U `acceptance.rs::a`").expect("parses");
        assert_eq!(derived_marker(&one), "U");
        let both = parse_evidence("U `acceptance.rs::a` · K `attach_live.rs::b`").expect("parses");
        assert_eq!(derived_marker(&both), "K+U");
        assert_eq!(derived_marker(&parse_evidence("—").expect("parses")), "—");
    }
}
