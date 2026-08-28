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
//! 3. Every reason the agent can report as degraded is named in the document.
//!    Sixteen degradation reasons went eight cycles with no reader because
//!    nothing required them to be written down anywhere.
//!
//! The fail-open this gate exists to refuse is an evidence column of English.
//! So the cell grammar is closed: `—`, or `K`/`U` markers each followed by one
//! backticked `source::name`, separated by `·`, and nothing else. A cell
//! carrying the word "covered" does not parse, and a claim that cannot cite
//! cannot be made in that section.
//!
//! `—` is the empty citation list, and it is the grammar's own way out: a
//! «Делает» table all of whose rows read `| — | — |` satisfies both checks
//! above while claiming nothing, under a heading whose entire rule is that
//! nothing unexecuted appears there. So `—` is allowed for exactly the
//! subjects listed in `NOT_EXECUTED_SUBJECTS` and nowhere else, and adding a
//! subject to that list is a deliberate act with a reason beside it.
//!
//! What it cannot do: it checks that a cited `fn` is *defined* in the file, not
//! that it asserts what the row says, and not that it is a `#[test]`. The
//! marker is the author's word for where the test ran. Neither is closable by
//! grep, and pretending otherwise here would be this project's own defect, one
//! level up. It used to be weaker still — a substring search for `fn NAME(`,
//! which a comment, a doc comment or a string literal satisfied, so a claim
//! could be resolved by the prose describing the test that used to carry it.
//! The match is now anchored at the start of a line.
//!
//! It used to be one-directional, and that was the hole: requiring that what
//! is cited exists says nothing about what exists and is not cited, so the
//! document rotted silently *downward* — a slice that proved something and did
//! not rewrite its row left the boundary understating the tree, and no build
//! turned red. That happened twice in cycle 9, to two rows this file had no way
//! to notice.
//!
//! One case of that direction is now closed, and only one: every `#[test]`
//! under `CITED_TEST_DIRS` must be cited by a row or named in
//! `UNCITED_TESTS` with a reason. Those two directories hold nothing but
//! gates, so each test in them is a claim about the product — the kind of thing
//! this document is a list of. The general form ("everything true about this
//! product is written down") has no mechanical form and is still a human duty,
//! which is why the document says so in its own words as well.

use ferrum_testkit::AcceptanceCase;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The section whose rows must cite. Renaming it in the document empties the
/// section, and the §D check below then fails rather than passing quietly.
const DOES_HEADING: &str = "## Делает";
const NOT_EXECUTED: &str = "—";
const ENTRY_SEPARATOR: char = '·';

/// The subjects in «Делает» that may carry `—`, each because the thing the row
/// is about has no executor in this tree at all.
///
/// `exception without TTL -> API reject` is the §D case whose subject is the
/// API server, and no API server has ever run here. Its row must still exist —
/// the §D check below refuses a dropped case — so it must be able to say that
/// it is not executed. Nothing else may: a row that has an executor and does
/// not cite it belongs in a different section of the document, not in this one
/// with a dash.
const NOT_EXECUTED_SUBJECTS: [&str; 1] = ["exception without TTL -> API reject"];

/// Modifiers a `fn` item may carry before the keyword, in the order rustfmt
/// writes them. Trailing space included: this is prefix-stripping, not word
/// matching.
const FN_MODIFIERS: [&str; 7] = [
    "pub ",
    "pub(crate) ",
    "pub(super) ",
    "default ",
    "const ",
    "async ",
    "unsafe ",
];

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

/// Whether `body` *defines* `fn name`, as opposed to mentioning it.
///
/// Anchored at the start of a line, after indentation and after the modifiers
/// a `fn` item may carry. The check this replaces was `body.contains("fn
/// NAME(")`, which a doc comment saying "see `fn NAME(...)`", a `//` note or a
/// string literal all satisfied — so a citation could resolve against the
/// prose left behind by a deleted test, which is the exact rot this gate
/// exists to catch.
///
/// Still not proof that the item is a `#[test]`, and still not proof that it
/// asserts the row's claim. It is proof that it is code.
fn defines_fn(body: &str, name: &str) -> bool {
    let wanted = format!("fn {name}(");
    body.lines().any(|line| {
        let mut rest = line.trim_start();
        while let Some(modifier) = FN_MODIFIERS.iter().find(|m| rest.starts_with(**m)) {
            rest = &rest[modifier.len()..];
        }
        rest.starts_with(&wanted)
    })
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
        let subject = row.cells.first().map(String::as_str).unwrap_or_default();
        if citations.is_empty() && !NOT_EXECUTED_SUBJECTS.contains(&subject) {
            failures.push(format!(
                "{at}: {subject:?} is in «Делает» and cites nothing. The heading's rule is that \
                 nothing unexecuted appears under it, so a dash here is a claim of no executor \
                 anywhere in the tree — say so in NOT_EXECUTED_SUBJECTS with the reason, or move \
                 the row to a section that admits unproven things"
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
            if !defines_fn(&body, &citation.name) {
                failures.push(format!(
                    "{at}: {} defines no `fn {}` — the claim outlived the test that carried it",
                    path.strip_prefix(&root).unwrap_or(&path).display(),
                    citation.name
                ));
            }
        }
    }

    assert!(failures.is_empty(), "\n{}\n", failures.join("\n"));
}

/// The directories whose every `#[test]` the document must account for.
///
/// Not "every test in the workspace". A unit test beside the code it tests is
/// an implementation detail of a crate, and requiring the boundary document to
/// name each one would turn it into a test index nobody reads — the failure
/// mode this file's own header warns about, arrived at from the other side.
/// These two directories are different: they hold nothing but gates. Every
/// file in them exists to establish a claim about the product rather than
/// about a function, which is exactly the kind of claim this document is a
/// list of. A test here that no row cites is either a claim the document is
/// missing or a test that has stopped being about the product.
const CITED_TEST_DIRS: [&str; 2] = ["crates/ferrum-testkit/tests", "crates/ferrum-agent/tests"];

/// Tests in those directories that no row cites, each with the reason it is
/// not a boundary claim.
///
/// Empty, and landed empty on purpose. Seeding this with everything currently
/// uncited would make the gate pass on the day it was written and prove
/// nothing afterwards — "green having run almost nothing", the shape cycle 10
/// closed twice for the kernel stages, aimed at a document. Making the rule a
/// warning instead would be the same thing wearing a different hat. So the
/// thirty-five tests this gate found uncited were answered with rows, and this
/// list is what a *future* test that genuinely is not a boundary claim goes
/// into — with a sentence, one entry at a time, the way `NOT_EXECUTED_SUBJECTS`
/// works above.
const UNCITED_TESTS: [(&str, &str); 0] = [];

/// Every `#[test]` in `text`, by the name of the function under the attribute.
///
/// Attributes stack — `#[test]` then `#[ignore]`, or a `#[cfg_attr(...)]`
/// between them — so the scan walks forward to the first `fn` rather than
/// assuming the next line is one.
fn tests_in(text: &str) -> Vec<String> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() != "#[test]" {
            continue;
        }
        for candidate in lines.iter().skip(i + 1) {
            let mut rest = candidate.trim_start();
            if rest.starts_with('#') {
                continue;
            }
            while let Some(modifier) = FN_MODIFIERS.iter().find(|m| rest.starts_with(**m)) {
                rest = &rest[modifier.len()..];
            }
            let Some(rest) = rest.strip_prefix("fn ") else {
                break;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.push(name);
            }
            break;
        }
    }
    out
}

/// The other direction, closed for the first time: every gate in this tree is
/// cited by a row.
///
/// The header of this file says the gate is one-directional and says why that
/// matters — a slice that proves something and does not rewrite its row leaves
/// the document *understating* the tree, and no build turns red. That is not
/// closable in general: "everything true about this product is written down"
/// has no mechanical form. One case of it is. A `#[test]` under
/// `CITED_TEST_DIRS` is a claim about the product that somebody executed, and
/// requiring each one to appear in a row converts "the document understates the
/// tree" from a human duty into a build failure — the same trick
/// `COUNTERS_WITHOUT_A_REASON` plays on the counters, aimed at the document.
///
/// What it still cannot do, and this is the same limit as the forward
/// direction: it checks that the *name* appears in a citation, not that the row
/// carrying it describes what the test asserts. A row that cites a test and
/// then says something else about it satisfies both directions. And it says
/// nothing at all about the unit tests beside the code, which is most of them.
#[test]
fn every_gate_in_this_tree_is_cited_by_a_row() {
    let doc = document();
    let root = repo_root();
    let crates = root.join("crates");
    let mut sources = Vec::new();
    rs_files(&crates, &mut sources);

    // What the document cites, resolved to the file each citation names, so a
    // name cited against another file does not answer for this one.
    let mut cited: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
    for row in rows(&doc).iter().filter(|r| r.section == DOES_HEADING) {
        let Some(evidence) = row.cells.last() else {
            continue;
        };
        let Ok(citations) = parse_evidence(evidence) else {
            // The forward gate is what reports an unparseable cell; reporting
            // it twice would name the same defect from two tests.
            continue;
        };
        for citation in citations {
            if citation.source == "Jenkinsfile" {
                continue;
            }
            if let Ok(path) = resolve(&citation.source, &sources, &crates) {
                cited.entry(path).or_default().push(citation.name);
            }
        }
    }

    let mut found = 0usize;
    let mut orphans: Vec<String> = Vec::new();
    for dir in CITED_TEST_DIRS {
        let dir = root.join(dir);
        assert!(
            dir.is_dir(),
            "{} is not a directory: this gate would scan nothing and pass",
            dir.display()
        );
        let mut files = Vec::new();
        rs_files(&dir, &mut files);
        files.sort();
        for file in files {
            let body = fs::read_to_string(&file).expect("test source");
            let empty = Vec::new();
            let names = cited.get(&file).unwrap_or(&empty);
            for test in tests_in(&body) {
                found += 1;
                if names.contains(&test) || UNCITED_TESTS.iter().any(|(n, _)| *n == test) {
                    continue;
                }
                orphans.push(format!(
                    "  {}::{test}",
                    file.strip_prefix(&root).unwrap_or(&file).display()
                ));
            }
        }
    }

    assert!(
        found > 40,
        "this gate found {found} #[test] items under {CITED_TEST_DIRS:?}; there were \
         seventy-seven when the floor was written, so the scan is broken rather than the \
         tree, and 'nothing is uncited' would be true for the wrong reason"
    );
    assert!(
        orphans.is_empty(),
        "these gates exist and no row of «Делает» cites them:\n{}\n\
         A test nobody cites is a claim the document does not make: the boundary then \
         understates the tree, which is the direction it rots in silently and the one no \
         other check here can see. Write the row. If a test genuinely is not a claim about \
         the product, name it in UNCITED_TESTS with the sentence saying why — one at a \
         time, never as a batch to get this green.",
        orphans.join("\n")
    );
}

/// The heading of the subject inventory table, and the one column that is not
/// evidence.
const INVENTORY_HEADING: &str = "### Инвентарь субъектов";

/// A `<resource>/status` a manifest may grant, and the type in `ferrum-api`
/// whose presence in a subject's sources is what writing it looks like here.
///
/// Both policy kinds share `PolicyStatus`, which is why this is a table and
/// not a name transformation.
const STATUS_TYPES: [(&str, &str); 7] = [
    ("clustersecuritypolicies/status", "PolicyStatus"),
    ("securitypolicies/status", "PolicyStatus"),
    ("policyexceptions/status", "PolicyExceptionStatus"),
    ("policylibraries/status", "PolicyLibraryStatus"),
    ("runtimeprofiles/status", "RuntimeProfileStatus"),
    ("ferrumclusters/status", "FerrumClusterStatus"),
    ("compliancesnapshots/status", "ComplianceSnapshotStatus"),
];

/// Every crate a manifest under `deploy/` asks the cluster to run, by the
/// `image:` lines that name them.
fn shipped_subjects(root: &Path) -> BTreeMap<String, ()> {
    let mut files = Vec::new();
    yaml_files(&root.join("deploy"), &mut files);
    let mut out = BTreeMap::new();
    for file in files {
        let body = fs::read_to_string(&file).expect("manifest");
        for line in body.lines() {
            let Some(reference) = line.trim().strip_prefix("image:") else {
                continue;
            };
            let reference = reference.trim().trim_matches('"');
            let repo = match reference.rfind(':') {
                Some(colon) if colon > reference.rfind('/').unwrap_or(0) => &reference[..colon],
                _ => reference,
            };
            if let Some(name) = repo.rsplit('/').next() {
                out.insert(name.to_string(), ());
            }
        }
    }
    out
}

fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            yaml_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "yaml") {
            out.push(path);
        }
    }
}

/// Every shipped binary has exactly one channel through which an operator
/// learns it is broken, that channel is reached by something executed, and no
/// subject holds a grant on a second channel it never writes.
///
/// Deliberately not a census. Every other enumeration in this tree — the
/// `DEG_*` prefix scan, the `degraded_reasons_at` body scan, the
/// `mark_terminal_fault` argument scan, the counter census, `status.json`, the
/// degradation table above — runs over `ferrum_agent::Agent`. Two of the three
/// shipped binaries have no `is_degraded()`, no reason list and no status
/// surface, so they cannot appear in any of those in either direction, *by
/// construction*: a census over a list that does not exist is vacuously
/// complete, which is the most dangerous state a gate can be in — green because
/// there is nothing to check, and indistinguishable from green because
/// everything checks out.
///
/// Inventing `is_degraded()` for the webhook to make a census possible would be
/// worse than the gap: it would create a reason list that process has nowhere
/// to publish, and cycle 10 was right to refuse the same move when it declined
/// to tie `COUNTERS_WITHOUT_A_REASON` to this document. So the instrument is an
/// inventory, and three assertions that need no reason list:
///
/// 1. one row per shipped binary, and exactly one — a subject with two channels
///    has one an operator does not read, and a subject with none is invisible;
/// 2. the channel is reachable — the row cites something that ran;
/// 3. the channel carries a cause rather than a constant, in the one form that
///    is decidable from the tree: no subject may hold a write grant on a
///    `<kind>/status` that nothing in it writes. A granted status subresource
///    with no writer is a second channel that reports the zero value of its own
///    struct forever, and it is indistinguishable from a healthy one.
///
/// `FerrumClusterStatus.degraded` was exactly that: `deploy/controller/rbac.yaml`
/// granted `ferrumclusters/status` and no source file in the workspace names
/// `FerrumCluster` at all. Two repairs were available — give `.degraded` its
/// first writer, or delete the grant — and the grant was deleted: the writer is
/// not one function but an API-server client this workspace has never had (see
/// «Ничто и никогда не обращалось к API server» in the document), while a grant
/// nobody exercises is a permission with no purpose, which this project's threat
/// model calls a lateral-movement target.
#[test]
fn every_shipped_subject_has_one_reachable_channel_that_carries_a_cause() {
    let doc = document();
    let root = repo_root();
    let subjects = shipped_subjects(&root);
    assert!(
        subjects.len() >= 3,
        "found {} image: references under deploy/; this gate would compare the inventory \
         against nothing",
        subjects.len()
    );

    // 1. One row per shipped binary, and no others.
    let mut listed: BTreeMap<String, usize> = BTreeMap::new();
    for row in rows(&doc) {
        if row.section != DOES_HEADING {
            continue;
        }
        let Some(first) = row.cells.first() else {
            continue;
        };
        let subject = first.trim().trim_matches('`').to_string();
        if subjects.contains_key(&subject) {
            *listed.entry(subject).or_insert(0) += 1;
        }
    }
    let missing: Vec<&String> = subjects
        .keys()
        .filter(|s| !listed.contains_key(*s))
        .collect();
    assert!(
        missing.is_empty(),
        "{INVENTORY_HEADING} names no channel for {missing:?}. A binary with no row is a \
         subject nobody can learn is broken, and the degradation table above cannot see it: \
         every scan behind that table runs over ferrum_agent::Agent, which these processes \
         are not."
    );
    let twice: Vec<&String> = listed
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(s, _)| s)
        .collect();
    assert!(
        twice.is_empty(),
        "{twice:?} carry more than one row in «Делает» keyed on the subject name. One \
         channel per subject: a second one is a channel an operator does not read."
    );

    // 2. Reachable: the inventory row cites something. The forward gate is
    //    what resolves the citation; this is what refuses a dash.
    let mut in_inventory = false;
    let mut checked = 0usize;
    for line in doc.lines() {
        if line.starts_with("###") {
            in_inventory = line.trim_end() == INVENTORY_HEADING;
            continue;
        }
        if !in_inventory || !is_table_line(line) {
            continue;
        }
        let cells = cells_of(line);
        if is_separator_row(&cells) || cells.len() < 4 {
            continue;
        }
        let subject = cells[0].trim().trim_matches('`').to_string();
        if !subjects.contains_key(&subject) {
            continue;
        }
        let citations = parse_evidence(&cells[cells.len() - 1])
            .unwrap_or_else(|why| panic!("{subject}: {why}"));
        assert!(
            !citations.is_empty(),
            "{subject} names a channel and cites nothing that reaches it. A channel nothing \
             has ever produced is a channel an operator will read for the first time during \
             an incident."
        );
        checked += 1;
    }
    assert_eq!(
        checked,
        subjects.len(),
        "the inventory table under {INVENTORY_HEADING} was read for {checked} of the \
         {} shipped subjects; either the heading moved or the table shape changed, and \
         this half asserted nothing",
        subjects.len()
    );

    // 3. A cause rather than a constant: no granted status subresource that
    //    nothing writes.
    let rbac = fs::read_to_string(root.join("deploy/controller/rbac.yaml")).expect("rbac.yaml");
    let mut sources = Vec::new();
    rs_files(&root.join("crates/ferrum-controller/src"), &mut sources);
    let written: String = sources
        .iter()
        .map(|p| fs::read_to_string(p).expect("controller source"))
        .collect();
    let mut dead = Vec::new();
    for (resource, status_type) in STATUS_TYPES {
        let granted = rbac
            .lines()
            .any(|l| l.trim().trim_start_matches("- ").trim_matches('"') == resource);
        if granted && !written.contains(status_type) {
            dead.push(format!("  {resource} (nothing names {status_type})"));
        }
    }
    assert!(
        dead.is_empty(),
        "deploy/controller/rbac.yaml grants write on these status subresources and no source \
         file of ferrum-controller writes one:\n{}\nA status nobody writes reports the zero \
         value of its own struct forever — `degraded: false` on a cluster that is down — and \
         the grant that carries it is a permission with no purpose, which the threat model \
         calls a lateral-movement target. Either write it, or delete the grant.",
        dead.join("\n")
    );
    // The positive control. Every check above is an absence, and an absence is
    // also what a renamed resource list, a reworked rbac.yaml or a typo in
    // STATUS_TYPES produces.
    assert!(
        rbac.contains("policyexceptions/status") && written.contains("PolicyExceptionStatus"),
        "the pair this scan is calibrated on is gone: it can no longer tell a granted \
         status with a writer from one without, so the loop above proved nothing"
    );
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

/// Every `pub const NAME: &str` in `ferrum-agent`'s sources, whatever file it
/// is in.
///
/// The scan this replaces read `lib.rs` alone, so a reason declared in
/// `respond.rs`, `main.rs` or `status.rs` was invisible to it and the floor
/// below still passed.
fn str_constants(src: &Path) -> BTreeMap<String, PathBuf> {
    let mut files = Vec::new();
    rs_files(src, &mut files);
    let mut out = BTreeMap::new();
    for file in files {
        let body = fs::read_to_string(&file).expect("agent source");
        for line in body.lines() {
            let Some(rest) = line.trim_start().strip_prefix("pub const ") else {
                continue;
            };
            let Some((name, ty)) = rest.split_once(':') else {
                continue;
            };
            if !ty.trim_start().starts_with("&str") {
                continue;
            }
            let name = name.trim();
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
                out.insert(name.to_string(), file.clone());
            }
        }
    }
    out
}

/// The body of `degraded_reasons_at`, by rustfmt's indentation.
///
/// Brace counting is not used on purpose: the body contains `format!` strings
/// with braces in them, so a counter would have to lex Rust to be right. A
/// method in a formatted file closes on a line that is exactly four spaces and
/// a brace, and the caller asserts the slice is not trivially short.
fn degraded_reasons_body(lib: &str) -> &str {
    let start = lib
        .find("    pub fn degraded_reasons_at(")
        .expect("ferrum-agent no longer has `degraded_reasons_at`: this gate scans nothing");
    let tail = &lib[start..];
    let end = tail
        .find("\n    }\n")
        .expect("degraded_reasons_at does not close at method indentation");
    &tail[..end]
}

/// Every degradation reason the agent can raise is named in the document.
/// A reason nobody wrote down is a reason nobody reads, which is how twenty-two
/// counters spent eight cycles without one.
///
/// Three scans, because `DEG_*` is a convention and not a mechanism. The
/// convention is scanned for its own sake — a reason declared and not yet
/// wired is still a reason someone will wire — and then the body of
/// `degraded_reasons_at` is read for the constants it actually pushes,
/// whatever they are called. That second scan is what sees the respond-scoped
/// reasons (`SELF_TGID_UNPUBLISHED`, `TARGET_CHECK_UNPROVABLE`,
/// `TARGET_NEVER_PROVEN`), which are deliberately outside the `DEG_*` family
/// because under observe the guard they speak for is never reached — a naming
/// decision that is defensible and that a name-shaped gate cannot follow.
///
/// The third scan reads the arguments of `mark_terminal_fault`. A terminal
/// fault reaches `degraded_reasons_at` as the *text it already holds* — the
/// arm is `if let Some(fault) = self.terminal_fault()`, so the constant naming
/// the fault is nowhere in that body and is not in the `DEG_*` family either.
/// Four reasons the agent latches this way went undocumented behind both of
/// the scans above, which is the same one-directional rot the header of this
/// file describes, one level in: a gate that reads only where reasons are
/// *pushed* cannot see the reasons that are pushed as data.
#[test]
fn every_degraded_reason_the_agent_can_raise_is_named_in_the_document() {
    let doc = document();
    let src = repo_root().join("crates/ferrum-agent/src");
    let declared = str_constants(&src);
    let lib = fs::read_to_string(src.join("lib.rs")).expect("ferrum-agent/src/lib.rs");

    // The convention, across the whole crate rather than one file of it.
    let mut constants: Vec<String> = declared
        .keys()
        .filter(|name| name.starts_with("DEG_"))
        .cloned()
        .collect();
    assert!(
        constants.len() >= 16,
        "found {} DEG_ constants in ferrum-agent; the scan is broken, not the agent",
        constants.len()
    );

    // The mechanism: what the function actually pushes.
    let body = degraded_reasons_body(&lib);
    assert!(
        body.lines().count() > 50,
        "the body of `degraded_reasons_at` came back as {} lines; the slice is wrong and this \
         scan would find nothing",
        body.lines().count()
    );
    let mut pushed: Vec<&str> = body
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| declared.contains_key(*token))
        .collect();
    pushed.sort_unstable();
    pushed.dedup();
    assert!(
        pushed.len() >= 19,
        "`degraded_reasons_at` names {} reason constants; it named nineteen when this floor was \
         written, so the scan is broken rather than the agent: {pushed:?}",
        pushed.len()
    );
    // The mechanism, second half: reasons that reach the list as the text a
    // terminal fault already holds, so they appear in no arm and carry no
    // `DEG_` prefix.
    let mut latched = terminal_fault_constants(&src, &declared);
    latched.sort_unstable();
    latched.dedup();
    assert!(
        latched.len() >= 4,
        "found {} constants passed to `mark_terminal_fault`; it found four when this floor was \
         written, so the scan is broken rather than the agent: {latched:?}",
        latched.len()
    );

    constants.extend(pushed.iter().map(|s| (*s).to_string()));
    constants.extend(latched);
    constants.sort();
    constants.dedup();

    let unnamed: Vec<String> = constants
        .iter()
        .filter(|c| !doc.contains(c.as_str()))
        .map(|c| {
            let file = declared
                .get(c)
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            format!("{c} ({file})")
        })
        .collect();
    assert!(
        unnamed.is_empty(),
        "degradation reasons the agent can raise and the boundary document does not name: \
         {unnamed:#?}"
    );
}

/// Constants handed to `mark_terminal_fault` anywhere in the crate.
///
/// Read from the call site rather than from the declaration: a `&str` constant
/// beside the reasons proves nothing about whether anything latches it, and the
/// whole point of this scan is what the agent can actually raise. The window is
/// the call and the two lines after it, which is what rustfmt gives a
/// `format!("{CONST} (...)")` argument that does not fit on one line.
fn terminal_fault_constants(src: &Path, declared: &BTreeMap<String, PathBuf>) -> Vec<String> {
    let mut out = Vec::new();
    let mut files = Vec::new();
    rs_files(src, &mut files);
    for file in files {
        let text = fs::read_to_string(&file).expect("read a source file");
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in lines.iter().enumerate() {
            if !line.contains("mark_terminal_fault(") {
                continue;
            }
            let window = lines[n..(n + 3).min(lines.len())].join("\n");
            out.extend(
                window
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .filter(|token| declared.contains_key(*token))
                    .map(str::to_string),
            );
        }
    }
    out
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

    /// A citation resolves against a definition, not against a mention of one.
    ///
    /// Each of these `body` values contains the exact bytes `fn a_test(`, and
    /// the substring check this replaced accepted every one of them — so a row
    /// stayed green on the doc comment left behind by the test it cited.
    #[test]
    fn a_mention_of_a_test_is_not_a_definition_of_one() {
        for body in [
            "/// See `fn a_test(` for the argument.\n",
            "// fn a_test() was removed in cycle 7\n",
            "    let needle = \"fn a_test(\";\n",
            "//! The claim rests on fn a_test(...).\n",
        ] {
            assert!(
                !defines_fn(body, "a_test"),
                "{body:?} resolved a citation without defining anything"
            );
        }
        for body in [
            "fn a_test() {}\n",
            "    fn a_test() {}\n",
            "    pub fn a_test() {}\n",
            "    pub(crate) fn a_test() {}\n",
            "    async fn a_test() {}\n",
            "    unsafe fn a_test() {}\n",
            "    pub const fn a_test() {}\n",
            "    pub async unsafe fn a_test() {}\n",
        ] {
            assert!(defines_fn(body, "a_test"), "{body:?} is a definition");
        }
    }

    /// The section's own way out: every row could read `| — | — |` and both
    /// gates would stay green under a heading that means "executed".
    #[test]
    fn only_a_named_subject_may_cite_nothing() {
        assert!(NOT_EXECUTED_SUBJECTS.contains(&"exception without TTL -> API reject"));
        assert_eq!(
            NOT_EXECUTED_SUBJECTS.len(),
            1,
            "adding a subject that may claim nothing is a deliberate act; state the reason \
             beside the constant and update this count"
        );
    }

    /// The reader under the reverse direction, on a file whose answer is
    /// known. "No test is uncited" is also what a `tests_in` that has stopped
    /// finding tests reports, and that failure is invisible: the gate goes
    /// green having scanned nothing.
    #[test]
    fn a_test_is_found_under_its_attributes_and_a_plain_fn_is_not() {
        let body = "#[test]\nfn plain() {}\n\
                    \x20   #[test]\n    #[ignore = \"needs a kernel\"]\n    fn indented_and_ignored() {}\n\
                    #[test]\n#[cfg_attr(miri, ignore)]\npub fn attributed() {}\n\
                    fn not_a_test() {}\n\
                    // #[test] in a comment\n";
        assert_eq!(
            tests_in(body),
            vec!["plain", "indented_and_ignored", "attributed"]
        );
        assert!(
            !tests_in(body).contains(&"not_a_test".to_string()),
            "a bare fn is not a test, and counting one would let this gate demand a row \
             for every helper in the file"
        );
        // `#[ignore]` does not exempt a test from needing a row. A gate whose
        // claim is written down and never runs is worse than one that is
        // absent: the document says the tree proves something and nothing does.
        assert!(tests_in("#[test]\n#[ignore]\nfn skipped() {}\n").contains(&"skipped".to_string()));
    }

    /// Adding an exemption is a deliberate act, like `NOT_EXECUTED_SUBJECTS`.
    ///
    /// The list landed empty and must not be filled to make the gate pass:
    /// seeding it with everything currently uncited is the "green having run
    /// almost nothing" shape, and this count is what makes growing it show up
    /// in a diff as its own decision.
    #[test]
    fn an_exemption_from_citation_is_named_one_at_a_time() {
        assert!(
            UNCITED_TESTS.len() <= 3,
            "{} tests are exempt from needing a row. The exemption list is for the rare \
             test that is not a claim about the product; a list this long means the \
             document stopped tracking the tree and this gate stopped noticing.",
            UNCITED_TESTS.len()
        );
        for (name, why) in UNCITED_TESTS {
            assert!(
                why.len() > 30,
                "{name} is exempt with no reason worth reading: {why:?}"
            );
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
