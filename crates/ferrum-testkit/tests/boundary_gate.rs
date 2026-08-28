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
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::{BTreeMap, BTreeSet};
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
const CITED_TEST_DIRS: [&str; 3] = [
    "crates/ferrum-testkit/tests",
    "crates/ferrum-agent/tests",
    "crates/ferrum-admission/tests",
];

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

/// Whether a test is answered: cited by a row that names the file it lives in,
/// or exempt with a reason.
///
/// A function rather than two conditions inline, because it is the only part of
/// the rule that can be exercised on inputs whose answer is known. The
/// exemption arm of it runs zero times against the tree — `UNCITED_TESTS` is
/// empty and is supposed to stay that way — so a gate that only ran against the
/// tree would never execute it, and the document's claim that the empty list is
/// *held* by something would be a claim about code nothing runs.
fn is_answered(test: &str, cited: &[String], exempt: &[(&str, &str)]) -> bool {
    cited.iter().any(|name| name == test) || exempt.iter().any(|(name, _)| *name == test)
}

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
                if is_answered(&test, names, &UNCITED_TESTS) {
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

/// A `<resource>/status` a subject's RBAC may grant, the Kind whose
/// `ApiResource` a writer of it needs, and the `ferrum-api` status type it
/// carries.
///
/// Both policy kinds share `PolicyStatus`, which is why this is a table and
/// not a name transformation.
///
/// The middle column is the one that decides. Naming the status *type* was
/// what this table held for one cycle, and a type name in a source file is not
/// a write: `runtimeprofiles/status` survived a cull that deleted three grants
/// of exactly its shape because `crates/ferrum-controller/src/lib.rs` contains
/// `pub fn runtime_profile_status(…) -> RuntimeProfileStatus`, whose only
/// consumer is a field two unit tests read. There is no `ApiResource` for
/// `runtimeprofiles`, no watch and no PATCH. A `pub fn` returning the type, a
/// `use` line or a doc comment mentioning it satisfied the rule forever.
const STATUS_TYPES: [(&str, &str, &str); 7] = [
    (
        "clustersecuritypolicies/status",
        "ClusterSecurityPolicy",
        "PolicyStatus",
    ),
    ("securitypolicies/status", "SecurityPolicy", "PolicyStatus"),
    (
        "policyexceptions/status",
        "PolicyException",
        "PolicyExceptionStatus",
    ),
    (
        "policylibraries/status",
        "PolicyLibrary",
        "PolicyLibraryStatus",
    ),
    (
        "runtimeprofiles/status",
        "RuntimeProfile",
        "RuntimeProfileStatus",
    ),
    (
        "ferrumclusters/status",
        "FerrumCluster",
        "FerrumClusterStatus",
    ),
    (
        "compliancesnapshots/status",
        "ComplianceSnapshot",
        "ComplianceSnapshotStatus",
    ),
];

/// The API group every kind in `STATUS_TYPES` belongs to. A wildcard resource
/// grant is only a grant on those when the rule names this group, or every one.
const FERRUM_GROUP: &str = "ferrum.io";

/// RBAC verbs that write. `get`, `list` and `watch` on a status subresource are
/// a read grant and not the finding here.
const WRITE_VERBS: [&str; 5] = ["create", "update", "patch", "delete", "*"];

/// How a subject's sources say it writes `<Kind>/status`, and it is two things
/// at once, neither sufficient alone.
///
/// A status PATCH in this workspace is `api.patch_status(...)` on an
/// `Api<DynamicObject>` built from an `ApiResource`, and an `ApiResource` is
/// built from a `GroupVersionKind::gvk(GROUP, VERSION, "<Kind>")`. So the Kind
/// must appear as the literal of a `gvk` call — the handle the write needs,
/// which a `pub fn` returning a status struct, a `use` line and a doc comment
/// cannot produce — and the crate must contain a status-patching call at all.
///
/// What this cannot do, stated rather than left to be read into it: it does not
/// follow the handle to the call. A `gvk` literal for a Kind the crate never
/// patches would satisfy it. That is a far narrower hole than the one it
/// replaces — the literal constructs a cluster API handle, it is not a name in
/// a signature — and closing it needs dataflow this file has no business
/// carrying.
fn writes_status(sources: &str, kind: &str) -> bool {
    let quoted = format!("\"{kind}\"");
    let has_handle = sources
        .match_indices("GroupVersionKind::gvk(")
        .any(|(at, _)| {
            let rest = &sources[at..];
            // The `;` that ends the statement the call is part of, whatever
            // rustfmt did to the line breaks inside the argument list.
            let end = rest.find(';').unwrap_or(rest.len());
            rest[..end].contains(&quoted)
        });
    has_handle && sources.contains("patch_status")
}

/// `text` with its comments removed, so a sentence describing a write is not
/// one.
///
/// `//` inside a string literal is left alone in the one shape this tree has, a
/// URL scheme, by not treating `://` as a comment opener. That is the whole of
/// it: a `//` inside any other string literal would over-strip, which fails
/// this scan closed — toward reporting a missing writer — and never open.
fn strip_rust_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let chars: Vec<char> = line.chars().collect();
        let cut = (1..chars.len())
            .find(|i| chars[*i] == '/' && chars[i - 1] == '/' && (*i < 2 || chars[i - 2] != ':'));
        match cut {
            Some(i) => out.extend(chars[..i - 1].iter()),
            None => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

/// A `(Cluster)RoleBinding`, reduced to what the census needs: the role it
/// points at and the ServiceAccounts it points at it from.
struct Binding {
    role_kind: String,
    role_name: String,
    accounts: Vec<String>,
}

fn scalar(node: &Value, key: &str) -> String {
    node.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn sequence<'a>(node: &'a Value, key: &str) -> &'a [Value] {
    node.get(key)
        .and_then(Value::as_sequence)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// Every value of `key` in one document, however deep the pod template is
/// nested.
fn collect_field(node: &Value, key: &str, out: &mut BTreeSet<String>) {
    match node {
        Value::Mapping(map) => {
            if let Some(Value::String(value)) = map.get(Value::from(key)) {
                out.insert(value.clone());
            }
            for (_, value) in map.iter() {
                collect_field(value, key, out);
            }
        }
        Value::Sequence(items) => {
            for item in items {
                collect_field(item, key, out);
            }
        }
        _ => {}
    }
}

/// Every YAML document under `deploy/`, one entry per `---`.
fn documents(root: &Path) -> Vec<Value> {
    let mut files = Vec::new();
    yaml_files(&root.join("deploy"), &mut files);
    files.sort();
    let mut out = Vec::new();
    for file in files {
        let body = fs::read_to_string(&file).expect("manifest");
        for doc in serde_yaml::Deserializer::from_str(&body) {
            if let Ok(value) = Value::deserialize(doc) {
                out.push(value);
            }
        }
    }
    out
}

/// Every crate a manifest under `deploy/` asks the cluster to run, by the
/// `image:` lines that name them, mapped to the ServiceAccounts the pod specs
/// carrying those images run as.
///
/// The accounts are what turns a name into a subject: RBAC binds a
/// ServiceAccount and not an image, so without them the grant census below
/// cannot ask what any subject but the one whose file it hardcoded may write.
fn shipped_subjects(root: &Path) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for doc in documents(root) {
        let mut images = BTreeSet::new();
        let mut accounts = BTreeSet::new();
        collect_field(&doc, "image", &mut images);
        collect_field(&doc, "serviceAccountName", &mut accounts);
        for reference in images {
            let reference = reference.trim().trim_matches('"');
            let repo = match reference.rfind(':') {
                Some(colon) if colon > reference.rfind('/').unwrap_or(0) => &reference[..colon],
                _ => reference,
            };
            if let Some(name) = repo.rsplit('/').next() {
                out.entry(name.to_string())
                    .or_default()
                    .extend(accounts.iter().cloned());
            }
        }
    }
    out
}

/// Every `(Cluster)Role` under `deploy/`, by kind and name, and every
/// `(Cluster)RoleBinding` that points at one.
#[allow(clippy::type_complexity)]
fn rbac(root: &Path) -> (BTreeMap<(String, String), Vec<Value>>, Vec<Binding>) {
    let mut roles: BTreeMap<(String, String), Vec<Value>> = BTreeMap::new();
    let mut bindings = Vec::new();
    for doc in documents(root) {
        let kind = scalar(&doc, "kind");
        let name = doc
            .get("metadata")
            .map(|m| scalar(m, "name"))
            .unwrap_or_default();
        match kind.as_str() {
            "Role" | "ClusterRole" => {
                roles.insert((kind, name), sequence(&doc, "rules").to_vec());
            }
            "RoleBinding" | "ClusterRoleBinding" => {
                let role = doc.get("roleRef");
                bindings.push(Binding {
                    role_kind: role.map(|r| scalar(r, "kind")).unwrap_or_default(),
                    role_name: role.map(|r| scalar(r, "name")).unwrap_or_default(),
                    accounts: sequence(&doc, "subjects")
                        .iter()
                        .filter(|s| scalar(s, "kind") == "ServiceAccount")
                        .map(|s| scalar(s, "name"))
                        .collect(),
                });
            }
            _ => {}
        }
    }
    (roles, bindings)
}

/// Every `<resource>/status` a subject may write, followed from its pod spec's
/// ServiceAccounts through the bindings to the rules, and how many rules were
/// reached at all.
///
/// The count is not decoration. A graph that resolves nothing produces the same
/// empty grant set as a subject that is granted nothing, and telling those two
/// apart is the whole difference between this census and the hardcoded read of
/// one file it replaces.
fn granted_status_writes(
    accounts: &BTreeSet<String>,
    roles: &BTreeMap<(String, String), Vec<Value>>,
    bindings: &[Binding],
) -> (BTreeSet<String>, usize) {
    let mut granted = BTreeSet::new();
    let mut reached = 0usize;
    for binding in bindings {
        if !binding.accounts.iter().any(|a| accounts.contains(a)) {
            continue;
        }
        let key = (binding.role_kind.clone(), binding.role_name.clone());
        let Some(rules) = roles.get(&key) else {
            continue;
        };
        for rule in rules {
            reached += 1;
            let writes = sequence(rule, "verbs")
                .iter()
                .filter_map(Value::as_str)
                .any(|verb| WRITE_VERBS.contains(&verb));
            if !writes {
                continue;
            }
            // A wildcard is the strongest form of the grant this census
            // exists to refuse, and the literal `/status` match was blind to
            // it: `resources: ["*"]` with a write verb grants every status
            // subresource in the groups the rule names and reads as granting
            // none. Expanded against STATUS_TYPES, which is entirely
            // `ferrum.io`, so a wildcard is only expanded when the rule names
            // that group (or every group). A core-group wildcard grants
            // `pods/status` too; that is a different finding, and FD002 in
            // `lint-deploy` is what refuses wildcards outright.
            let ferrum_group = sequence(rule, "apiGroups")
                .iter()
                .filter_map(Value::as_str)
                .any(|group| group == "*" || group == FERRUM_GROUP);
            for resource in sequence(rule, "resources").iter().filter_map(Value::as_str) {
                let wildcard = match resource {
                    "*" => Some(None),
                    other => other.strip_suffix("/*").map(Some),
                };
                match wildcard {
                    Some(prefix) if ferrum_group => {
                        for (status, _, _) in STATUS_TYPES {
                            let names = prefix
                                .is_none_or(|kind| status.strip_suffix("/status") == Some(kind));
                            if names {
                                granted.insert(status.to_string());
                            }
                        }
                    }
                    Some(_) => {}
                    None => {
                        if resource.contains("/status") {
                            granted.insert(resource.to_string());
                        }
                    }
                }
            }
        }
    }
    (granted, reached)
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
/// The third assertion is a census over the same three subjects as the first
/// two, and for one cycle it was not: it read `deploy/controller/rbac.yaml` by
/// name and a list of `ferrum.io` resources, so `ferrum-agent` and
/// `ferrum-admission` passed it because nothing in the loop could name them —
/// «green because there is nothing to check», two subjects out of three, inside
/// the test whose own docstring is an argument against that. It now follows
/// each subject's pod spec to its ServiceAccounts, those to the bindings, and
/// the bindings to the rules, so a status grant added to the agent or the
/// webhook is seen by the same rule that sees the controller's.
///
/// `FerrumClusterStatus.degraded` was exactly that: `deploy/controller/rbac.yaml`
/// granted `ferrumclusters/status` and no source file in the workspace names
/// `FerrumCluster` at all. Two repairs were available — give `.degraded` its
/// first writer, or delete the grant — and the grant was deleted: the writer is
/// not one function but an API-server client this workspace has never had (see
/// «Ничто и никогда не обращалось к API server» in the document), while a grant
/// nobody exercises is a permission with no purpose, which this project's threat
/// model calls a lateral-movement target.
///
/// `runtimeprofiles/status` was the same finding and survived that cull,
/// because the rule asked whether the *status type* was named anywhere in the
/// crate and `pub fn runtime_profile_status(…) -> RuntimeProfileStatus` names
/// it. Its result is a struct field two unit tests read; there is no
/// `ApiResource` for `runtimeprofiles`, no watch and no PATCH. The rule now
/// asks for the handle a write needs — see `writes_status` — and the grant is
/// deleted, the same repair for the same reason.
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

    // 3. A cause rather than a constant: no subject holds a write grant on a
    //    `<kind>/status` that nothing in it writes.
    //
    //    Over every shipped subject, not over one hardcoded file. The loop this
    //    replaces read `deploy/controller/rbac.yaml` and one list of `ferrum.io`
    //    resources, so `ferrum-agent` and `ferrum-admission` passed it because
    //    nothing in it could name them — assertion 3 was vacuous for two
    //    subjects out of three, inside the test whose docstring is an argument
    //    against exactly that.
    let (roles, bindings) = rbac(&root);
    let mut dead = Vec::new();
    let mut unknown = Vec::new();
    let mut resolved = 0usize;
    for (subject, accounts) in &subjects {
        let (granted, reached) = granted_status_writes(accounts, &roles, &bindings);
        resolved += reached;
        assert!(
            !accounts.is_empty(),
            "no pod spec under deploy/ that runs {subject} names a serviceAccountName, so no \
             binding can be followed to it and this census asked nothing about it"
        );
        let sources_dir = root.join("crates").join(subject).join("src");
        assert!(
            sources_dir.is_dir(),
            "{} does not exist, so what {subject} writes cannot be read",
            sources_dir.display()
        );
        let mut files = Vec::new();
        rs_files(&sources_dir, &mut files);
        let sources: String = files
            .iter()
            .map(|path| strip_rust_comments(&fs::read_to_string(path).expect("source file")))
            .collect();
        for resource in &granted {
            let Some((_, kind, status_type)) = STATUS_TYPES.iter().find(|(r, _, _)| r == resource)
            else {
                unknown.push(format!("  {subject}: {resource}"));
                continue;
            };
            if !writes_status(&sources, kind) {
                dead.push(format!(
                    "  {subject}: {resource} (no GroupVersionKind::gvk(…, \"{kind}\") and \
                     patch_status in crates/{subject}/src; carrying {status_type})"
                ));
            }
        }
    }
    assert!(
        unknown.is_empty(),
        "these subjects are granted write on a status subresource STATUS_TYPES does not \
         name:\n{}\nThe table is what this census decides against; a grant outside it is \
         checked by nothing.",
        unknown.join("\n")
    );
    assert!(
        dead.is_empty(),
        "these subjects hold write on a status subresource and no source file of theirs \
         writes one:\n{}\nA status nobody writes reports the zero value of its own struct \
         forever — `degraded: false` on a cluster that is down — and the grant that carries \
         it is a permission with no purpose, which the threat model calls a lateral-movement \
         target. Either write it, or delete the grant.\n\nNaming the status type is not \
         writing it: `runtimeprofiles/status` survived the cull that took three grants of \
         its exact shape because a `pub fn runtime_profile_status(…) -> RuntimeProfileStatus` \
         existed whose only consumer is a struct field two unit tests read.",
        dead.join("\n")
    );

    // The positive controls. Every check above is an absence, and an absence is
    // also what an unresolved RBAC graph, a renamed resource list, a reworked
    // rbac.yaml or a typo in STATUS_TYPES produces.
    assert!(
        resolved > 0,
        "no binding under deploy/ resolved to a role for any shipped subject, so the grant \
         census ran over an empty rule set for all {} of them and proved nothing",
        subjects.len()
    );
    let controller = subjects
        .get("ferrum-controller")
        .expect("ferrum-controller is a shipped subject");
    let (granted, _) = granted_status_writes(controller, &roles, &bindings);
    assert!(
        granted.contains("policyexceptions/status"),
        "the grant this census is calibrated on is gone from the graph: it can no longer \
         follow a ServiceAccount through a binding to a rule, so every subject above came \
         back with nothing granted and the loop proved nothing. Found: {granted:?}"
    );
    let mut controller_sources = Vec::new();
    rs_files(
        &root.join("crates/ferrum-controller/src"),
        &mut controller_sources,
    );
    let controller_body: String = controller_sources
        .iter()
        .map(|path| strip_rust_comments(&fs::read_to_string(path).expect("source file")))
        .collect();
    assert!(
        writes_status(&controller_body, "PolicyException"),
        "the writer this census is calibrated on is gone: it can no longer tell a granted \
         status with a writer from one without"
    );
    assert!(
        !writes_status(&controller_body, "RuntimeProfile"),
        "the controller now names RuntimeProfile in a gvk call. If it genuinely watches and \
         patches RuntimeProfile now, restore the runtimeprofiles/status grant in \
         deploy/controller/rbac.yaml in the same change and delete this control; if it does \
         not, this scan has stopped telling a handle from a mention and the negative half of \
         it proves nothing"
    );
}

/// The reader under assertion 3, on the grant shape that assertion was blind
/// to.
///
/// `resources: ["*"]` with write verbs grants every status subresource in the
/// group, and the census matched the literal `/status`, so the strongest
/// possible version of the grant it exists to refuse was the one form it could
/// not see. A rule that decides by substring where it claims to decide by
/// meaning: the same defect the two rules above were fixed for.
///
/// Not a gate over the tree — `deploy/` carries no wildcard and FD002 refuses
/// one — so this is the reader on inputs whose answer is known, which is what
/// keeps assertion 3 honest when a wildcard does arrive.
#[test]
fn a_wildcard_resource_grant_is_a_status_grant() {
    let rules = |groups: &str,
                 resources: &str,
                 verbs: &str|
     -> BTreeMap<(String, String), Vec<Value>> {
        let body = format!(
            "rules:\n  - apiGroups: [{groups}]\n    resources: [{resources}]\n    verbs: [{verbs}]\n"
        );
        let doc: Value = serde_yaml::from_str(&body).expect("role");
        let mut roles = BTreeMap::new();
        roles.insert(
            ("ClusterRole".to_string(), "test".to_string()),
            sequence(&doc, "rules").to_vec(),
        );
        roles
    };
    let bindings = vec![Binding {
        role_kind: "ClusterRole".to_string(),
        role_name: "test".to_string(),
        accounts: vec!["ferrum-test".to_string()],
    }];
    let accounts: BTreeSet<String> = ["ferrum-test".to_string()].into_iter().collect();

    let (granted, reached) = granted_status_writes(
        &accounts,
        &rules("\"ferrum.io\"", "\"*\"", "\"get\", \"patch\""),
        &bindings,
    );
    assert_eq!(reached, 1, "the synthetic binding resolved to no rule");
    assert!(
        granted.contains("policyexceptions/status"),
        "a wildcard resource with a write verb grants every status subresource in the group \
         and must be read as granting them: {granted:?}"
    );
    assert_eq!(
        granted.len(),
        STATUS_TYPES.len(),
        "a wildcard grants every kind this census knows, not some of them: {granted:?}"
    );

    // The halves that keep the expansion from becoming "a wildcard anywhere is
    // every grant": a read-only wildcard is not a write grant, and a wildcard
    // in another group does not reach ferrum.io kinds.
    let (read_only, _) = granted_status_writes(
        &accounts,
        &rules("\"ferrum.io\"", "\"*\"", "\"get\", \"list\", \"watch\""),
        &bindings,
    );
    assert!(
        read_only.is_empty(),
        "a read grant on a status subresource is not the finding here: {read_only:?}"
    );
    let (other_group, _) =
        granted_status_writes(&accounts, &rules("\"\"", "\"*\"", "\"patch\""), &bindings);
    assert!(
        other_group.is_empty(),
        "a core-group wildcard grants no ferrum.io status: {other_group:?}"
    );

    // The subresource wildcard is the same grant written one level in.
    let (subresource, _) = granted_status_writes(
        &accounts,
        &rules("\"ferrum.io\"", "\"policyexceptions/*\"", "\"patch\""),
        &bindings,
    );
    assert_eq!(
        subresource,
        ["policyexceptions/status".to_string()]
            .into_iter()
            .collect(),
        "`<resource>/*` grants that resource's status and only that one"
    );
}

/// The controller's channel is stderr, and the exit code is reachable only
/// before the watch starts.
///
/// The inventory row for `ferrum-controller` said «код выхода и строка
/// `error: <причина>` в stderr» and cited an argv test, and that is true of
/// exactly one class of fault: the ones `run()` can return before `run_watch`
/// is entered. After that the process is three `tokio::select!`ed watch loops.
/// `kube::runtime::watcher` retries internally and does not terminate, so every
/// fault an operator actually needs a channel for — a reconcile that fails, a
/// status PATCH that 403s, which is precisely what a botched RBAC edit
/// produces, a watch error — is one `eprintln!` and the loop continues. The
/// exit code is never reached and the line does not carry the `error:` prefix
/// the row named. So the row's second assertion, «the channel is reachable»,
/// was satisfied by the one class of fault an operator never needs a channel
/// for.
///
/// This is what makes the rewritten row true rather than the claim true: the
/// channel *is* stderr, both halves of it, and the difference between them is
/// whether the process is still running afterwards. The repair the row cannot
/// make is in `crates/ferrum-controller/src`, which this slice does not own —
/// a 403 on a status PATCH is a log line and nothing else: no exit, no
/// counter, no status, nothing an operator polls.
#[test]
fn the_controllers_channel_is_stderr_and_a_failed_event_never_reaches_the_exit_code() {
    let root = repo_root();
    let main = strip_rust_comments(
        &fs::read_to_string(root.join("crates/ferrum-controller/src/main.rs")).expect("main.rs"),
    );
    let watch = strip_rust_comments(
        &fs::read_to_string(root.join("crates/ferrum-controller/src/watch.rs")).expect("watch.rs"),
    );

    // The startup half, which is the one the row used to claim was the whole
    // channel: a returned error is printed with the `error:` prefix and the
    // process leaves with 1.
    assert!(
        main.contains("eprintln!(\"error: {err}\")") && main.contains("process::exit(1)"),
        "crates/ferrum-controller/src/main.rs no longer prints `error: <cause>` and exits 1, \
         so the startup half of the inventory row names a channel that is gone"
    );

    // The post-startup half. Each watch loop handles a per-event failure by
    // printing it and going round again, so the count is one per arm and the
    // prefix is the process name rather than `error:`.
    let loops = watch
        .matches("while let Some(event) = stream.next().await")
        .count();
    assert!(
        loops >= 3,
        "found {loops} event loops in watch.rs; there are three, so this scan is reading \
         something else and what follows proves nothing"
    );
    let printed = watch.matches("eprintln!(\"ferrum-controller").count();
    assert!(
        printed >= loops * 2,
        "watch.rs has {loops} event loops and only {printed} `ferrum-controller:` lines. Each \
         loop reports two kinds of failure — the event's own and the watch's — and a loop \
         that reports neither swallows it entirely"
    );
    assert!(
        !watch.contains("eprintln!(\"error:"),
        "watch.rs prints an `error:` line. That prefix belongs to `main`, which exits after \
         it; a line with the same prefix from a loop that continues tells an operator the \
         process is gone when it is not, and the inventory row would then be naming two \
         channels under one name"
    );
    for exit in ["process::exit(", "std::process::exit(", "exit(1)"] {
        assert!(
            !watch.contains(exit),
            "watch.rs calls {exit}. The inventory row says the exit code is the startup \
             channel; if a failed event can now reach it, the row is understating what an \
             operator sees and the two halves are no longer distinguishable"
        );
    }
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

    /// Adding an exemption is a deliberate act, like `NOT_EXECUTED_SUBJECTS`,
    /// and the exemption actually exempts.
    ///
    /// This asserted nothing for a cycle. `UNCITED_TESTS` is `[(&str, &str); 0]`,
    /// so `0 <= 3` is a compile-time truth and the `for` body never ran — while
    /// the document carried a row saying the empty list is *held by a gate*.
    /// Nothing was held: had the list been filled with thirty names and no
    /// reasons, this test would have passed exactly as it did.
    ///
    /// So the rule is exercised on inputs whose answer is known, and the
    /// constant is checked separately. The list landed empty and must not be
    /// filled to make the citation gate pass: seeding it with everything
    /// currently uncited is the "green having run almost nothing" shape, and
    /// the count below is what makes growing it show up in a diff as its own
    /// decision.
    #[test]
    fn an_exemption_from_citation_is_named_one_at_a_time() {
        // The rule, on the cases that matter and with the exemption list this
        // tree does not have.
        let cited = vec!["a_cited_gate".to_string()];
        assert!(is_answered("a_cited_gate", &cited, &[]));
        assert!(
            !is_answered("an_uncited_gate", &cited, &[]),
            "with an empty exemption list an uncited test must be reported; if this passes, \
             the citation gate is green because its rule answers everything"
        );
        assert!(
            is_answered(
                "an_uncited_gate",
                &cited,
                &[("an_uncited_gate", "a reason")]
            ),
            "an exemption that does not exempt would make the list unusable and push the \
             next author toward deleting the test or the directory instead"
        );
        assert!(
            !is_answered("an_uncited_gate", &cited, &[("another_test", "a reason")]),
            "an exemption naming one test must not answer for another, or one entry would \
             silence the whole directory"
        );
        // And the citation has to name the file the test lives in: `cited` is
        // what the caller resolved for that one file, never the whole document.
        assert!(!is_answered("a_cited_gate", &[], &[]));

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
