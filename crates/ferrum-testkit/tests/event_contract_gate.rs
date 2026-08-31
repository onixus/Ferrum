//! The record that leaves this product, and what it is allowed to become.
//!
//! `EventEnvelope` is an interface with somebody else's system. A SIEM rule is
//! written once, by a person who will never read this repository, against the
//! field names of a record they saw. Every ordinary way of fixing a mistake is
//! unavailable: there is no version negotiation, no deprecation window a
//! consumer can be told about, and no error when a detection silently stops
//! matching. A renamed field is a detection that reports nothing, forever, and
//! nothing anywhere goes red.
//!
//! So this file holds five things, and each one is a way that fails.
//!
//! 1. **The shape drifting from the version it claims.** The field inventory
//!    is *derived* from the type by serialising it — there is no hand-written
//!    list of fields here, because a hand-written list is a second copy and
//!    copies drift. It is compared against the frozen inventory of the version
//!    the code claims, and against every earlier one of the same major. A
//!    field added without a version bump fails; a field removed or retyped
//!    fails and keeps failing.
//! 2. **A released record becoming unreadable.** The frozen records under
//!    `crates/ferrum-proto/schema/records/` were emitted by the versions they
//!    are named after, and this build must still decode all of them. That is
//!    the compatibility claim itself, rather than a description of it.
//! 3. **A field reaching a third-party system because nobody decided.**
//!    `ferrum_siem::FIELDS` must cover every leaf of the envelope exactly, and
//!    the withheld ones must be provably absent from all three renderings.
//! 4. **A workload forging a record.** `comm` is chosen by the process being
//!    enforced against. An envelope full of `|`, `=`, `"`, `]` and newlines
//!    goes through all three profiles here, and the record count may not move.
//! 5. **The sink being code nobody runs.** A real §D enforcement decision is
//!    pumped through the shipped chain — `QueueSink` over `FanoutSink` over a
//!    file sink and a `SyslogSink` — into a TCP listener bound in this test,
//!    and the record that arrives is parsed back. And a destination that is
//!    not there must reach the agent's own degraded state through the counter
//!    that already existed, not through a second one.
//!
//! What none of it can do: it cannot check that a *value's meaning* stayed the
//! same. A new string in `action` is a schema change to whoever wrote
//! `action == "kill"`, and no scan over field names will ever see it. That
//! clause of the evolution rule is a human duty and the module docs of
//! `ferrum-proto` say so in those words.

#[allow(dead_code)]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chrono::{TimeZone, Utc};
use ferrum_export::{EventSink, FanoutSink, QueueSink, RotatingFileSink, SinkContext};
use ferrum_ids::{Digest, PolicyId, RuleId};
use ferrum_proto::{
    EnforcementEvent, EventEnvelope, SchemaId, SchemaVersion, WaiverRef, EVENT_SCHEMA,
    EVENT_SCHEMA_VERSION,
};
use ferrum_siem::{Disposition, Profile, SinkConfig, SyslogSink, Transport, FIELDS};
use serde_json::Value;

const SCHEMA_DIR: &str = "crates/ferrum-proto/schema";
const RECORD_DIR: &str = "crates/ferrum-proto/schema/records";

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

// --- the envelope this gate reasons about
//
// Two of them: one with every optional field present, one with none. The
// difference between their serialisations is what "optional" means on the
// wire, and deriving it that way rather than reading the `#[serde]` attributes
// means a change to those attributes is visible here.

/// Distinctive values, so a gate can ask whether a field's *value* reached a
/// rendering rather than whether its name did. Nothing here contains a
/// character any of the three formats treats specially — the hostile case is a
/// separate test with the opposite property.
const SENTINEL_NODE: &str = "sentinelnode";
const SENTINEL_ROLE: &str = "sentinelrole";
const SENTINEL_BUNDLE: &str = "sha256:sentinelbundle";
const SENTINEL_POLICY: &str = "sentinelpolicy";
const SENTINEL_RULE: &str = "sentinelrule";
const SENTINEL_ACTION: &str = "kill";
const SENTINEL_IMAGE: &str = "sha256:sentinelimage";
const SENTINEL_POD: &str = "sentinelpod";
const SENTINEL_NS: &str = "sentinelns";
const SENTINEL_COMM: &str = "sentinelcomm";
const SENTINEL_SYSCALL: &str = "execve";
const SENTINEL_RESPOND_ERROR: &str = "sentinelresponderror";
const SENTINEL_TICKET: &str = "SENTINELTICKET-1";
const SENTINEL_PID: u32 = 131_071;
const SENTINEL_TGID: u32 = 262_143;
/// The two values that must never leave the product.
const SENTINEL_REQUESTED_BY: &str = "sentinelrequestedby";
const SENTINEL_APPROVED_BY: &str = "sentinelapprovedby";

fn maximal() -> EventEnvelope {
    EventEnvelope {
        schema: SchemaId,
        schema_version: EVENT_SCHEMA_VERSION,
        ts: Utc.with_ymd_and_hms(2026, 8, 31, 12, 0, 0).unwrap(),
        node: SENTINEL_NODE.into(),
        bundle_digest: Some(Digest::new(SENTINEL_BUNDLE)),
        agent_role: SENTINEL_ROLE.into(),
        degraded: true,
        event: EnforcementEvent {
            policy: PolicyId::new(SENTINEL_POLICY),
            rule: RuleId::new(SENTINEL_RULE),
            action: SENTINEL_ACTION.into(),
            image_digest: Some(Digest::new(SENTINEL_IMAGE)),
            pod: SENTINEL_POD.into(),
            namespace: SENTINEL_NS.into(),
            comm: SENTINEL_COMM.into(),
            syscall: SENTINEL_SYSCALL.into(),
            pid: SENTINEL_PID,
            tgid: SENTINEL_TGID,
            executed: true,
            labels_unknown: true,
            path_unknown: true,
            container_unknown: true,
            respond_error: Some(SENTINEL_RESPOND_ERROR.into()),
            waiver: Some(WaiverRef {
                ticket: SENTINEL_TICKET.into(),
                requested_by: SENTINEL_REQUESTED_BY.into(),
                approved_by: SENTINEL_APPROVED_BY.into(),
                expires_at: Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap(),
            }),
        },
    }
}

fn minimal() -> EventEnvelope {
    EventEnvelope {
        schema: SchemaId,
        schema_version: EVENT_SCHEMA_VERSION,
        ts: Utc.with_ymd_and_hms(2026, 8, 31, 12, 0, 0).unwrap(),
        node: String::new(),
        bundle_digest: None,
        agent_role: String::new(),
        degraded: false,
        event: EnforcementEvent {
            policy: PolicyId::new(""),
            rule: RuleId::new(""),
            action: String::new(),
            image_digest: None,
            pod: String::new(),
            namespace: String::new(),
            comm: String::new(),
            syscall: String::new(),
            pid: 0,
            tgid: 0,
            executed: false,
            labels_unknown: false,
            path_unknown: false,
            container_unknown: false,
            respond_error: None,
            waiver: None,
        },
    }
}

/// One leaf of the serialised record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Leaf {
    /// JSON type of the value in the maximal record.
    kind: String,
    /// How the key behaves when there is nothing to say. Three values, and
    /// each is a different promise to a consumer:
    ///
    ///  * `always` — the key is written on every record. A consumer may index
    ///    on it.
    ///  * `omitted` — the key disappears from its object. A consumer has to
    ///    check for it.
    ///  * `with-parent` — the key is required *inside* an object that is
    ///    itself optional. A consumer that found the object may rely on the
    ///    key; the thing it has to check for is the object.
    ///
    /// The third exists because collapsing it into `omitted` would be a lie in
    /// both directions: `waiver.ticket` is not optional (a waiver without a
    /// ticket does not decode), and it is not always present either.
    presence: String,
    /// Whether the key can carry `null`.
    nullable: bool,
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Every leaf path of a JSON object, dotted. Objects recurse; everything else
/// is a leaf, `null` included.
fn leaves(value: &Value, prefix: &str, out: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                leaves(child, &path, out);
            }
        }
        other => {
            out.insert(prefix.to_string(), other.clone());
        }
    }
}

/// Where a path stops existing in a record that says nothing, if it does.
///
/// Returns the prefix of `path` that is missing: the whole path when only the
/// leaf is gone, a shorter one when an object above it is. `None` when the
/// path is present all the way down.
fn missing_at(doc: &Value, path: &str) -> Option<String> {
    let mut node = doc;
    let mut walked = Vec::new();
    for part in path.split('.') {
        walked.push(part);
        match node.get(part) {
            Some(child) => node = child,
            None => return Some(walked.join(".")),
        }
    }
    None
}

/// The field inventory of this build, derived by serialising the type.
fn inventory() -> BTreeMap<String, Leaf> {
    let full = serde_json::to_value(maximal()).expect("serialise maximal");
    let empty = serde_json::to_value(minimal()).expect("serialise minimal");
    let mut full_leaves = BTreeMap::new();
    leaves(&full, "", &mut full_leaves);

    full_leaves
        .into_iter()
        .map(|(path, value)| {
            let presence = match missing_at(&empty, &path) {
                None => "always",
                Some(at) if at == path => "omitted",
                Some(_) => "with-parent",
            };
            let leaf = Leaf {
                kind: kind_of(&value).to_string(),
                presence: presence.to_string(),
                nullable: matches!(empty.pointer(&pointer(&path)), Some(Value::Null)),
            };
            (path, leaf)
        })
        .collect()
}

/// A dotted path as a JSON pointer. None of the field names in this schema
/// contain `/` or `~`, and a field that did would be a schema change this
/// gate's own comparison would report first.
fn pointer(path: &str) -> String {
    format!("/{}", path.replace('.', "/"))
}

/// The frozen inventory of one released version.
fn frozen(version: SchemaVersion) -> BTreeMap<String, Leaf> {
    let text = read(&format!("{SCHEMA_DIR}/v{version}.json"));
    let doc: Value = serde_json::from_str(&text).expect("frozen inventory is not valid JSON");
    assert_eq!(
        doc["schema"].as_str(),
        Some(EVENT_SCHEMA),
        "the frozen inventory for {version} names another schema"
    );
    assert_eq!(
        doc["version"].as_str().map(str::to_string),
        Some(version.to_string()),
        "the frozen inventory for {version} names another version"
    );
    doc["fields"]
        .as_object()
        .expect("`fields` is not an object")
        .iter()
        .map(|(path, leaf)| {
            (
                path.clone(),
                Leaf {
                    kind: leaf["type"].as_str().expect("type").to_string(),
                    presence: leaf["presence"].as_str().expect("presence").to_string(),
                    nullable: leaf["nullable"].as_bool().expect("nullable"),
                },
            )
        })
        .collect()
}

/// Every version this repository has frozen, found rather than listed: a file
/// added and not mentioned anywhere is exactly what the checks below must see.
fn frozen_versions() -> Vec<SchemaVersion> {
    let dir = repo_root().join(SCHEMA_DIR);
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("schema directory").flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix('v') else {
            continue;
        };
        let Some(rest) = rest.strip_suffix(".json") else {
            continue;
        };
        out.push(
            rest.parse::<SchemaVersion>()
                .unwrap_or_else(|err| panic!("{name}: {err}")),
        );
    }
    out.sort();
    assert!(
        !out.is_empty(),
        "no frozen inventory under {SCHEMA_DIR}: this gate would compare nothing and pass"
    );
    out
}

/// The one direction that cannot be satisfied by editing the current code:
/// records written by a released version must still decode.
///
/// Not a description of compatibility — the compatibility itself. Every line
/// under `schema/records/` was produced by the version its file is named
/// after, and a change to `EventEnvelope` that cannot read them is a change
/// that orphaned every record already sitting in somebody's SIEM and in every
/// rotated `events.jsonl` on every node.
#[test]
fn every_record_a_released_version_wrote_is_still_readable_by_this_build() {
    let mut checked = 0usize;
    for version in frozen_versions() {
        let text = read(&format!("{RECORD_DIR}/v{version}.jsonl"));
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert!(
            lines.len() >= 2,
            "{RECORD_DIR}/v{version}.jsonl holds {} records; one record cannot show both a \
             populated and an empty optional, so the file proves nothing about the fields that \
             are allowed to be absent",
            lines.len()
        );
        for (n, line) in lines.iter().enumerate() {
            let record: EventEnvelope = serde_json::from_str(line).unwrap_or_else(|err| {
                panic!(
                    "{RECORD_DIR}/v{version}.jsonl:{}: a record this product released no longer \
                     decodes: {err}\nA consumer's stored records are in the same position, and \
                     nothing on their side will report it.",
                    n + 1
                )
            });
            assert_eq!(
                record.schema_version,
                version,
                "{RECORD_DIR}/v{version}.jsonl:{}: the record claims another version, so the \
                 file is not evidence about {version}",
                n + 1
            );
            assert!(
                record.schema_version.readable_by(EVENT_SCHEMA_VERSION),
                "a frozen record of {version} is not readable by {EVENT_SCHEMA_VERSION} by the \
                 type's own rule, and yet it decoded"
            );
            checked += 1;
        }
    }
    assert!(checked >= 2, "the scan read {checked} records");
}

/// The shape this build produces is the shape frozen for the version it
/// claims, and every earlier version of the same major is a subset of it with
/// nothing changed underneath.
///
/// Adding a field therefore costs a version bump and a new frozen file, which
/// is the evolution rule turned into a build failure. Removing or retyping one
/// costs nothing that can be paid: the older inventory keeps naming it.
#[test]
fn this_builds_record_shape_is_the_one_frozen_for_the_version_it_claims() {
    let current = inventory();
    assert!(
        current.len() > 20,
        "the derivation produced {} leaves; the envelope has more than twenty, so the scan is \
         broken rather than the type",
        current.len()
    );
    let versions = frozen_versions();
    assert!(
        versions.contains(&EVENT_SCHEMA_VERSION),
        "EVENT_SCHEMA_VERSION is {EVENT_SCHEMA_VERSION} and {SCHEMA_DIR} has no \
         v{EVENT_SCHEMA_VERSION}.json. A version the code claims and nothing froze is a version \
         no consumer can be held to."
    );
    assert_eq!(
        current,
        frozen(EVENT_SCHEMA_VERSION),
        "the record this build writes is not the one frozen for v{EVENT_SCHEMA_VERSION}. If a \
         field was added: bump the minor in `ferrum-proto`, freeze a new inventory beside the \
         old one, and add a record file for it. If a field was renamed, removed or retyped: it \
         is not an allowed change within a major version — see the evolution rule in \
         `ferrum-proto`'s module docs."
    );

    for version in versions {
        if version.major != EVENT_SCHEMA_VERSION.major || version == EVENT_SCHEMA_VERSION {
            continue;
        }
        for (path, was) in frozen(version) {
            let now = current.get(&path).unwrap_or_else(|| {
                panic!(
                    "v{version} promised the field {path:?} and this build does not write it. \
                     Within a major version a field is never taken away: a consumer reading it \
                     gets nothing, and gets no error either."
                )
            });
            assert_eq!(
                *now, was,
                "the field {path:?} changed between v{version} and this build. Type, presence \
                 and nullability are all part of what v{version} promised."
            );
        }
    }
}

/// Control on the derivation: a removed and a retyped field must both be
/// visible to it.
///
/// Without this, the comparison above would also pass on a derivation that
/// returned the same map for every input — which is what a small mistake in
/// the leaf walk produces, and it would leave the whole file asserting
/// nothing.
#[test]
fn the_inventory_derivation_notices_a_removed_and_a_retyped_field() {
    let intact = inventory();
    assert!(intact.contains_key("event.comm"));
    assert!(intact.contains_key("event.waiver.ticket"));

    let full = serde_json::to_value(maximal()).expect("serialise");
    let mut removed = full.clone();
    removed
        .as_object_mut()
        .expect("object")
        .get_mut("event")
        .expect("event")
        .as_object_mut()
        .expect("event object")
        .remove("comm")
        .expect("comm was there");
    let mut leaves_of_removed = BTreeMap::new();
    leaves(&removed, "", &mut leaves_of_removed);
    assert!(
        !leaves_of_removed.contains_key("event.comm"),
        "the walk reported a field that is not in the document: it cannot see a removal"
    );

    let mut retyped = full;
    retyped["event"]["pid"] = Value::String("131071".into());
    let mut leaves_of_retyped = BTreeMap::new();
    leaves(&retyped, "", &mut leaves_of_retyped);
    assert_eq!(
        kind_of(&leaves_of_retyped["event.pid"]),
        "string",
        "the walk read a string as a number: a retyped field would compare equal"
    );
    assert_eq!(kind_of(&intact_value("event.pid")), "number");
}

fn intact_value(path: &str) -> Value {
    let full = serde_json::to_value(maximal()).expect("serialise");
    let mut out = BTreeMap::new();
    leaves(&full, "", &mut out);
    out.get(path)
        .unwrap_or_else(|| panic!("{path} is not a leaf of the envelope"))
        .clone()
}

/// Every leaf that could leave this product has a written decision about
/// whether it does.
///
/// Both directions, and the second is the one that matters: a field added to
/// `EventEnvelope` and not mentioned in `ferrum_siem::FIELDS` fails here, so
/// it cannot reach a third-party system because nobody thought about it. The
/// first direction keeps the table from describing fields that are gone.
#[test]
fn every_field_that_leaves_this_product_has_a_written_disposition() {
    let paths: BTreeSet<String> = inventory().keys().cloned().collect();
    let decided: BTreeSet<String> = FIELDS.iter().map(|(p, _, _)| (*p).to_string()).collect();

    let undecided: Vec<&String> = paths.difference(&decided).collect();
    assert!(
        undecided.is_empty(),
        "these fields of the exported record have no entry in ferrum_siem::FIELDS: \
         {undecided:#?}. A field with no decision is a field that leaves this product because \
         nobody stopped it — and the destination is a system whose retention, access control \
         and jurisdiction are not this project's to reason about."
    );
    let invented: Vec<&String> = decided.difference(&paths).collect();
    assert!(
        invented.is_empty(),
        "ferrum_siem::FIELDS decides about fields the envelope does not have: {invented:#?}"
    );

    // The optionality the inventory claims is the optionality the type has:
    // an `omitted` field must decode when absent, and a `nullable` one when
    // null. Otherwise "optional" is a word in a JSON file.
    let full = serde_json::to_value(maximal()).expect("serialise");
    let empty = serde_json::to_value(minimal()).expect("serialise");
    for (path, leaf) in inventory() {
        if leaf.presence != "always" {
            // Remove what actually goes missing — the leaf for `omitted`, the
            // object above it for `with-parent`. Removing a `with-parent` leaf
            // on its own would produce a record the product never writes, and
            // failing on it would be this gate inventing a requirement.
            let gone = missing_at(&empty, &path).expect("not always present");
            let mut without = full.clone();
            remove_path(&mut without, &gone);
            serde_json::from_value::<EventEnvelope>(without).unwrap_or_else(|err| {
                panic!(
                    "{path} is frozen as {} and a record without {gone} does not decode: {err}",
                    leaf.presence
                )
            });
        }
        if leaf.nullable {
            let mut nulled = full.clone();
            set_path(&mut nulled, &path, Value::Null);
            serde_json::from_value::<EventEnvelope>(nulled).unwrap_or_else(|err| {
                panic!("{path} is frozen as nullable and a null in it does not decode: {err}")
            });
        }
    }
}

fn walk_to<'a>(doc: &'a mut Value, path: &str) -> (&'a mut Value, String) {
    let mut node = doc;
    let parts: Vec<&str> = path.split('.').collect();
    for part in &parts[..parts.len() - 1] {
        node = node.get_mut(*part).expect("path exists");
    }
    (node, parts[parts.len() - 1].to_string())
}

fn remove_path(doc: &mut Value, path: &str) {
    let (parent, key) = walk_to(doc, path);
    parent.as_object_mut().expect("object").remove(&key);
}

fn set_path(doc: &mut Value, path: &str, value: Value) {
    let (parent, key) = walk_to(doc, path);
    parent.as_object_mut().expect("object").insert(key, value);
}

/// A withheld field reaches no profile.
///
/// Asserted on the *value*, not on the key name: a renderer that put
/// `approvedBy` under some other key would satisfy a check on the key and
/// still ship the person's name.
#[test]
fn a_withheld_field_appears_in_no_profile() {
    let withheld: Vec<&str> = FIELDS
        .iter()
        .filter(|(_, d, _)| *d == Disposition::Withheld)
        .map(|(p, _, _)| *p)
        .collect();
    assert!(
        !withheld.is_empty(),
        "nothing is withheld, so this gate is about nothing — which would itself be the finding"
    );
    let sentinels: BTreeMap<&str, &str> = [
        ("event.waiver.requestedBy", SENTINEL_REQUESTED_BY),
        ("event.waiver.approvedBy", SENTINEL_APPROVED_BY),
    ]
    .into_iter()
    .collect();
    for path in &withheld {
        assert!(
            sentinels.contains_key(path),
            "{path} is withheld and this gate has no sentinel value for it, so nothing checks \
             that it is actually absent"
        );
    }

    let envelope = maximal();
    for profile in Profile::ALL {
        let rendered = profile.render(&envelope);
        for (path, sentinel) in &sentinels {
            assert!(
                !rendered.contains(sentinel),
                "{path} is withheld and its value is in the {} rendering:\n{rendered}",
                profile.name()
            );
        }
        // The control: the *ticket* is emitted, so a rendering that contained
        // neither would pass the assertion above by rendering nothing at all.
        assert!(
            rendered.contains(SENTINEL_TICKET),
            "the {} rendering carries no waiver at all, so the absence of the two names above \
             proves nothing:\n{rendered}",
            profile.name()
        );
    }
}

/// Every value declared emitted actually reaches every profile.
///
/// Strings and numbers are checked by their sentinel value. Booleans cannot
/// be: both of their values appear in a rendering that names the field, so a
/// substring check on one proves nothing. They are checked by flipping the
/// single flag and requiring the rendering to change — which needs no table of
/// per-profile key names, and which a newly added boolean fails until somebody
/// gives it a probe.
#[test]
fn every_emitted_value_reaches_every_profile() {
    let inventory = inventory();
    let emitted: Vec<&str> = FIELDS
        .iter()
        .filter(|(_, d, _)| *d == Disposition::Emitted)
        .map(|(p, _, _)| *p)
        .collect();

    let sentinels: BTreeMap<&str, String> = [
        ("schema", EVENT_SCHEMA.to_string()),
        ("schemaVersion", EVENT_SCHEMA_VERSION.to_string()),
        // Only the date part: the three profiles format the instant
        // differently on purpose (CEF wants epoch millis in `rt`), and the one
        // thing all of them must carry is the moment.
        ("ts", "2026-08-31".to_string()),
        ("node", SENTINEL_NODE.to_string()),
        ("bundleDigest", SENTINEL_BUNDLE.to_string()),
        ("agentRole", SENTINEL_ROLE.to_string()),
        ("event.policy", SENTINEL_POLICY.to_string()),
        ("event.rule", SENTINEL_RULE.to_string()),
        ("event.action", SENTINEL_ACTION.to_string()),
        ("event.imageDigest", SENTINEL_IMAGE.to_string()),
        ("event.pod", SENTINEL_POD.to_string()),
        ("event.namespace", SENTINEL_NS.to_string()),
        ("event.comm", SENTINEL_COMM.to_string()),
        ("event.syscall", SENTINEL_SYSCALL.to_string()),
        ("event.pid", SENTINEL_PID.to_string()),
        ("event.tgid", SENTINEL_TGID.to_string()),
        ("event.respondError", SENTINEL_RESPOND_ERROR.to_string()),
        ("event.waiver.ticket", SENTINEL_TICKET.to_string()),
        ("event.waiver.expiresAt", "2026-11-01".to_string()),
    ]
    .into_iter()
    .collect();

    // Flipping one flag must change the record. The closure is the probe; a
    // boolean with none of them is a field this gate cannot see.
    type Flip = fn(&mut EventEnvelope);
    let flips: BTreeMap<&str, Flip> = [
        (
            "degraded",
            (|e: &mut EventEnvelope| e.degraded = false) as Flip,
        ),
        (
            "event.executed",
            (|e: &mut EventEnvelope| e.event.executed = false) as Flip,
        ),
        (
            "event.labelsUnknown",
            (|e: &mut EventEnvelope| e.event.labels_unknown = false) as Flip,
        ),
        (
            "event.pathUnknown",
            (|e: &mut EventEnvelope| e.event.path_unknown = false) as Flip,
        ),
        (
            "event.containerUnknown",
            (|e: &mut EventEnvelope| e.event.container_unknown = false) as Flip,
        ),
    ]
    .into_iter()
    .collect();

    let envelope = maximal();
    for path in emitted {
        let leaf = inventory
            .get(path)
            .unwrap_or_else(|| panic!("{path} is not a leaf of the envelope"));
        for profile in Profile::ALL {
            let rendered = profile.render(&envelope);
            if leaf.kind == "bool" {
                let flip = flips.get(path).unwrap_or_else(|| {
                    panic!(
                        "{path} is a boolean declared emitted and has no flip probe: a substring \
                         check cannot tell `false` from a field that is missing, so nothing here \
                         would notice it being dropped"
                    )
                });
                let mut flipped = envelope.clone();
                flip(&mut flipped);
                assert_ne!(
                    profile.render(&flipped),
                    rendered,
                    "flipping {path} did not change the {} rendering, so the field is declared \
                     emitted and is not in it",
                    profile.name()
                );
                continue;
            }
            let sentinel = sentinels.get(path).unwrap_or_else(|| {
                panic!("{path} is declared emitted and this gate has no sentinel for it")
            });
            assert!(
                rendered.contains(sentinel.as_str()),
                "{path} is declared emitted and its value is not in the {} rendering:\n{rendered}",
                profile.name()
            );
        }
    }
}

/// A workload cannot forge a record.
///
/// `comm` is the process's own name, and in the two line-oriented profiles a
/// newline in it would be a second record attributed to this node. The pod and
/// namespace are chosen by whoever can create objects, and the format
/// metacharacters differ per profile — `|` and `=` for CEF, `"` and `]` for
/// the structured data, `"` and `{` for JSON — so all of them go in at once.
#[test]
fn a_hostile_workload_cannot_forge_a_record_in_any_profile() {
    let mut envelope = maximal();
    envelope.event.comm = "sh\nCEF:0|Acme|Fake|1|0|forged|10|act=allow".into();
    envelope.event.pod = "p\"]\r[ferrum@32473 forged=\"yes\"".into();
    envelope.event.namespace = "ns=1|2\\3".into();
    envelope.event.respond_error = Some("{\"forged\":true}\n{\"second\":1}".into());

    for profile in Profile::ALL {
        let rendered = profile.render(&envelope);
        assert_eq!(
            rendered.lines().count(),
            1,
            "the {} rendering of a hostile event is {} lines: a workload named itself into a \
             second record.\n{rendered}",
            profile.name(),
            rendered.lines().count()
        );
        assert!(
            !rendered.contains('\r'),
            "a CR survived into {}",
            profile.name()
        );
        match profile {
            Profile::Cef => {
                // The forged `CEF:0|...|forged|...` text is still *in* the
                // record, and that is correct: CEF's extension may contain
                // pipes, and deleting an attacker's input would hide the
                // attempt. What must be true is that it is in the extension —
                // the eighth field — and moved none of the seven before it. So
                // the header is split the way a connector splits it, on
                // unescaped pipes only.
                let at = rendered.find("CEF:0|").expect("payload");
                let fields = cef_header_fields(&rendered[at..]);
                assert_eq!(fields.len(), 8, "{rendered}");
                assert_eq!(fields[1], "Ferrum", "{rendered}");
                assert_eq!(fields[4], SENTINEL_RULE, "the signature moved: {rendered}");
                assert_eq!(fields[5], "kill", "the name moved: {rendered}");
                assert_eq!(fields[6], "9", "the severity moved: {rendered}");
                assert!(
                    fields[7].contains("forged"),
                    "the forged header did not end up in the extension: {rendered}"
                );
                // The newline the workload tried to insert is recorded, not
                // dropped: the attempt is evidence.
                assert!(fields[7].contains("\\\\x0a"), "{rendered}");
            }
            Profile::Rfc5424 => {
                // Read the element the way a receiver reads it — PARAM-NAME
                // and a quoted PARAM-VALUE with `"`, `\` and `]` un-escaped —
                // rather than counting substrings. A substring count cannot
                // tell a bracket inside a quoted value (harmless, and it must
                // survive: it is the pod name the attacker chose) from one
                // that opened a second element.
                let (params, rest) = parse_sd(&rendered);
                assert_eq!(
                    params.get("pod").map(String::as_str),
                    Some(r#"p"]\x0d[ferrum@32473 forged="yes""#),
                    "the pod name did not survive as one value: {rendered}"
                );
                assert!(
                    !params.contains_key("forged"),
                    "a forged parameter was parsed out of a value: {params:?}"
                );
                assert_eq!(
                    params.get("containerUnknown").map(String::as_str),
                    Some("true"),
                    "the element ended before the last parameter this crate wrote, so a value \
                     closed it early: {rendered}"
                );
                // MSG is free text to the end of the message (RFC 5424 §6.4),
                // so the pod name reappears there with its brackets intact and
                // nothing parses them: SD parsing stopped at the `]` the
                // parser above consumed, which is what the assertions on
                // `params` establish.
                assert!(
                    rest.starts_with(' '),
                    "the element and MSG are not separated: {rest:?}"
                );
            }
            Profile::Ecs => {
                let doc: Value = serde_json::from_str(&rendered).unwrap_or_else(|err| {
                    panic!("hostile input broke the JSON: {err}\n{rendered}")
                });
                assert_eq!(
                    doc["ferrum"]["policy"],
                    Value::String(SENTINEL_POLICY.into())
                );
            }
        }
    }
}

/// Read the one SD-ELEMENT out of an RFC 5424 line the way a receiver does.
///
/// PARAM-NAME, `=`, then a quoted PARAM-VALUE in which `"`, `\` and `]` arrive
/// backslash-escaped (§6.3.3). Returns the parameters and whatever follows the
/// element, which is MSG. Written here rather than asserted about with
/// substrings, because the property under test is what a *parser* sees.
fn parse_sd(line: &str) -> (BTreeMap<String, String>, String) {
    let start = line
        .find(&format!("[{} ", ferrum_siem::rfc5424::SD_ID))
        .expect("no structured-data element");
    let mut chars = line[start..].chars();
    // `[SD-ID `
    for _ in 0..ferrum_siem::rfc5424::SD_ID.len() + 2 {
        chars.next();
    }
    let mut params = BTreeMap::new();
    loop {
        let mut name = String::new();
        loop {
            match chars.next() {
                Some('=') => break,
                Some(']') | None => panic!("element ended inside a parameter name"),
                Some(c) => name.push(c),
            }
        }
        assert_eq!(chars.next(), Some('"'), "PARAM-VALUE is not quoted");
        let mut value = String::new();
        loop {
            match chars.next() {
                Some('\\') => value.push(chars.next().expect("escape at end of element")),
                Some('"') => break,
                None => panic!("element ended inside a parameter value"),
                Some(c) => value.push(c),
            }
        }
        params.insert(name, value);
        match chars.next() {
            Some(' ') => continue,
            Some(']') => break,
            other => panic!("unexpected {other:?} after a parameter"),
        }
    }
    (params, chars.collect())
}

/// Split a CEF prefix the way a connector does: on `|` that is not preceded by
/// a backslash, seven times, and everything left over is the extension.
///
/// A naive `split('|')` is exactly the parser the escaping exists to protect,
/// so a test that used one would call an escaped pipe a moved field and a
/// missing escape correct.
fn cef_header_fields(payload: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let mut escaped = false;
    for ch in payload.chars() {
        if out.len() == 8 {
            out.last_mut().expect("extension").push(ch);
            continue;
        }
        match (escaped, ch) {
            (true, c) => {
                out.last_mut().expect("field").push(c);
                escaped = false;
            }
            (false, '\\') => escaped = true,
            (false, '|') => out.push(String::new()),
            (false, c) => out.last_mut().expect("field").push(c),
        }
    }
    out
}

/// The chain that ships, executed: a real §D enforcement decision, through the
/// real sinks, into a real socket, parsed back on the other side.
///
/// Everything above this test reads text or renders a struct. This one is the
/// only claim in the file about the product working: the record is produced by
/// `pump_records` from the wire bytes the datapath writes, wrapped by the same
/// `QueueSink`/`FanoutSink` the agent's `main` builds, and read off a TCP
/// listener bound here. What it does not cover is the kernel — the records are
/// replayed rather than produced by one, exactly as in `replay.rs`.
#[test]
fn an_enforcement_decision_reaches_a_local_receiver_through_the_shipped_sink_chain() {
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    // Exactly one line, then return. Reading to EOF would wait for the sink's
    // stream to be dropped, and the test holds a handle on the sink to read
    // its counters afterwards — so "to EOF" would be "forever".
    let receiver = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .expect("timeout");
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .expect("one record");
        line
    });

    let dir = std::env::temp_dir().join(format!(
        "ferrum-siem-gate-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("tmpdir");

    let ctx = SinkContext::new("gate-node", "respond");
    ctx.set_bundle_digest(Some(Digest::new("sha256:gatebundle")));
    let siem = std::sync::Arc::new(SyslogSink::new(SinkConfig {
        address: addr.to_string(),
        transport: Transport::Tcp,
        profile: Profile::Ecs,
    }));
    let sink = QueueSink::new(
        FanoutSink::new(
            ctx.clone(),
            vec![
                Box::new(RotatingFileSink::new(
                    dir.clone(),
                    64 * 1024 * 1024,
                    2,
                    ctx.clone(),
                )),
                Box::new(std::sync::Arc::clone(&siem)),
            ],
        ),
        1024,
    );

    // The §D case: `kubectl exec` + /bin/sh must be killed. Replayed from the
    // datapath's own wire bytes, through the shipped policy.
    let (agent, killed) = common::replay_agent(None);
    let records = vec![common::wire::RecordBuilder::new("execve")
        .comm("sh")
        .cgroup(common::CGROUP_PAYMENTS)
        .process(common::TGID_WORKLOAD, common::TGID_WORKLOAD)
        .build(ferrum_ebpf::SyscallArch::X86_64)];
    let stats =
        ferrum_agent::pump_records(&agent, ferrum_ebpf::SyscallArch::X86_64, records, &sink);
    assert_eq!(stats.handled, 1, "the record was not decided: {stats:?}");
    assert_eq!(
        killed.lock().expect("killed").as_slice(),
        &[common::TGID_WORKLOAD],
        "the §D case did not kill, so the record this gate is about is not a kill record"
    );

    // Flush the queue: the writer thread is what does the sending, and until
    // it has drained, the record this test is about may still be in it.
    sink.close();
    let line = receiver.join().expect("receiver thread");
    let record: Value =
        serde_json::from_str(line.trim_end()).expect("the receiver got valid ECS JSON");
    assert_eq!(record["event"]["action"], Value::String("kill".into()));
    assert_eq!(record["event"]["outcome"], Value::String("success".into()));
    assert_eq!(record["host"]["name"], Value::String("gate-node".into()));
    assert_eq!(
        record["orchestrator"]["namespace"],
        Value::String("payments".into())
    );
    assert_eq!(record["rule"]["id"], Value::String("no-shell".into()));
    assert_eq!(
        record["ferrum"]["bundleDigest"],
        Value::String("sha256:gatebundle".into())
    );
    assert_eq!(
        record["ferrum"]["schemaVersion"],
        Value::String(EVENT_SCHEMA_VERSION.to_string())
    );
    assert_eq!(
        record["ferrum"]["tgid"],
        Value::Number(common::TGID_WORKLOAD.into())
    );

    // The same decision is in the file, with the same timestamp: one event is
    // one record, and an investigation joining the two joins on a field that
    // matches.
    let jsonl = std::fs::read_to_string(dir.join("events.jsonl")).expect("events.jsonl");
    let local: EventEnvelope =
        serde_json::from_str(jsonl.lines().next().expect("a line")).expect("envelope");
    assert_eq!(
        local
            .ts
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        record["@timestamp"].as_str().expect("@timestamp"),
        "the node's own record and the SIEM's carry different timestamps for one decision"
    );
    assert_eq!(siem.export_write_failed_total(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

/// A SIEM that is not there is counted, and the count reaches the agent's own
/// degraded state — through the counter that already existed.
///
/// The point of the test is the *absence* of a second counter: what the
/// operator sees is `export_write_failed_total`, the same family already on
/// `/metrics` and already wired to `DEG_EXPORT_LOSSY`. A new family for this
/// destination would have needed a new panel, a new alert and a new thing to
/// forget.
#[test]
fn an_unreachable_siem_is_counted_by_the_existing_export_loss_and_degrades_the_node() {
    use ferrum_agent::{Agent, AgentConfig, DEG_EXPORT_LOSSY};
    use std::net::TcpListener;
    use std::time::Instant;

    let addr = {
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind");
        probe.local_addr().expect("addr")
    };
    let ctx = SinkContext::new("gate-node", "observe");
    let sink = FanoutSink::new(
        ctx,
        vec![
            Box::new(ferrum_export::MemorySink::new()),
            Box::new(SyslogSink::new(SinkConfig {
                address: addr.to_string(),
                transport: Transport::Tcp,
                profile: Profile::Cef,
            })),
        ],
    );

    let agent = Agent::new(AgentConfig::default());
    let now = Instant::now();
    agent.note_export_state_at(&sink, now);
    let before = agent.degraded_snapshot_at(now);
    assert!(
        !before
            .reasons
            .iter()
            .any(|r| r.starts_with(DEG_EXPORT_LOSSY)),
        "the node was already reporting export loss before anything was exported"
    );

    sink.emit(&sample_event());
    assert_eq!(
        sink.export_write_failed_total(),
        1,
        "an event that never reached the SIEM was not counted anywhere"
    );
    // The local destination still has it: the record is not gone, the *export*
    // to the system the SOC watches is.
    assert_eq!(sink.export_queue_dropped_total(), 0);

    agent.note_export_state_at(&sink, now);
    let after = agent.degraded_snapshot_at(now);
    assert!(
        after
            .reasons
            .iter()
            .any(|r| r.starts_with(DEG_EXPORT_LOSSY)),
        "a SIEM that is not there did not make the node Degraded; the loss is therefore visible \
         only to whoever reads this counter on purpose, which is the silent loss the boundary \
         forbids. Reasons: {:?}",
        after.reasons
    );
}

fn sample_event() -> EnforcementEvent {
    EnforcementEvent {
        policy: PolicyId::new("p"),
        rule: RuleId::new("no-shell"),
        action: "kill".into(),
        image_digest: None,
        pod: "web".into(),
        namespace: "prod".into(),
        comm: "sh".into(),
        syscall: "execve".into(),
        pid: 7,
        tgid: 7,
        executed: true,
        labels_unknown: false,
        path_unknown: false,
        container_unknown: false,
        respond_error: None,
        waiver: None,
    }
}

/// The sink is wired in the shipping tree, or it is code nobody runs.
///
/// The default install cannot carry a destination — the address belongs to the
/// site, and a default would be either a name that does not resolve on every
/// node or a guess about somebody's network. So it is a kustomize root of its
/// own, and what this test holds is that the root really passes the flags the
/// binary really parses: an overlay naming `--siem-endpoint` would install
/// cleanly, change nothing, and be discovered when an incident could not be
/// investigated.
#[test]
fn the_shipped_overlay_configures_the_sink_with_flags_the_binary_parses() {
    use serde_yaml::Value as Yaml;

    const OVERLAY: &str = "overlays/siem-syslog/kustomization.yaml";
    let doc: Yaml = serde_yaml::from_str(&read(OVERLAY)).expect("the overlay is not valid YAML");
    let resources: Vec<&str> = doc
        .get("resources")
        .and_then(Yaml::as_sequence)
        .expect("the overlay installs nothing")
        .iter()
        .filter_map(Yaml::as_str)
        .collect();
    assert_eq!(
        resources,
        ["../../deploy/agent"],
        "the SIEM overlay must patch the agent root and nothing else: it is the DaemonSet that \
         exports, and an overlay that also pulled the control plane would make turning the sink \
         on a re-apply of the webhook"
    );

    // The args the patch appends, in order, read out of the patch document
    // rather than grepped: what the DaemonSet ends up running is a list, and
    // an assertion about a substring would pass on a flag whose value went
    // missing.
    let patch = doc
        .get("patches")
        .and_then(Yaml::as_sequence)
        .and_then(|p| p.first())
        .and_then(|p| p.get("patch"))
        .and_then(Yaml::as_str)
        .expect("the overlay carries no patch, so it changes no args");
    let ops: Yaml = serde_yaml::from_str(patch).expect("the patch is not valid YAML");
    let appended: Vec<String> = ops
        .as_sequence()
        .expect("the patch is not a list of operations")
        .iter()
        .map(|op| {
            assert_eq!(
                op.get("op").and_then(Yaml::as_str),
                Some("add"),
                "the overlay does something other than append arguments: {op:?}"
            );
            assert_eq!(
                op.get("path").and_then(Yaml::as_str),
                Some("/spec/template/spec/containers/0/args/-"),
                "the overlay writes somewhere other than the end of the agent's args: {op:?}"
            );
            op.get("value")
                .and_then(Yaml::as_str)
                .expect("an argument with no value")
                .to_string()
        })
        .collect();

    let pairs: BTreeMap<&str, &str> = appended
        .chunks(2)
        .map(|pair| {
            assert_eq!(pair.len(), 2, "a flag with no value: {appended:?}");
            (pair[0].as_str(), pair[1].as_str())
        })
        .collect();
    for flag in ["--siem-address", "--siem-transport", "--siem-profile"] {
        assert!(
            pairs.contains_key(flag),
            "{OVERLAY} passes no {flag}, so applying it changes nothing about the export: \
             {appended:?}"
        );
    }
    assert!(
        pairs["--siem-address"].contains(':'),
        "{OVERLAY} names {:?} as the destination, which has no port",
        pairs["--siem-address"]
    );

    // Every flag the overlay passes is one `main` reads. A patch naming a flag
    // the binary ignores installs cleanly and does nothing.
    let main = read("crates/ferrum-agent/src/main.rs");
    for flag in pairs.keys() {
        let name = flag.trim_start_matches("--");
        assert!(
            main.contains(&format!("get(\"{name}\")")),
            "{OVERLAY} passes {flag} and crates/ferrum-agent/src/main.rs never reads it: the \
             overlay would install and export nothing"
        );
    }

    // And the values are ones the binary accepts, read through the parsers
    // themselves rather than through a copy of their names.
    Profile::parse_name(pairs["--siem-profile"])
        .unwrap_or_else(|err| panic!("{OVERLAY} names a profile the binary refuses: {err}"));
    Transport::parse_name(pairs["--siem-transport"])
        .unwrap_or_else(|err| panic!("{OVERLAY} names a transport the binary refuses: {err}"));

    // The overlay must not be reachable from the default install: turning on
    // an export to a third party is a deliberate act, like respond.
    let root = read("deploy/kustomization.yaml");
    assert!(
        !root.contains("siem-syslog"),
        "deploy/kustomization.yaml pulls in the SIEM overlay, so an operator who typed \
         `kubectl apply -k deploy` starts shipping enforcement records to an address they did \
         not choose"
    );

    // The README an operator reads has to name it, or the root is a directory
    // nobody finds.
    let readme = read("deploy/README");
    assert!(
        readme.contains("overlays/siem-syslog"),
        "deploy/README does not mention the SIEM overlay: an install path nobody is told about \
         is one nobody takes"
    );
}
