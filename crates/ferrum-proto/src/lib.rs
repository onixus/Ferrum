//! The wire contract of an exported enforcement event.
//!
//! `EventEnvelope` is the only thing this product says about itself to a
//! system nobody here operates. That makes it an interface with the same
//! obligations as a published API and none of the usual ways to fix a mistake:
//! a SIEM rule written against a field name is written once, by somebody else,
//! and a rename here is a detection that silently stops firing there. So the
//! record carries its own identity — [`EVENT_SCHEMA`] and
//! [`EVENT_SCHEMA_VERSION`] — inside every record rather than in a README the
//! receiver never sees.
//!
//! # Evolution rule
//!
//! Within one major version:
//!
//!  * **Adding an optional field is allowed**, and it costs a minor bump. The
//!    field must decode when absent (`#[serde(default)]` or `Option`), so code
//!    written against the older version still parses a newer record.
//!  * **Renaming, removing or retyping a field is not allowed**, and neither
//!    is turning an optional field into a required one. Each of those breaks a
//!    consumer that was written correctly against the older version.
//!  * **Widening what a value means without widening its type is not allowed
//!    either**, and it is the one clause nothing here can check: a new
//!    `action` string is a schema change to whoever wrote `action == "kill"`.
//!
//! A major bump is the sanctioned break. It is a deliberate act that rewrites
//! the gate below along with the schema, and it is not how a field gets added.
//!
//! The rule is held by `crates/ferrum-testkit/tests/event_contract_gate.rs`.
//! It derives the field inventory from this type by serialising it — there is
//! no hand-written list of fields to drift — and compares it against the
//! frozen inventory of every released version in `crates/ferrum-proto/schema/`
//! together with the frozen records beside them. An added field fails the
//! build until the version is bumped and its inventory frozen; a removed or
//! retyped one fails and keeps failing.

use chrono::{DateTime, Utc};
use ferrum_ids::{Digest, PolicyId, RuleId};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Name of the exported record schema, carried in every envelope.
///
/// A constant and not a free string: a SIEM that receives records from more
/// than one product needs a discriminator that is not "it has a field called
/// `pod`".
pub const EVENT_SCHEMA: &str = "ferrum.io/enforcement-event";

/// Version of that schema, `major.minor`. The module docs say what each half
/// licenses.
pub const EVENT_SCHEMA_VERSION: SchemaVersion = SchemaVersion { major: 1, minor: 0 };

/// The `schema` field: serialises to [`EVENT_SCHEMA`] and refuses to decode
/// anything else.
///
/// A unit type rather than a `String`, for two reasons. It allocates nothing
/// on a path that runs once per enforcement event, and a record from another
/// producer fails to decode here instead of being parsed into a shape whose
/// field names happen to line up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SchemaId;

impl Serialize for SchemaId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(EVENT_SCHEMA)
    }
}

impl<'de> Deserialize<'de> for SchemaId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        if text == EVENT_SCHEMA {
            Ok(SchemaId)
        } else {
            Err(D::Error::custom(format!(
                "not a {EVENT_SCHEMA} record: schema={text:?}"
            )))
        }
    }
}

impl std::fmt::Display for SchemaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(EVENT_SCHEMA)
    }
}

/// `major.minor` of the record schema.
///
/// `Copy` and allocation-free for the same reason as [`SchemaId`]. Ordering is
/// by major then minor, so a consumer can ask "is this at least 1.2".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SchemaVersion {
    pub major: u16,
    pub minor: u16,
}

impl SchemaVersion {
    /// Whether a record of this version can be read by code written for
    /// `reader`: same major, and the reader is not behind. That is exactly the
    /// direction the evolution rule guarantees — a newer minor may carry
    /// fields the reader has never heard of, and the reader is required to
    /// ignore them, but a newer *major* promises nothing.
    pub fn readable_by(self, reader: SchemaVersion) -> bool {
        self.major == reader.major && self.minor <= reader.minor
    }
}

impl std::fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl std::str::FromStr for SchemaVersion {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let (major, minor) = text
            .split_once('.')
            .ok_or_else(|| format!("schema version {text:?} is not major.minor"))?;
        Ok(SchemaVersion {
            major: major
                .parse()
                .map_err(|_| format!("schema version {text:?}: major is not a number"))?,
            minor: minor
                .parse()
                .map_err(|_| format!("schema version {text:?}: minor is not a number"))?,
        })
    }
}

impl Serialize for SchemaVersion {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(D::Error::custom)
    }
}

/// Audit trail of the exception that demoted an enforcing action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WaiverRef {
    pub ticket: String,
    pub requested_by: String,
    pub approved_by: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnforcementEvent {
    pub policy: PolicyId,
    pub rule: RuleId,
    pub action: String,
    pub image_digest: Option<Digest>,
    pub pod: String,
    pub namespace: String,
    pub comm: String,
    pub syscall: String,
    /// Structural identity of the process the record came from. Absent in
    /// pre-reaction records, hence `default`.
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub tgid: u32,
    /// True only when the reaction for `action` actually ran (a signal was
    /// delivered). Audit/observe records and every refusal stay false.
    #[serde(default)]
    pub executed: bool,
    /// Why the reaction did not run, when it did not.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub respond_error: Option<String>,
    /// The selector was matched against labels nobody had observed yet: the
    /// rules were applied fail-closed, so this record is an assertion about
    /// the workload, not a resolved match.
    #[serde(default)]
    pub labels_unknown: bool,
    /// A path predicate was accepted against a path the datapath could not
    /// carry whole. Without this an investigation cannot tell a record whose
    /// path was never observed from one that genuinely named the file: the
    /// node counter for it is an aggregate and cannot be joined to a record.
    #[serde(default)]
    pub path_unknown: bool,
    /// A `containerOnly` rule that would have decided this record was skipped
    /// because the datapath did not flag the caller as a container, on a
    /// caller nothing has yet proven is not one. Unlike the two above it does
    /// not mark the verdict fail-closed — the flag stays the authority — but
    /// it is the one signal saying the verdict was reached without knowing
    /// whether the process was in a container. The node counter for it is an
    /// aggregate and cannot be joined to a record, so without this field a
    /// single exported event carries only a reason string and downstream can
    /// neither filter nor aggregate on it.
    #[serde(default)]
    pub container_unknown: bool,
    /// Set only on waived events.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub waiver: Option<WaiverRef>,
}

/// Self-contained export record: readable without access to the cluster
/// that produced it (etcd is not the SIEM).
///
/// The first two fields are the contract, and they are required on decode
/// rather than defaulted. A record with no version is not a version 1 record —
/// it is a record from a producer this build knows nothing about, and reading
/// it as the current schema is precisely the silent misinterpretation the
/// version exists to prevent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventEnvelope {
    /// Always [`EVENT_SCHEMA`].
    pub schema: SchemaId,
    /// The version this record was written under, not the version the reader
    /// wants: a file on a node outlives the agent that wrote it, and a
    /// rotated `events.jsonl` can hold two versions at once.
    pub schema_version: SchemaVersion,
    pub ts: DateTime<Utc>,
    pub node: String,
    /// None until the agent has loaded its first bundle.
    pub bundle_digest: Option<Digest>,
    pub agent_role: String,
    pub degraded: bool,
    pub event: EnforcementEvent,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> EventEnvelope {
        EventEnvelope {
            schema: SchemaId,
            schema_version: EVENT_SCHEMA_VERSION,
            ts: Utc::now(),
            node: "node-a".into(),
            bundle_digest: Some(Digest::new("sha256:abc")),
            agent_role: "observe".into(),
            degraded: false,
            event: EnforcementEvent {
                policy: PolicyId::new("p"),
                rule: RuleId::new("no-shell"),
                action: "kill".into(),
                image_digest: None,
                pod: "web".into(),
                namespace: "prod".into(),
                comm: "sh".into(),
                syscall: "execve".into(),
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

    #[test]
    fn envelope_roundtrip_camel_case() {
        let env = EventEnvelope {
            schema: SchemaId,
            schema_version: EVENT_SCHEMA_VERSION,
            ts: Utc::now(),
            node: "node-a".into(),
            bundle_digest: Some(Digest::new("sha256:abc")),
            agent_role: "observe".into(),
            degraded: true,
            event: EnforcementEvent {
                policy: PolicyId::new("p"),
                rule: RuleId::new("no-shell"),
                action: "kill".into(),
                image_digest: None,
                pod: "web".into(),
                namespace: "prod".into(),
                comm: "sh".into(),
                syscall: "execve".into(),
                pid: 0,
                tgid: 0,
                executed: false,
                labels_unknown: false,
                path_unknown: false,
                container_unknown: false,
                respond_error: None,
                waiver: None,
            },
        };
        let json = serde_json::to_string(&env).expect("serialize");
        assert!(json.contains("\"schema\":\"ferrum.io/enforcement-event\""));
        assert!(json.contains("\"schemaVersion\":\"1.0\""));
        assert!(json.contains("\"bundleDigest\":\"sha256:abc\""));
        assert!(json.contains("\"agentRole\":\"observe\""));
        assert!(json.contains("\"degraded\":true"));
        assert!(json.contains("\"ts\":"));
        assert!(!json.contains("\"waiver\""));
        let back: EventEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.schema_version, EVENT_SCHEMA_VERSION);
        assert_eq!(back.node, "node-a");
        assert_eq!(back.ts, env.ts);
        assert_eq!(back.event.rule.to_string(), "no-shell");
        assert_eq!(back.event.waiver, None);
    }

    /// The two contract fields are required, and a record from somewhere else
    /// is refused rather than parsed.
    ///
    /// The refusal matters more than it looks. Every other field of this type
    /// is `Option` or has a `default`, so a JSON object carrying only `event`
    /// would otherwise decode into a perfectly plausible envelope with an
    /// invented timestamp — and the thing reading it is a SIEM ingest that
    /// would then have a record nobody produced.
    #[test]
    fn a_record_without_this_schema_and_version_does_not_decode() {
        let ok = serde_json::to_string(&envelope()).expect("serialize");
        serde_json::from_str::<EventEnvelope>(&ok).expect("its own output decodes");

        let no_version = ok.replace(r#""schemaVersion":"1.0","#, "");
        assert_ne!(no_version, ok, "the mutation matched nothing");
        assert!(
            serde_json::from_str::<EventEnvelope>(&no_version).is_err(),
            "a record with no schemaVersion decoded: absent is being read as 1.0, which is the \
             one thing a version must never mean"
        );

        let no_schema = ok.replace(&format!(r#""schema":"{EVENT_SCHEMA}","#), "");
        assert_ne!(no_schema, ok);
        assert!(serde_json::from_str::<EventEnvelope>(&no_schema).is_err());

        let foreign = ok.replace(EVENT_SCHEMA, "example.com/some-other-event");
        assert_ne!(foreign, ok);
        assert!(
            serde_json::from_str::<EventEnvelope>(&foreign).is_err(),
            "another producer's record decoded as ours because the field names lined up"
        );

        let unparseable = ok.replace(r#""schemaVersion":"1.0""#, r#""schemaVersion":"one""#);
        assert_ne!(unparseable, ok);
        assert!(serde_json::from_str::<EventEnvelope>(&unparseable).is_err());
    }

    /// `readable_by` is the question a consumer asks, and it has to answer it
    /// asymmetrically: a newer minor is readable, a newer major is not.
    #[test]
    fn a_newer_minor_is_readable_and_a_newer_major_is_not() {
        let v1_0 = SchemaVersion { major: 1, minor: 0 };
        let v1_2 = SchemaVersion { major: 1, minor: 2 };
        let v2_0 = SchemaVersion { major: 2, minor: 0 };
        assert!(v1_0.readable_by(v1_2), "an older record must stay readable");
        assert!(
            !v1_2.readable_by(v1_0),
            "a reader cannot promise a field it has never seen"
        );
        assert!(!v2_0.readable_by(v1_2));
        assert!(
            !v1_2.readable_by(v2_0),
            "a major bump is a break in both directions"
        );
        assert_eq!("1.2".parse::<SchemaVersion>().expect("parse"), v1_2);
        assert_eq!(v1_2.to_string(), "1.2");
        assert!("1".parse::<SchemaVersion>().is_err());
    }

    /// All three flags are per-record: a reader of one event must be able to
    /// tell a match taken on an unobserved path, unresolved labels or an
    /// unproven container from a proven one. Records written before the fields
    /// existed still decode.
    #[test]
    fn unknown_flags_round_trip_and_default_on_legacy_records() {
        let mut ev = EnforcementEvent {
            policy: PolicyId::new("p"),
            rule: RuleId::new("no-runtime-sock"),
            action: "kill".into(),
            image_digest: None,
            pod: "web".into(),
            namespace: "payments".into(),
            comm: "curl".into(),
            syscall: "openat".into(),
            pid: 7,
            tgid: 7,
            executed: true,
            respond_error: None,
            labels_unknown: true,
            path_unknown: true,
            container_unknown: true,
            waiver: None,
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        assert!(json.contains("\"labelsUnknown\":true"));
        assert!(json.contains("\"pathUnknown\":true"));
        assert!(json.contains("\"containerUnknown\":true"));
        let back: EnforcementEvent = serde_json::from_str(&json).expect("deserialize");
        assert!(back.labels_unknown);
        assert!(back.path_unknown);
        assert!(back.container_unknown);

        ev.labels_unknown = false;
        ev.path_unknown = false;
        ev.container_unknown = false;
        let json = serde_json::to_string(&ev).expect("serialize");
        assert!(json.contains("\"pathUnknown\":false"));
        assert!(json.contains("\"containerUnknown\":false"));

        let legacy = r#"{"policy":"p","rule":"r","action":"kill","imageDigest":null,
            "pod":"w","namespace":"n","comm":"sh","syscall":"execve"}"#;
        let back: EnforcementEvent = serde_json::from_str(legacy).expect("deserialize");
        assert!(!back.labels_unknown);
        assert!(!back.path_unknown);
        assert!(!back.container_unknown);
    }

    #[test]
    fn waiver_ref_camel_case_and_absent_field_decodes() {
        let ev = EnforcementEvent {
            policy: PolicyId::new("p"),
            rule: RuleId::new("no-runtime-sock"),
            action: "waived".into(),
            image_digest: None,
            pod: "web".into(),
            namespace: "payments".into(),
            comm: "curl".into(),
            syscall: "openat".into(),
            pid: 7,
            tgid: 7,
            executed: false,
            labels_unknown: false,
            path_unknown: false,
            container_unknown: false,
            respond_error: None,
            waiver: Some(WaiverRef {
                ticket: "JIRA-1".into(),
                requested_by: "sre".into(),
                approved_by: "sec-arch".into(),
                expires_at: Utc::now(),
            }),
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        assert!(json.contains("\"waiver\":{\"ticket\":\"JIRA-1\""));
        assert!(json.contains("\"requestedBy\":\"sre\""));
        assert!(json.contains("\"approvedBy\":\"sec-arch\""));
        assert!(json.contains("\"expiresAt\":"));
        // Pre-waiver records (no `waiver` key) still decode.
        let legacy = r#"{"policy":"p","rule":"r","action":"kill","imageDigest":null,
            "pod":"w","namespace":"n","comm":"sh","syscall":"execve"}"#;
        let back: EnforcementEvent = serde_json::from_str(legacy).expect("deserialize");
        assert_eq!(back.waiver, None);
        assert_eq!(back.tgid, 0);
        assert!(!back.executed);
        assert_eq!(back.respond_error, None);
    }
}
