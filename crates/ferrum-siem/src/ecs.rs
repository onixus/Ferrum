//! Elastic Common Schema, one JSON object per line.
//!
//! Two halves, and keeping them apart is the point. The ECS half uses ECS
//! field names with ECS meanings, so an Elastic or OpenSearch index template
//! maps it with no work and a Splunk input with `KV_MODE=json` searches it with
//! no app installed. The `ferrum` half is everything ECS has no field for, in
//! one namespace, so nothing of ours is put into an ECS field whose meaning is
//! nearly-but-not-quite ours — which is how a shared dashboard ends up
//! counting two different things.
//!
//! Escaping is `serde_json`'s, not this file's. That is deliberate: the two
//! syslog profiles hand-escape because their formats have no serialiser, and
//! this one must not acquire a fourth hand-rolled escaper for a format that
//! already has one.

use ferrum_proto::EventEnvelope;
use serde_json::{json, Map, Value};

use crate::{message, sanitize, severity};

/// The ECS version these field names are taken from. Published in the record:
/// ECS is versioned, consumers pin to it, and a receiver that knows which
/// version it is reading can map an older one.
pub const ECS_VERSION: &str = "8.11.0";
/// `event.dataset`, the ECS name for "which stream is this".
pub const DATASET: &str = "ferrum.enforcement";

pub fn render(envelope: &EventEnvelope) -> String {
    let e = &envelope.event;
    let sev = severity(&e.action, e.executed);

    let mut ferrum = Map::new();
    ferrum.insert("schema".into(), json!(envelope.schema.to_string()));
    ferrum.insert(
        "schemaVersion".into(),
        json!(envelope.schema_version.to_string()),
    );
    ferrum.insert("agentRole".into(), json!(sanitize(&envelope.agent_role)));
    ferrum.insert("degraded".into(), json!(envelope.degraded));
    // An array here and a joined string in the two syslog profiles: this one
    // has a serialiser and a receiver that indexes arrays, and the other two
    // have neither.
    ferrum.insert(
        "degradedReasons".into(),
        json!(envelope
            .degraded_reasons
            .iter()
            .map(|r| sanitize(r))
            .collect::<Vec<_>>()),
    );
    ferrum.insert(
        "bundleDigest".into(),
        match &envelope.bundle_digest {
            Some(d) => json!(sanitize(d.as_str())),
            None => Value::Null,
        },
    );
    ferrum.insert("policy".into(), json!(sanitize(e.policy.as_str())));
    ferrum.insert("rule".into(), json!(sanitize(e.rule.as_str())));
    ferrum.insert("action".into(), json!(sanitize(&e.action)));
    ferrum.insert("syscall".into(), json!(sanitize(&e.syscall)));
    ferrum.insert("tgid".into(), json!(e.tgid));
    ferrum.insert("executed".into(), json!(e.executed));
    ferrum.insert("labelsUnknown".into(), json!(e.labels_unknown));
    ferrum.insert("pathUnknown".into(), json!(e.path_unknown));
    ferrum.insert("containerUnknown".into(), json!(e.container_unknown));
    ferrum.insert(
        "respondError".into(),
        match &e.respond_error {
            Some(reason) => json!(sanitize(reason)),
            None => Value::Null,
        },
    );
    // requestedBy and approvedBy are absent on purpose. See `FIELDS`.
    ferrum.insert(
        "waiver".into(),
        match &e.waiver {
            Some(waiver) => json!({
                "ticket": sanitize(&waiver.ticket),
                "expiresAt": waiver
                    .expires_at
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            }),
            None => Value::Null,
        },
    );

    let record = json!({
        "@timestamp": envelope.ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "ecs": { "version": ECS_VERSION },
        "event": {
            "kind": "alert",
            "category": ["process"],
            // `denied` and `allowed` are ECS's own event.type values, and the
            // record's action decides which: an audit record that claimed
            // `denied` would be counted as enforcement by every ECS dashboard
            // that exists.
            "type": [ecs_type(&e.action)],
            "action": sanitize(&e.action),
            "outcome": if e.executed { "success" } else { "failure" },
            "dataset": DATASET,
            "module": "ferrum",
            "provider": crate::rfc5424::APP_NAME,
            "severity": sev,
        },
        "host": { "name": sanitize(&envelope.node) },
        "orchestrator": {
            "type": "kubernetes",
            "namespace": sanitize(&e.namespace),
            "resource": { "type": "pod", "name": sanitize(&e.pod) },
        },
        "process": { "name": sanitize(&e.comm), "pid": e.pid },
        "container": {
            "image": match &e.image_digest {
                Some(d) => json!({ "hash": { "all": [sanitize(d.as_str())] } }),
                None => Value::Null,
            },
        },
        "rule": { "id": sanitize(e.rule.as_str()), "ruleset": sanitize(e.policy.as_str()) },
        "message": message(envelope),
        "ferrum": Value::Object(ferrum),
    });
    // `to_string`, never `to_string_pretty`: the framing is one record per
    // line, and a pretty object is as many records as it has lines.
    record.to_string()
}

fn ecs_type(action: &str) -> &'static str {
    match action {
        "kill" | "isolate" | "deny" => "denied",
        "waived" | "allow" => "allowed",
        // `info` is ECS's own value for "something happened and nothing was
        // decided about access", which is what an audit record is.
        _ => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::envelope;
    use crate::Profile;

    #[test]
    fn one_record_is_one_line_of_valid_json_in_ecs_field_names() {
        let text = Profile::Ecs.render(&envelope());
        assert!(
            !text.contains('\n'),
            "a pretty-printed record is many records"
        );
        let doc: Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(doc["@timestamp"], json!("2026-08-31T12:00:00.000Z"));
        assert_eq!(doc["ecs"]["version"], json!(ECS_VERSION));
        assert_eq!(doc["event"]["kind"], json!("alert"));
        assert_eq!(doc["event"]["type"], json!(["denied"]));
        assert_eq!(doc["event"]["outcome"], json!("success"));
        assert_eq!(doc["host"]["name"], json!("node-a"));
        assert_eq!(doc["orchestrator"]["namespace"], json!("payments"));
        assert_eq!(doc["orchestrator"]["resource"]["name"], json!("web-7f"));
        assert_eq!(doc["process"]["pid"], json!(4242));
        assert_eq!(doc["rule"]["id"], json!("no-shell"));
        assert_eq!(doc["rule"]["ruleset"], json!("prod-restricted"));
        assert_eq!(
            doc["ferrum"]["schemaVersion"],
            json!(ferrum_proto::EVENT_SCHEMA_VERSION.to_string())
        );
        // An array here rather than the joined string the two syslog profiles
        // carry: this receiver indexes arrays, and a rule filtering on one
        // reason must not have to match a substring of a joined field.
        assert_eq!(
            doc["ferrum"]["degradedReasons"],
            json!(["lkg_partial", "clock_rollback"])
        );
    }

    /// A record whose values carry quotes and braces stays one JSON document.
    /// The serialiser is what makes that true, and this is the test that says
    /// so rather than assuming it.
    #[test]
    fn a_quote_in_a_value_does_not_end_the_document() {
        let mut env = envelope();
        env.event.comm = r#"a"}{b"#.into();
        let text = Profile::Ecs.render(&env);
        let doc: Value = serde_json::from_str(&text).expect("still one document");
        assert_eq!(doc["process"]["name"], json!(r#"a"}{b"#));
    }

    /// An audit record must not be counted as enforcement by a dashboard that
    /// filters on `event.type`.
    #[test]
    fn the_ecs_type_separates_a_decision_from_an_observation() {
        assert_eq!(ecs_type("kill"), "denied");
        assert_eq!(ecs_type("deny"), "denied");
        assert_eq!(ecs_type("allow"), "allowed");
        assert_eq!(ecs_type("audit"), "info");
    }
}
