//! Read-only claims about an [`EnforcementEvent`].
//!
//! Nothing here is written onto the record. The syscall has already finished
//! before userspace signals, so a delivered `kill` is not prevention of that
//! syscall. `deny` and `isolate` carry neither an errno nor a process outcome,
//! so they are not containment either.

use crate::EnforcementEvent;

/// True only for `audit`, `waived`, `kill`, `deny`, and `isolate`.
pub fn detection(event: &EnforcementEvent) -> bool {
    matches!(
        event.action.as_str(),
        "audit" | "waived" | "kill" | "deny" | "isolate"
    )
}

/// Delivered `kill` only. The syscall name is not consulted.
///
/// A waiver forces this false even when `action` is still `kill` and
/// `executed` is set. So does any `respond_error`, including one set beside
/// `executed == true`. An empty syscall or `tgid == 0` is not a delivered kill.
pub fn containment(event: &EnforcementEvent) -> bool {
    event.action == "kill"
        && event.waiver.is_none()
        && event.executed
        && event.respond_error.is_none()
        && !event.syscall.is_empty()
        && event.tgid != 0
}

/// Always false. No argument is taken, because none would change the answer.
pub const fn prevention() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::{containment, detection, prevention};
    use crate::{
        EnforcementEvent, EventEnvelope, PolicyId, RuleId, SchemaId, WaiverRef,
        EVENT_SCHEMA_VERSION,
    };
    use chrono::{DateTime, Utc};

    fn record(action: &str) -> EnforcementEvent {
        EnforcementEvent {
            policy: PolicyId::new("p"),
            rule: RuleId::new("no-shell"),
            action: action.into(),
            image_digest: None,
            pod: "web".into(),
            namespace: "prod".into(),
            comm: "sh".into(),
            syscall: "execve".into(),
            pid: 42,
            tgid: 42,
            executed: true,
            respond_error: None,
            labels_unknown: false,
            path_unknown: false,
            container_unknown: false,
            waiver: None,
        }
    }

    fn waiver() -> WaiverRef {
        WaiverRef {
            ticket: "SEC-44".into(),
            requested_by: "sre".into(),
            approved_by: "sec-arch".into(),
            expires_at: "2026-12-01T00:00:00Z"
                .parse::<DateTime<Utc>>()
                .expect("expiry"),
        }
    }

    fn envelope(event: EnforcementEvent) -> EventEnvelope {
        EventEnvelope {
            schema: SchemaId,
            schema_version: EVENT_SCHEMA_VERSION,
            ts: "2026-11-11T00:00:00Z".parse::<DateTime<Utc>>().expect("ts"),
            node: "node-a".into(),
            bundle_digest: None,
            agent_role: "respond".into(),
            degraded: false,
            degraded_reasons: Vec::new(),
            event,
        }
    }

    #[track_caller]
    fn assert_claims(event: &EnforcementEvent, is_detection: bool, is_containment: bool) {
        assert_eq!(
            detection(event),
            is_detection,
            "action {:?} executed {} tgid {} syscall {:?} err {:?} waiver {}",
            event.action,
            event.executed,
            event.tgid,
            event.syscall,
            event.respond_error,
            event.waiver.is_some()
        );
        assert_eq!(
            containment(event),
            is_containment,
            "action {:?}",
            event.action
        );
        assert!(!prevention());
    }

    #[test]
    fn detection_only_for_audit_waived_kill_deny_isolate() {
        for action in ["audit", "waived", "kill", "deny", "isolate"] {
            let event = record(action);
            assert_claims(&event, true, action == "kill");
        }
    }

    #[test]
    fn allow_empty_and_unknown_actions_support_nothing() {
        for action in ["allow", "", " ", "unknown", "Kill", "prevent", "observe"] {
            let mut event = record(action);
            event.executed = true;
            event.syscall = "execve".into();
            event.tgid = 9;
            event.respond_error = None;
            assert_claims(&event, false, false);
        }
    }

    #[test]
    fn containment_is_a_delivered_kill_and_ignores_syscall_name() {
        for syscall in ["execve", "openat", "bpf", "init_module", "unshare"] {
            let mut event = record("kill");
            event.syscall = syscall.into();
            event.pid = 0;
            event.tgid = 1;
            event.labels_unknown = true;
            event.path_unknown = true;
            event.container_unknown = true;
            assert_claims(&event, true, true);
        }

        let mut wide = record("kill");
        wide.tgid = u32::MAX;
        wide.syscall = "write".into();
        assert_claims(&wide, true, true);
    }

    #[test]
    fn undelivered_or_errored_kill_is_not_containment() {
        let mut quiet = record("kill");
        quiet.executed = false;
        quiet.respond_error = None;
        assert_claims(&quiet, true, false);

        let mut refused = record("kill");
        refused.executed = false;
        refused.respond_error = Some("role".into());
        assert_claims(&refused, true, false);

        let mut both = record("kill");
        both.executed = true;
        both.respond_error = Some("esrch".into());
        assert_claims(&both, true, false);

        let mut empty_err = record("kill");
        empty_err.executed = true;
        empty_err.respond_error = Some(String::new());
        assert_claims(&empty_err, true, false);
    }

    #[test]
    fn waiver_and_waived_are_not_containment() {
        let mut waived = record("waived");
        waived.executed = true;
        waived.waiver = Some(waiver());
        assert_claims(&waived, true, false);

        let mut waived_bare = record("waived");
        waived_bare.executed = true;
        waived_bare.waiver = None;
        assert_claims(&waived_bare, true, false);

        let mut kill = record("kill");
        kill.executed = true;
        kill.waiver = Some(waiver());
        kill.respond_error = None;
        kill.tgid = 7;
        kill.syscall = "execve".into();
        assert_claims(&kill, true, false);
    }

    #[test]
    fn deny_and_isolate_are_neither_containment_nor_prevention() {
        for action in ["deny", "isolate"] {
            let mut event = record(action);
            event.executed = true;
            event.respond_error = None;
            event.syscall = "bpf".into();
            event.tgid = 4;
            assert_claims(&event, true, false);

            event.executed = false;
            event.respond_error = Some("not enforceable".into());
            assert_claims(&event, true, false);
        }
        assert!(!prevention());
    }

    #[test]
    fn tgid_zero_or_empty_syscall_is_not_containment() {
        let mut tgid = record("kill");
        tgid.tgid = 0;
        tgid.pid = 99;
        tgid.executed = true;
        tgid.syscall = "execve".into();
        assert_claims(&tgid, true, false);

        let mut syscall = record("kill");
        syscall.syscall.clear();
        syscall.tgid = 5;
        syscall.executed = true;
        assert_claims(&syscall, true, false);

        let mut neither = record("kill");
        neither.tgid = 0;
        neither.syscall.clear();
        neither.executed = false;
        neither.respond_error = Some("gone".into());
        assert_claims(&neither, true, false);
    }

    #[test]
    fn prevention_is_false_with_no_input() {
        for action in ["kill", "deny", "isolate", "waived", "allow", ""] {
            let event = record(action);
            assert_eq!(
                (detection(&event), containment(&event), prevention()),
                (
                    matches!(action, "kill" | "deny" | "isolate" | "waived"),
                    action == "kill",
                    false
                ),
                "{action:?}"
            );
        }
    }

    #[test]
    fn serialized_envelope_has_no_outcome_containment_or_prevention_key() {
        assert_eq!(
            EVENT_SCHEMA_VERSION,
            crate::SchemaVersion { major: 1, minor: 1 }
        );

        let mut event = record("kill");
        event.labels_unknown = true;
        event.path_unknown = false;
        event.container_unknown = false;
        assert!(detection(&event));
        assert!(containment(&event));
        assert!(!prevention());

        let json = serde_json::to_string(&envelope(event.clone())).expect("serialize");
        assert!(json.contains("\"schemaVersion\":\"1.1\""), "{json}");
        for key in ["outcome", "containment", "prevention", "detection"] {
            assert!(
                !json.contains(&format!("\"{key}\"")),
                "{key} leaked onto the wire: {json}"
            );
        }
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        let mut envelope_keys: Vec<&str> = value
            .as_object()
            .expect("envelope")
            .keys()
            .map(String::as_str)
            .collect();
        envelope_keys.sort_unstable();
        assert_eq!(
            envelope_keys,
            [
                "agentRole",
                "bundleDigest",
                "degraded",
                "degradedReasons",
                "event",
                "node",
                "schema",
                "schemaVersion",
                "ts",
            ]
        );
        let mut event_keys: Vec<&str> = value["event"]
            .as_object()
            .expect("event")
            .keys()
            .map(String::as_str)
            .collect();
        event_keys.sort_unstable();
        assert_eq!(
            event_keys,
            [
                "action",
                "comm",
                "containerUnknown",
                "executed",
                "imageDigest",
                "labelsUnknown",
                "namespace",
                "pathUnknown",
                "pid",
                "pod",
                "policy",
                "rule",
                "syscall",
                "tgid",
            ]
        );
        let back: EventEnvelope = serde_json::from_str(&json).expect("decode");
        assert_eq!(back.schema_version.to_string(), "1.1");
        assert_eq!(back.event.action, "kill");
        assert!(back.event.executed);
        assert_eq!(back.event.respond_error, None);
        assert!(back.event.waiver.is_none());
        assert_eq!(back.event.tgid, event.tgid);
        assert_eq!(back.event.syscall, event.syscall);

        let mut waived = record("kill");
        waived.waiver = Some(waiver());
        waived.respond_error = Some("waived".into());
        waived.executed = true;
        assert!(!containment(&waived));
        let waived_json = serde_json::to_string(&envelope(waived)).expect("serialize");
        assert!(waived_json.contains("\"waiver\""));
        assert!(waived_json.contains("\"respondError\""));
        for key in ["outcome", "containment", "prevention", "detection"] {
            assert!(
                !waived_json.contains(&format!("\"{key}\"")),
                "{key} leaked onto the waived record: {waived_json}"
            );
        }
    }
}
