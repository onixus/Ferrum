//! RFC 5424, with the record in a structured-data element.
//!
//! This is the profile for a receiver nobody wrote an integration for: the
//! whole record is `[ferrum@32473 key="value" ...]`, which every syslog daemon
//! in use parses into key/value pairs without a regex written by whoever is on
//! call. The human sentence stays in MSG, where a person reading a raw log
//! finds it.
//!
//! # The enterprise number
//!
//! An SD-ID outside the four IANA-registered ones must be `name@<PEN>`, where
//! PEN is an IANA Private Enterprise Number. This project does not have one.
//! 32473 is the PEN IANA reserves for documentation and examples (RFC 5612),
//! and using it is the honest choice available: it says "this identifier is
//! not registered" to anyone who looks it up, where an invented number would
//! collide with whoever actually holds it. When FERRUM registers a PEN, this
//! constant changes and every consumer's SD-ID changes with it — which is a
//! schema break and is treated as one.
//!
//! # Framing
//!
//! One record per line, LF-terminated (RFC 6587 §3.4.2, "non-transparent
//! framing"). Octet counting is not implemented, and that is a limitation
//! rather than a preference: it is what a receiver configured for
//! `octet-counted` needs, and a record sent the other way to such a receiver is
//! dropped by it. The one thing that makes LF framing safe here is that no
//! rendered value can contain an LF — see `sanitize`.

use ferrum_proto::EventEnvelope;

use crate::{message, sanitize};

/// IANA's documentation/example PEN. See the module docs.
pub const ENTERPRISE_NUMBER: u32 = 32473;
/// SD-ID of the element carrying the whole record.
pub const SD_ID: &str = "ferrum@32473";
/// APP-NAME. The agent is the only producer today; the field exists so a
/// second one does not have to be told apart by its fields.
pub const APP_NAME: &str = "ferrum-agent";
/// MSGID: the record type, not the record. A second message type from this
/// producer gets its own and the receiver filters on it.
pub const MSG_ID: &str = "enforcement";
/// local0. A configurable facility was refused: it is a routing knob on the
/// receiver's side, and the one thing it can do here is make two nodes of one
/// fleet land in different files.
pub const FACILITY: u8 = 16;

/// Syslog severity from the CEF-scale severity the profiles share.
///
/// Squeezing 0..10 into 0..7 loses resolution, and that is fine: syslog
/// severity decides routing and paging, and the finer number rides along in
/// the record.
pub fn syslog_severity(cef_severity: u8) -> u8 {
    match cef_severity {
        9..=10 => 3, // error: enforcement happened
        7..=8 => 4,  // warning: enforcement was decided and did not happen
        4..=6 => 5,  // notice
        _ => 6,      // informational
    }
}

/// Wrap a structured-data element and a message in an RFC 5424 header. Shared
/// with the CEF profile, which passes NILVALUE for the element and its whole
/// payload as the message.
///
/// PROCID is NILVALUE: the pid of the agent process is not the pid of anything
/// in the record, and a receiver that groups by PROCID would be grouping by
/// "which restart of the DaemonSet reported this".
pub fn frame(
    envelope: &EventEnvelope,
    cef_severity: u8,
    structured_data: &str,
    msg: &str,
) -> String {
    let pri = u16::from(FACILITY) * 8 + u16::from(syslog_severity(cef_severity));
    format!(
        "<{pri}>1 {ts} {host} {app} - {msgid} {sd} {msg}",
        ts = envelope
            .ts
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        host = hostname(&envelope.node),
        app = APP_NAME,
        msgid = MSG_ID,
        sd = structured_data,
    )
}

/// HOSTNAME must be a single printable token; a node name with a space in it
/// would end the field early. `-` is the RFC's NILVALUE and is what an unknown
/// host is spelled as.
fn hostname(node: &str) -> String {
    let cleaned: String = sanitize(node)
        .chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .collect();
    if cleaned.is_empty() {
        "-".to_string()
    } else {
        cleaned
    }
}

pub fn render(envelope: &EventEnvelope) -> String {
    let e = &envelope.event;
    let sev = crate::severity(&e.action, e.executed);
    let mut sd = Element::new(SD_ID);
    sd.put("schema", &envelope.schema.to_string());
    sd.put("schemaVersion", &envelope.schema_version.to_string());
    sd.put("node", &sanitize(&envelope.node));
    sd.put("agentRole", &sanitize(&envelope.agent_role));
    sd.put("degraded", bool_text(envelope.degraded));
    sd.put("degradedReasons", &crate::degraded_reasons_text(envelope));
    sd.put(
        "bundleDigest",
        &envelope
            .bundle_digest
            .as_ref()
            .map(|d| sanitize(d.as_str()))
            .unwrap_or_default(),
    );
    sd.put("policy", &sanitize(e.policy.as_str()));
    sd.put("rule", &sanitize(e.rule.as_str()));
    sd.put("action", &sanitize(&e.action));
    sd.put(
        "imageDigest",
        &e.image_digest
            .as_ref()
            .map(|d| sanitize(d.as_str()))
            .unwrap_or_default(),
    );
    sd.put("namespace", &sanitize(&e.namespace));
    sd.put("pod", &sanitize(&e.pod));
    sd.put("comm", &sanitize(&e.comm));
    sd.put("syscall", &sanitize(&e.syscall));
    sd.put("pid", &e.pid.to_string());
    sd.put("tgid", &e.tgid.to_string());
    sd.put("executed", bool_text(e.executed));
    sd.put("labelsUnknown", bool_text(e.labels_unknown));
    sd.put("pathUnknown", bool_text(e.path_unknown));
    sd.put("containerUnknown", bool_text(e.container_unknown));
    if let Some(reason) = &e.respond_error {
        sd.put("respondError", &sanitize(reason));
    }
    if let Some(waiver) = &e.waiver {
        // requestedBy and approvedBy are absent on purpose. See `FIELDS`.
        sd.put("waiverTicket", &sanitize(&waiver.ticket));
        sd.put(
            "waiverExpiresAt",
            &waiver
                .expires_at
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
    }
    frame(envelope, sev, &sd.close(), &message(envelope))
}

fn bool_text(flag: bool) -> &'static str {
    if flag {
        "true"
    } else {
        "false"
    }
}

struct Element(String);

impl Element {
    fn new(sd_id: &str) -> Element {
        Element(format!("[{sd_id}"))
    }

    /// PARAM-VALUE escaping, RFC 5424 §6.3.3: `"`, `\` and `]`. Nothing else,
    /// and in particular not the whole value — a receiver un-escapes exactly
    /// these three.
    fn put(&mut self, name: &str, value: &str) {
        self.0.push(' ');
        self.0.push_str(name);
        self.0.push_str("=\"");
        for ch in value.chars() {
            if ch == '"' || ch == '\\' || ch == ']' {
                self.0.push('\\');
            }
            self.0.push(ch);
        }
        self.0.push('"');
    }

    fn close(self) -> String {
        format!("{}]", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::envelope;
    use crate::Profile;

    #[test]
    fn the_header_is_a_valid_rfc_5424_prefix_carrying_the_node_time_and_name() {
        let text = Profile::Rfc5424.render(&envelope());
        assert!(text.starts_with("<131>1 "), "{text}");
        let fields: Vec<&str> = text.splitn(7, ' ').collect();
        assert_eq!(fields[1], "2026-08-31T12:00:00.000Z");
        assert_eq!(fields[2], "node-a");
        assert_eq!(fields[3], APP_NAME);
        assert_eq!(fields[4], "-", "PROCID is NILVALUE");
        assert_eq!(fields[5], MSG_ID);
        assert!(
            fields[6].starts_with("[ferrum@32473 "),
            "STRUCTURED-DATA is not in the STRUCTURED-DATA position: {text}"
        );
        assert!(text.contains(r#"[ferrum@32473 schema="ferrum.io/enforcement-event""#));
        assert!(text.contains(r#"rule="no-shell""#));
    }

    /// `]` ends the element and `"` ends the value. Both are typeable into a
    /// pod name's neighbourhood and into a policy name outright.
    #[test]
    fn a_bracket_or_a_quote_in_a_value_cannot_close_the_element_early() {
        let mut env = envelope();
        env.event.pod = r#"a"]b"#.into();
        let text = Profile::Rfc5424.render(&env);
        assert!(text.contains(r#"pod="a\"\]b""#), "{text}");
        // Exactly one element, and it closes where this crate closed it.
        assert_eq!(text.matches("[ferrum@32473").count(), 1);
        let sd_end = text.find("\"]").expect("element must close") + 2;
        assert!(
            text[..sd_end].contains(r#"containerUnknown="false""#),
            "the element closed before the last key it was supposed to carry: {text}"
        );
    }

    /// The SD-ID and the enterprise number are one fact spelled twice, because
    /// `concat!` over a `u32` is not a const expression. This is the check that
    /// keeps the two halves from drifting apart.
    #[test]
    fn the_sd_id_carries_the_enterprise_number_it_names() {
        assert_eq!(SD_ID, format!("ferrum@{ENTERPRISE_NUMBER}"));
    }

    #[test]
    fn severity_maps_an_executed_kill_to_error_and_an_allow_to_informational() {
        assert_eq!(syslog_severity(crate::severity("kill", true)), 3);
        assert_eq!(syslog_severity(crate::severity("kill", false)), 4);
        assert_eq!(syslog_severity(crate::severity("allow", false)), 6);
    }
}
