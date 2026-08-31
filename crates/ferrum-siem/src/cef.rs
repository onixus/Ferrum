//! ArcSight CEF 0, wrapped in an RFC 5424 frame.
//!
//! The frame is not decoration: a CEF connector's syslog input reads a syslog
//! line and finds `CEF:0` inside it, so a bare CEF payload sent to a syslog
//! port arrives with no timestamp and no host of its own and is stamped with
//! the collector's. The header this crate writes carries the *node's* time and
//! name, which is the pair an investigation joins on.
//!
//! Two escaping domains, and they are different, which is the classic way CEF
//! goes wrong: in the seven header fields `\` and `|` are escaped, and in the
//! extension `\`, `=` and newline are. A value escaped for the wrong half
//! either swallows the next field or ends the record.
//!
//! Keys: the CEF dictionary where it has one (`rt`, `act`, `outcome`,
//! `dvchost`, `sproc`, `spid`, `cs1..cs6` with their labels), and
//! `ferrum`-prefixed custom keys for the rest. The alternative was folding
//! eight fields into the six `cs` slots, which is how a connector ends up
//! parsing `cs4` as two things depending on the rule that fired.

use ferrum_proto::EventEnvelope;

use crate::{message, rfc5424, sanitize, severity};

/// Vendor/product/version triple. The version is this crate's, i.e. the
/// agent's: a connector keys its parser on all three, so it must move when the
/// record shape moves and not when a release is cut for other reasons.
const VENDOR: &str = "Ferrum";
const PRODUCT: &str = "ferrum";
const DEVICE_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn render(envelope: &EventEnvelope) -> String {
    let e = &envelope.event;
    let sev = severity(&e.action, e.executed);
    let mut ext = Extension::default();
    ext.put("rt", &envelope.ts.timestamp_millis().to_string());
    ext.put("dvchost", &sanitize(&envelope.node));
    ext.put("act", &sanitize(&e.action));
    ext.put("outcome", if e.executed { "success" } else { "failure" });
    ext.put("sproc", &sanitize(&e.comm));
    ext.put("spid", &e.pid.to_string());
    ext.labelled("cs1", "ferrumPolicy", &sanitize(e.policy.as_str()));
    ext.labelled("cs2", "ferrumNamespace", &sanitize(&e.namespace));
    ext.labelled("cs3", "ferrumPod", &sanitize(&e.pod));
    ext.labelled("cs4", "ferrumSyscall", &sanitize(&e.syscall));
    ext.labelled(
        "cs5",
        "ferrumBundleDigest",
        &envelope
            .bundle_digest
            .as_ref()
            .map(|d| sanitize(d.as_str()))
            .unwrap_or_default(),
    );
    ext.labelled(
        "cs6",
        "ferrumImageDigest",
        &e.image_digest
            .as_ref()
            .map(|d| sanitize(d.as_str()))
            .unwrap_or_default(),
    );
    ext.put("cn1Label", "ferrumTgid");
    ext.put("cn1", &e.tgid.to_string());
    ext.put("ferrumSchema", &envelope.schema.to_string());
    ext.put("ferrumSchemaVersion", &envelope.schema_version.to_string());
    ext.put("ferrumAgentRole", &sanitize(&envelope.agent_role));
    ext.put("ferrumDegraded", bool_text(envelope.degraded));
    ext.put(
        "ferrumDegradedReasons",
        &crate::degraded_reasons_text(envelope),
    );
    ext.put("ferrumExecuted", bool_text(e.executed));
    ext.put("ferrumLabelsUnknown", bool_text(e.labels_unknown));
    ext.put("ferrumPathUnknown", bool_text(e.path_unknown));
    ext.put("ferrumContainerUnknown", bool_text(e.container_unknown));
    if let Some(reason) = &e.respond_error {
        ext.put("ferrumRespondError", &sanitize(reason));
    }
    if let Some(waiver) = &e.waiver {
        // requestedBy and approvedBy are absent on purpose. See `FIELDS`.
        ext.put("ferrumWaiverTicket", &sanitize(&waiver.ticket));
        ext.put(
            "ferrumWaiverExpiresAt",
            &waiver
                .expires_at
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        );
    }
    ext.put("msg", &message(envelope));

    let payload = format!(
        "CEF:0|{vendor}|{product}|{version}|{signature}|{name}|{sev}|{ext}",
        vendor = escape_header(VENDOR),
        product = escape_header(PRODUCT),
        version = escape_header(DEVICE_VERSION),
        signature = escape_header(&sanitize(e.rule.as_str())),
        name = escape_header(&sanitize(&e.action)),
        sev = sev,
        ext = ext.0,
    );
    // NILVALUE for STRUCTURED-DATA: the record is the CEF payload, and a
    // connector that found both would have two copies to disagree about.
    rfc5424::frame(envelope, sev, "-", &payload)
}

fn bool_text(flag: bool) -> &'static str {
    if flag {
        "true"
    } else {
        "false"
    }
}

#[derive(Default)]
struct Extension(String);

impl Extension {
    /// `key=value`, space separated. Escaping happens here and only here, so
    /// there is one place to be wrong and no call site can forget — including
    /// `msg`, whose text is full of `=` and must be escaped exactly once.
    fn put(&mut self, key: &str, value: &str) {
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        self.0.push_str(key);
        self.0.push('=');
        self.0.push_str(&escape_extension_value(value));
    }

    fn labelled(&mut self, slot: &str, label: &str, value: &str) {
        self.put(&format!("{slot}Label"), label);
        self.put(slot, value);
    }
}

/// Header fields: `\` and `|`.
fn escape_header(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch == '\\' || ch == '|' {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Extension values: `\` and `=`. A newline would end the record, and
/// `sanitize` has already turned every one of them into `\x0a` before this is
/// reached — this function escapes the backslash that produced.
fn escape_extension_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch == '\\' || ch == '=' {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::tests::envelope;
    use crate::Profile;

    #[test]
    fn the_header_carries_the_rule_as_the_signature_and_the_action_as_the_name() {
        let text = Profile::Cef.render(&envelope());
        let at = text.find("CEF:0|").expect("no CEF payload in the frame");
        let fields: Vec<&str> = text[at..].splitn(8, '|').collect();
        assert_eq!(fields[1], "Ferrum");
        assert_eq!(fields[2], "ferrum");
        assert_eq!(fields[4], "no-shell", "signature id must be the rule");
        assert_eq!(fields[5], "kill");
        assert_eq!(fields[6], "9", "an executed kill is the top of the scale");
        assert!(fields[7].contains("cs1Label=ferrumPolicy cs1=prod-restricted"));
        assert!(fields[7].contains("act=kill"));
        assert!(fields[7].contains("outcome=success"));
    }

    /// Split a CEF prefix the way a connector does: on `|` that is not
    /// preceded by a backslash. A naive `split('|')` is exactly the parser
    /// this escaping exists to protect, so the test must not use one — it
    /// would report an escaped pipe as a moved field and a *missing* escape as
    /// correct.
    fn header_fields(payload: &str) -> Vec<String> {
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

    /// A pipe in a header field would add a field; an `=` in an extension
    /// value would end one. Both are reachable from a workload-chosen `comm`
    /// and from an operator-chosen policy name.
    #[test]
    fn a_pipe_in_a_header_and_an_equals_in_an_extension_do_not_move_a_field() {
        let mut env = envelope();
        env.event.rule = ferrum_ids::RuleId::new("no|shell");
        env.event.comm = "a=b".into();
        let text = Profile::Cef.render(&env);
        let at = text.find("CEF:0|").expect("payload");
        let fields = header_fields(&text[at..]);
        assert_eq!(fields[4], "no|shell", "the parser must see one field back");
        assert_eq!(fields[5], "kill", "the pipe shifted a field: {text}");
        assert_eq!(fields[6], "9");
        assert!(text.contains("sproc=a\\=b"), "{text}");

        // The control: without the escape the same input moves the fields, so
        // the assertion above is about the escaping and not about the splitter.
        let unescaped = text.replace("no\\|shell", "no|shell");
        let at = unescaped.find("CEF:0|").expect("payload");
        assert_ne!(
            header_fields(&unescaped[at..])[5],
            "kill",
            "the splitter cannot tell an escaped pipe from a bare one, so it proves nothing"
        );
    }
}
