//! Enforcement events, normalised for somebody else's system.
//!
//! Why a crate of its own rather than a module in `ferrum-export`: the
//! boundary table in `AGENTS.md` gives that crate a JSONL sink and a bounded
//! queue, and a socket is neither. It is the same call `ferrum-metrics` got —
//! the surface that talks to the network is reviewed once, in one place, with
//! its own dependency list — with one difference stated plainly: `ferrum-metrics`
//! has no dependencies at all and this crate has four, because rendering a
//! type requires the type. What is refused here is the rest: no async runtime,
//! no TLS stack, no HTTP client, no retry buffer that grows.
//!
//! Three things this crate is responsible for, and it is worth naming them
//! apart because they fail differently.
//!
//! # 1. What goes into somebody else's system
//!
//! A record leaving this product is read by people who cannot ask the cluster
//! anything, and it is stored where this project's threat model does not
//! reach. So every leaf of [`EventEnvelope`] has an explicit disposition in
//! [`FIELDS`], and a field with no entry is a build failure rather than a
//! silent export — the same shape as `NON_NUMERIC_KEYS` in the agent's metrics
//! module, aimed at a destination that is further away.
//!
//! Two are withheld and the rest are emitted, and both halves are decisions:
//!
//!  * **Policy and rule names go out.** They are what the record is *for*: the
//!    closing criterion of this phase is that "respond killed the wrong
//!    process" is investigated from the SIEM without access to the node, and
//!    a record that will not say which rule fired cannot answer it. This is
//!    the opposite call from `/metrics`, which withholds the policy name, and
//!    deliberately so: that port is reachable by every Pod in the cluster and
//!    this destination is an address an operator configured.
//!  * **The two human names on a waiver do not.** `requestedBy` and
//!    `approvedBy` are people, and a waiver's audit value is carried by
//!    `ticket`, which goes out and joins to the same record in the system that
//!    issued it. Shipping the names would put personal data into a third-party
//!    store to save a join.
//!
//! And one thing that is a decision by *absence*: process arguments, the
//! command line, environment, and the resolved path are not on this envelope
//! at all. `comm` is sixteen bytes of the process name and `pathUnknown` is a
//! flag rather than a path. That is not an oversight to be fixed by adding
//! them — it is the reason this export can be turned on without a review of
//! what secrets a workload happens to pass on its command line.
//!
//! # 2. What an event can do to the record around it
//!
//! `comm` is chosen by the workload, and `pod`/`namespace` by whoever can
//! create objects. In a line-oriented format a value carrying a newline is a
//! second record, forged, attributed to this node. So every value passes
//! [`sanitize`] before any format sees it: control characters become printable
//! `\xNN`, and the value is capped. Then each profile escapes its own
//! metacharacters on top. The gate feeds an envelope full of `|`, `=`, `"`,
//! `]` and newlines through all three profiles and requires the record count
//! not to change.
//!
//! # 3. What happens when the SIEM is not there
//!
//! Nothing waits, and nothing is lost quietly. See [`SyslogSink`].

#![deny(unsafe_code)]

// Public so a consumer — and the gate — can name the constants that make up
// the wire contract (`SD_ID`, `ECS_VERSION`, the CEF vendor triple) instead of
// re-typing them as literals. A literal in a second file is the drift every
// other gate in this tree exists to catch.
pub mod cef;
pub mod ecs;
pub mod rfc5424;
mod sink;

pub use sink::{SinkConfig, SyslogSink, Transport};

use ferrum_proto::EventEnvelope;

/// The wire shape a record is rendered into.
///
/// Three, and the third is a JSON profile rather than a fourth syslog dialect.
/// The reasoning, since the issue asks for it:
///
///  * [`Profile::Cef`] — ArcSight's format, and the one QRadar, Exabeam and
///    most commercial collectors parse without a custom device parser. It is
///    the lowest common denominator of the enterprise SIEM market, and it is
///    the one an operator in a closed contour is most likely to already have a
///    connector for.
///  * [`Profile::Rfc5424`] — the standard itself, with the payload in a
///    structured-data element instead of a message somebody has to regex.
///    Everything that speaks syslog reads it: rsyslog, syslog-ng, Vector,
///    Fluent Bit, and every appliance that only has a syslog input. This is the
///    profile for a receiver nobody has written an integration for.
///  * [`Profile::Ecs`] — Elastic Common Schema, one JSON object per line. It is
///    the only *published, versioned* field dictionary in this list, so an
///    Elastic or OpenSearch cluster indexes it with no mapping work, and Splunk
///    ingests it as JSON with `KV_MODE=json` and no app to install. Splunk's own
///    CIM was the alternative and was refused: it is a datamodel, not a wire
///    format, and using it would mean shipping a Splunk add-on for the
///    receiver's search head — an artefact an air-gapped operator cannot
///    install from us anyway.
///
/// What is missing from the list is a proprietary "connector" for any one
/// vendor, and it stays missing: this product does not want a supply chain in
/// somebody else's plugin format.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Profile {
    /// `CEF:0|...` inside an RFC 5424 frame, the way an ArcSight syslog
    /// connector expects it.
    Cef,
    /// RFC 5424 with the whole record in one SD-ELEMENT.
    Rfc5424,
    /// One ECS JSON object. No syslog header: a receiver reading JSON lines
    /// would have to strip it, and one that does not would fail every parse.
    Ecs,
}

impl Profile {
    pub const ALL: [Profile; 3] = [Profile::Cef, Profile::Rfc5424, Profile::Ecs];

    pub fn name(self) -> &'static str {
        match self {
            Profile::Cef => "cef",
            Profile::Rfc5424 => "rfc5424",
            Profile::Ecs => "ecs",
        }
    }

    /// Parse the value of `--siem-profile`. An unknown name is an error and
    /// never a fallback to a default: a node exporting in a format the
    /// receiver cannot parse is a node whose events are dropped by somebody
    /// else's parser, which is the one loss nothing in this tree can count.
    pub fn parse_name(text: &str) -> Result<Profile, String> {
        Profile::ALL
            .into_iter()
            .find(|p| p.name() == text)
            .ok_or_else(|| {
                format!(
                    "unknown --siem-profile {text:?}; known: {}",
                    Profile::ALL
                        .iter()
                        .map(|p| p.name())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }

    /// One record, without its trailing newline.
    pub fn render(self, envelope: &EventEnvelope) -> String {
        match self {
            Profile::Cef => cef::render(envelope),
            Profile::Rfc5424 => rfc5424::render(envelope),
            Profile::Ecs => ecs::render(envelope),
        }
    }
}

/// What becomes of one leaf of the envelope on its way out of the product.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disposition {
    /// Rendered into every profile.
    Emitted,
    /// Deliberately never rendered. The reason is the third column of
    /// [`FIELDS`], and the gate requires it to be a sentence.
    Withheld,
}

/// Every leaf of a serialised [`EventEnvelope`], by its JSON path, with what
/// this crate does about it and why.
///
/// Exhaustive by gate in both directions: a path here that the envelope does
/// not have, and a path the envelope has and this table does not, are both
/// build failures. That is the whole mechanism — a field added to the schema
/// cannot reach a third-party system until somebody decides, in writing, that
/// it should.
pub const FIELDS: [(&str, Disposition, &str); 27] = [
    (
        "schema",
        Disposition::Emitted,
        "имя схемы: получатель, у которого не один источник, обязан отличать \
         наши записи по полю, а не по совпадению имён",
    ),
    (
        "schemaVersion",
        Disposition::Emitted,
        "версия схемы едет в самой записи: правило разбора на стороне SIEM \
         пишется один раз и должно уметь узнать, что запись новее его",
    ),
    (
        "ts",
        Disposition::Emitted,
        "время события на узле; время приёма у коллектора — другое время, и \
         разница между ними и есть задержка стока",
    ),
    (
        "node",
        Disposition::Emitted,
        "какой узел это решил: без него запись не адресуется ни к чему",
    ),
    (
        "bundleDigest",
        Disposition::Emitted,
        "контент-хеш bundle: он не называет ни одной политики и ровно он \
         присоединяет узел к выкатке, по которой разбирают инцидент",
    ),
    (
        "agentRole",
        Disposition::Emitted,
        "observe или respond — первый вопрос после неожиданного kill'а, и \
         восстановить его из остального нельзя",
    ),
    (
        "degraded",
        Disposition::Emitted,
        "узел был деградирован в момент решения: запись, принятая \
         fail-closed, и запись при полном знании — разные утверждения",
    ),
    (
        "degradedReasons",
        Disposition::Emitted,
        "стабильные id деградаций узла в момент решения. Именно на этом поле \
         критерий закрытия фазы 1 упирался в доступ к узлу: булев `degraded` \
         выше говорит «что-то не так», а какой именно из `lkg_partial`, \
         `clock_rollback`, `container_flag_disagreement` был поднят — жило \
         только в `status.json`, файле 0600 на самом узле. Уходит наружу, \
         потому что id — не предложение и не имя политики: это тот же \
         словарь, что уже публикует `ferrum_agent_degraded_reason`, и \
         разбирающий инцидент соединяет запись с графиком, а не заводит \
         второй словарь",
    ),
    (
        "event.policy",
        Disposition::Emitted,
        "имя политики. Решение, обратное решению /metrics: там оно \
         withheld, потому что порт достижим из любого Pod'а, здесь — адрес \
         назначения выбрал оператор, а запись без имени политики не отвечает \
         на вопрос, ради которого сток существует",
    ),
    (
        "event.rule",
        Disposition::Emitted,
        "то же самое на уровне правила: это signature id записи, и в CEF он \
         именно им и становится",
    ),
    (
        "event.action",
        Disposition::Emitted,
        "что было решено: allow/audit/kill/isolate/waived",
    ),
    (
        "event.imageDigest",
        Disposition::Emitted,
        "дайджест образа: то, что джойнится с supply-chain записями у \
         получателя, и то, что не является ни именем, ни путём",
    ),
    (
        "event.pod",
        Disposition::Emitted,
        "имя Pod'а — адрес рабочей нагрузки в кластере; без него запись не \
         указывает ни на что, что можно посмотреть",
    ),
    (
        "event.namespace",
        Disposition::Emitted,
        "namespace: и адрес, и граница ответственности команды, которой \
         поедет алерт",
    ),
    (
        "event.comm",
        Disposition::Emitted,
        "шестнадцать байт имени процесса. Значение выбирает сама нагрузка, \
         поэтому оно проходит sanitize перед любым форматом",
    ),
    (
        "event.syscall",
        Disposition::Emitted,
        "какой вызов сматчился; без него action не привязан ни к чему",
    ),
    (
        "event.pid",
        Disposition::Emitted,
        "pid из initial pid namespace, как его отдаёт датапейс",
    ),
    (
        "event.tgid",
        Disposition::Emitted,
        "tgid оттуда же: именно его сигналит respond, и именно он нужен, \
         чтобы проверить, того ли убили",
    ),
    (
        "event.executed",
        Disposition::Emitted,
        "реакция действительно исполнилась. Решение и его исполнение — \
         разные факты, и SIEM обязан их различать",
    ),
    (
        "event.respondError",
        Disposition::Emitted,
        "почему реакция не исполнилась. Текст наш, не пользовательский, и \
         это единственное поле, отвечающее на «kill записан, а процесс жив»",
    ),
    (
        "event.labelsUnknown",
        Disposition::Emitted,
        "селектор сматчен против ещё не наблюдённых меток: запись — \
         утверждение о нагрузке, а не разрешённое совпадение",
    ),
    (
        "event.pathUnknown",
        Disposition::Emitted,
        "путь не был прочитан целиком; правило по пути на нечитаемом пути \
         совпадение утверждает, а не пропускает",
    ),
    (
        "event.containerUnknown",
        Disposition::Emitted,
        "решение принято, не зная, был ли вызывающий в контейнере",
    ),
    (
        "event.waiver.ticket",
        Disposition::Emitted,
        "тикет — ключ соединения с системой, которая waiver выписала; \
         именно он делает выдачу имён ниже ненужной",
    ),
    (
        "event.waiver.requestedBy",
        Disposition::Withheld,
        "человек. Персональные данные в чужом хранилище ради join'а, \
         который уже сделан тикетом выше: значение отдаётся системе, чей \
         режим доступа этому дереву неизвестен, и удалить его оттуда потом \
         нельзя",
    ),
    (
        "event.waiver.approvedBy",
        Disposition::Withheld,
        "то же самое и по той же причине; кто утвердил, отвечает система \
         тикетов, а не поток enforcement-событий",
    ),
    (
        "event.waiver.expiresAt",
        Disposition::Emitted,
        "до какого момента waiver действовал: запись после этого времени — \
         дефект, и увидеть его должен получатель, а не только этот узел",
    ),
];

/// The disposition of one path, or `None` if the table says nothing about it.
pub fn disposition(path: &str) -> Option<Disposition> {
    FIELDS
        .iter()
        .find(|(name, _, _)| *name == path)
        .map(|(_, d, _)| *d)
}

/// Longest value this crate will put in one field.
///
/// Not because anything on the envelope is unbounded today — `comm` is sixteen
/// bytes and the Kubernetes names are capped at 253 — but because the cap is
/// what keeps that true after a field is added, and because a UDP datagram
/// that grows past the path MTU is silently truncated by the network rather
/// than by us.
pub const MAX_FIELD_BYTES: usize = 512;

/// Marker appended to a value this crate cut short. Without it a truncated pod
/// name reads as a real, shorter pod name.
pub const TRUNCATION_MARK: &str = "...";

/// Make one value safe to put in a line-oriented record, before any format
/// sees it.
///
/// Control characters become printable `\xNN` rather than being dropped: a
/// workload that named itself with an embedded newline is trying to forge a
/// record, and the evidence of the attempt belongs in the record it failed to
/// forge. Dropping the byte would hide it; passing it through would create the
/// second record.
pub fn sanitize(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut budget = MAX_FIELD_BYTES;
    let mut truncated = false;
    for ch in value.chars() {
        let piece = if (ch.is_control() && ch != ' ') || ch == '\u{7f}' {
            format!("\\x{:02x}", ch as u32 & 0xff)
        } else {
            ch.to_string()
        };
        if piece.len() > budget {
            truncated = true;
            break;
        }
        budget -= piece.len();
        out.push_str(&piece);
    }
    if truncated {
        out.push_str(TRUNCATION_MARK);
    }
    out
}

/// Separator between degradation reason ids in the two syslog profiles.
///
/// A comma and not a space: CEF's extension and RFC 5424's SD-PARAM both take
/// one value per key, and a space inside it is where a hand-written parser on
/// the receiver's side splits a field it was not supposed to split. The reason
/// ids themselves are `[a-z_]`, so a comma cannot occur inside one.
pub const REASON_SEPARATOR: &str = ",";

/// The node's degradation reason ids as one field value, for the two formats
/// that have no arrays. Empty when the node was healthy, which is the same
/// thing `degraded=false` says and is written anyway: a key that disappears is
/// a key a receiver has to special-case.
pub fn degraded_reasons_text(envelope: &EventEnvelope) -> String {
    envelope
        .degraded_reasons
        .iter()
        .map(|reason| sanitize(reason))
        .collect::<Vec<_>>()
        .join(REASON_SEPARATOR)
}

/// CEF severity, 0..10. Shared by all three profiles so a rule written against
/// one does not disagree with a dashboard built on another.
pub fn severity(action: &str, executed: bool) -> u8 {
    match action {
        "kill" | "isolate" => {
            if executed {
                9
            } else {
                7
            }
        }
        "deny" => 8,
        "waived" => 4,
        "audit" => 3,
        "allow" => 1,
        // Not a fallback that hides anything: an action this build does not
        // know is exactly the case an operator should see in the middle of the
        // scale rather than at either end.
        _ => 5,
    }
}

/// The one-line human summary every profile carries. Sanitised, like
/// everything else that came off the wire.
pub fn message(envelope: &EventEnvelope) -> String {
    let e = &envelope.event;
    format!(
        "{action} {ns}/{pod} rule={rule} policy={policy} comm={comm} syscall={syscall} \
         executed={executed}",
        action = sanitize(&e.action),
        ns = sanitize(&e.namespace),
        pod = sanitize(&e.pod),
        rule = sanitize(e.rule.as_str()),
        policy = sanitize(e.policy.as_str()),
        comm = sanitize(&e.comm),
        syscall = sanitize(&e.syscall),
        executed = e.executed,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use ferrum_ids::{Digest, PolicyId, RuleId};
    use ferrum_proto::{EnforcementEvent, EVENT_SCHEMA_VERSION};

    pub(crate) fn envelope() -> EventEnvelope {
        EventEnvelope {
            schema: ferrum_proto::SchemaId,
            schema_version: EVENT_SCHEMA_VERSION,
            ts: Utc.with_ymd_and_hms(2026, 8, 31, 12, 0, 0).unwrap(),
            node: "node-a".into(),
            bundle_digest: Some(Digest::new("sha256:abc")),
            agent_role: "respond".into(),
            degraded: true,
            degraded_reasons: vec!["lkg_partial".into(), "clock_rollback".into()],
            event: EnforcementEvent {
                policy: PolicyId::new("prod-restricted"),
                rule: RuleId::new("no-shell"),
                action: "kill".into(),
                image_digest: Some(Digest::new("sha256:img")),
                pod: "web-7f".into(),
                namespace: "payments".into(),
                comm: "sh".into(),
                syscall: "execve".into(),
                pid: 4242,
                tgid: 4242,
                executed: true,
                labels_unknown: false,
                path_unknown: false,
                container_unknown: false,
                respond_error: None,
                waiver: None,
            },
        }
    }

    #[test]
    fn a_newline_in_a_workload_chosen_value_cannot_become_a_second_record() {
        let hostile = sanitize("sh\nCEF:0|Acme|Fake|1|0|forged|10|");
        assert!(!hostile.contains('\n'), "{hostile}");
        assert!(
            hostile.contains("\\x0a"),
            "the attempt is not visible: {hostile}"
        );
        assert!(!sanitize("a\rb").contains('\r'));
        assert!(!sanitize("a\u{7f}b").contains('\u{7f}'));
        // A space is not a control character and must survive: it is inside
        // legitimate values and escaping it would make every record noisy.
        assert_eq!(sanitize("a b"), "a b");
    }

    #[test]
    fn an_over_long_value_is_cut_and_says_so() {
        let long = "x".repeat(MAX_FIELD_BYTES * 2);
        let cut = sanitize(&long);
        assert!(
            cut.len() <= MAX_FIELD_BYTES + TRUNCATION_MARK.len(),
            "{}",
            cut.len()
        );
        assert!(cut.ends_with(TRUNCATION_MARK));
        // The cap counts the escaped form, not the input: an input made
        // entirely of control characters is four times its own length once
        // escaped, and a cap applied before escaping would let it through.
        let controls = "\u{1}".repeat(MAX_FIELD_BYTES);
        assert!(sanitize(&controls).len() <= MAX_FIELD_BYTES + TRUNCATION_MARK.len());
    }

    #[test]
    fn a_multibyte_value_is_never_cut_inside_a_character() {
        let long = "П".repeat(MAX_FIELD_BYTES);
        let cut = sanitize(&long);
        // The assertion is that this is valid UTF-8 at all, which it is by
        // construction in Rust; the real one is that no character was halved,
        // i.e. the length is a whole number of two-byte characters plus the
        // mark.
        let body = cut.strip_suffix(TRUNCATION_MARK).expect("cut");
        assert_eq!(body.len() % 2, 0, "a character was split: {}", body.len());
        assert!(body.chars().all(|c| c == 'П'));
    }

    #[test]
    fn severity_separates_a_kill_that_ran_from_one_that_did_not() {
        assert!(severity("kill", true) > severity("kill", false));
        assert!(severity("kill", false) > severity("waived", false));
        assert!(severity("waived", false) > severity("audit", false));
        assert_eq!(severity("something-new", false), 5);
    }

    #[test]
    fn every_field_entry_names_a_disposition_and_a_reason() {
        for (path, _, reason) in FIELDS {
            assert!(!path.is_empty());
            assert!(
                reason.chars().count() > 40,
                "{path} is dispositioned by {reason:?}, which is not a reason"
            );
        }
        let withheld: Vec<&str> = FIELDS
            .iter()
            .filter(|(_, d, _)| *d == Disposition::Withheld)
            .map(|(p, _, _)| *p)
            .collect();
        assert_eq!(
            withheld,
            ["event.waiver.requestedBy", "event.waiver.approvedBy"],
            "the withheld set changed; that is a decision about what leaves this product and \
             it does not get made by editing a table"
        );
    }

    #[test]
    fn an_unknown_profile_name_is_an_error_and_not_a_default() {
        assert_eq!(Profile::parse_name("cef").expect("cef"), Profile::Cef);
        assert_eq!(Profile::parse_name("ecs").expect("ecs"), Profile::Ecs);
        let err = Profile::parse_name("leef").expect_err("leef is not implemented");
        assert!(err.contains("cef"), "{err}");
    }
}
