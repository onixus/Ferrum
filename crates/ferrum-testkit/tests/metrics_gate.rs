//! `/metrics` may not outlive, precede or exceed what the binaries export.
//!
//! Four directions rot silently around a metrics surface, and this file closes
//! each of them. None is hypothetical: every one of them is the same shape as
//! a failure this tree has already had.
//!
//! 1. **A dashboard charting a metric nothing exports.** The panel reads "No
//!    data", which is also what a broken scrape reads, so the difference is
//!    invisible to the person on call. Held by
//!    `every_metric_this_dashboard_charts_is_one_the_binaries_export`, which
//!    obtains the exported set by *rendering the real binaries* rather than by
//!    reading a list somewhere.
//! 2. **A metric exported and charted nowhere.** That is the state
//!    `events_dropped_total` was already in — existing, correct, and with no
//!    reader — one level out. Held by
//!    `every_exported_family_is_charted_or_named_as_not_charted`, whose escape
//!    hatch costs a written reason.
//! 3. **A degradation reason with no stable id.** The reason constants are
//!    sentences and get reworded; an alert written against a sentence stops
//!    firing with nothing red anywhere. Held by
//!    `every_degradation_reason_the_agent_can_raise_has_a_stable_metric_id`,
//!    over the same three scans `boundary_gate.rs` uses to find reasons.
//! 4. **Code nobody collects.** A port the binary opens and no manifest names,
//!    or a manifest that opens a port with nothing in front of it. Held by
//!    `the_shipped_manifests_open_and_govern_every_metrics_port`.
//!
//! And the endpoint itself is exercised rather than argued about:
//! `the_metrics_endpoint_answers_a_read_and_refuses_everything_else` binds a
//! real socket over a real `WebhookState`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const DASHBOARD: &str = "deploy/observability/grafana-dashboard.json";

/// Families a binary exports that no panel charts, each with the reason.
///
/// A list and not a prose comment, for the same reason `NOT_INSTALLED_BY_ANY_ROOT`
/// in `deploy_gate.rs` is one: a family drops out of the dashboard by
/// oversight exactly as easily as by decision, and the only difference between
/// the two is a written reason. A short one fails.
const NOT_CHARTED: [(&str, &str); 14] = [
    (
        "ferrum_agent_info",
        "идентичность процесса, не измерение: версия и роль нужны как ярлык на \
         серии в других панелях, а собственная панель у метрики, которая всегда \
         равна единице, — панель без содержания",
    ),
    (
        "ferrum_admission_info",
        "то же самое на стороне вебхука: версия как ярлык, а не как график",
    ),
    (
        "ferrum_admission_break_glass_journal_info",
        "идентичность цепочки, а не измерение: head — хеш, который всегда \
         равен единице как серия, и нужен он затем, что Prometheus его \
         хранит. Это и есть его работа — держать копию головы вне узла, — \
         и панель, показывающая единицу, к ней ничего не добавляет",
    ),
    (
        "ferrum_admission_break_glass_activations_total",
        "накопительная половина `break_glass_active`, который на панели \
         есть: сколько раз grant вступал в силу, читается при разборе \
         инцидента, а на графике это вторая линия про то же событие",
    ),
    (
        "ferrum_admission_break_glass_journal_entries_total",
        "длина цепочки. Она растёт на каждом переходе, которые панель уже \
         показывает по отдельности, и сама по себе не отвечает ни на один \
         вопрос оператора; нужна она при сверке журнала — сколько записей \
         должно быть в файле, — то есть при разборе, а не на дежурстве",
    ),
    (
        "ferrum_agent_attached",
        "то же самое утверждение, что и `degraded_reason{reason=\"not_attached\"}`, \
         которое панель уже показывает; две панели про один факт расходятся в \
         тот день, когда меняется одна из них",
    ),
    (
        "ferrum_agent_control_plane_down",
        "дублирует `degraded_reason{reason=\"control_plane_down\"}`, который \
         на панели причин уже есть; смысл держать оба — алерт по булеву и \
         разбор по причине, но график один",
    ),
    (
        "ferrum_agent_using_last_known_good",
        "следствие control_plane_down и lkg_partial, обе из которых на панели \
         причин; отдельный график добавил бы третью линию про то же событие",
    ),
    (
        "ferrum_agent_lkg_partial",
        "то же: причина `lkg_partial` уже на панели причин, и там она стоит \
         рядом с остальными, а не одна",
    ),
    (
        "ferrum_agent_self_tgid_unpublished",
        "respond-scoped и в базовой поставке истинно на каждом узле: график, \
         который всегда горит, — это график, который перестают смотреть. \
         Значимо оно только под respond, и там его показывает панель причин",
    ),
    (
        "ferrum_agent_lkg_rules_dropped_total",
        "счётчик того же события, что и причина `lkg_partial`: сколько правил \
         не доехало, читается при разборе инцидента из status.json, а на \
         дашборде это была бы вторая линия про ту же деградацию",
    ),
    (
        "ferrum_agent_clock_rollback_total",
        "причина `clock_rollback` на панели причин; счётчик нужен при разборе, \
         график — нет, откат часов не бывает частым",
    ),
    (
        "ferrum_agent_decode_failure_run",
        "текущая длина серии неудачных декодирований — величина для порога \
         внутри агента, а не для глаза: сам факт показывает \
         `records_decode_failed_total`, который на дашборде есть",
    ),
    (
        "ferrum_agent_status_write_failed_total",
        "накопительная половина `status_write_failed`, который на дашборде \
         есть булевом: узел, у которого файл не пишется, важен как факт, а не \
         как частота",
    ),
];

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

/// An agent in the state a fresh Pod is in, plus a sink to read export losses
/// from. Nothing is loaded and nothing is attached, which is deliberate: the
/// families this gate is about must all be present on a node that has done
/// nothing yet, because that is the node whose dashboard reads "No data" if
/// they are not.
fn agent_families() -> (Vec<String>, String) {
    use ferrum_agent::{Agent, AgentConfig};
    use ferrum_export::MemorySink;

    let agent = Agent::new(AgentConfig::default());
    let sink = MemorySink::new();
    let state = agent.degraded_snapshot_at(std::time::Instant::now());
    let exposition = ferrum_agent::exposition(&agent, None, Some(&sink), &state);
    let text = exposition.render();
    (exposition.family_names(), text)
}

fn admission_families() -> (Vec<String>, String) {
    use ferrum_admission::{AdmissionProgram, ReviewConfig, WebhookState};
    use ferrum_api::{AdmitSpec, PolicyMode, PolicySelector, SupplySpec};

    let program = AdmissionProgram {
        abi: ferrum_admission::ADMISSION_ABI,
        mode: PolicyMode::Enforce,
        disabled: false,
        priority: 0,
        supply: SupplySpec::default(),
        admit: AdmitSpec::default(),
        selector: PolicySelector::default(),
    };
    let state = WebhookState::new(program, vec![0u8; 32], Vec::new(), ReviewConfig::default());
    let exposition = ferrum_admission::exposition(&state);
    let text = exposition.render();
    (exposition.family_names(), text)
}

fn exported_families() -> BTreeSet<String> {
    let (agent, _) = agent_families();
    let (admission, _) = admission_families();
    agent.into_iter().chain(admission).collect()
}

/// Every `ferrum_*` identifier in every `expr` of the dashboard.
///
/// Reads the `expr` strings and nothing else: a metric name that appears only
/// in a panel title or a description is documentation, and this gate is about
/// what the panel would actually query. Histogram series are folded back onto
/// their family — `_bucket`, `_sum` and `_count` are how one family is spelled
/// on the wire, not three families.
fn charted_families(dashboard: &serde_json::Value) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut panels: Vec<&serde_json::Value> = Vec::new();
    collect_panels(dashboard, &mut panels);
    for panel in panels {
        let title = panel
            .get("title")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<untitled>")
            .to_string();
        let targets = panel
            .get("targets")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        for target in targets {
            let Some(expr) = target.get("expr").and_then(serde_json::Value::as_str) else {
                continue;
            };
            for name in identifiers(expr) {
                out.entry(name).or_default().insert(title.clone());
            }
        }
    }
    out
}

fn collect_panels<'a>(node: &'a serde_json::Value, out: &mut Vec<&'a serde_json::Value>) {
    if let Some(panels) = node.get("panels").and_then(serde_json::Value::as_array) {
        for panel in panels {
            out.push(panel);
            collect_panels(panel, out);
        }
    }
}

/// `ferrum_`-prefixed identifiers in a PromQL expression, with histogram
/// suffixes folded away.
fn identifiers(expr: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes: Vec<char> = expr.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_alphabetic() || bytes[i] == '_') {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == '_') {
            i += 1;
        }
        let word: String = bytes[start..i].iter().collect();
        if !word.starts_with("ferrum_") {
            continue;
        }
        let family = ["_bucket", "_sum", "_count"]
            .iter()
            .find_map(|suffix| word.strip_suffix(*suffix))
            .map(str::to_string)
            .unwrap_or(word);
        out.insert(family);
    }
    out
}

fn dashboard() -> serde_json::Value {
    serde_json::from_str(&read(DASHBOARD)).expect("the dashboard is not valid JSON")
}

/// A panel may only query a family a render actually produced.
///
/// The exported set comes from calling the shipped render functions, not from
/// a list this file keeps: a list would be a third copy, and the whole finding
/// here is that copies drift. A metric renamed in `ferrum-agent` therefore
/// fails this test on the next run, before the panel silently reads "No data"
/// for the rest of the quarter.
#[test]
fn every_metric_this_dashboard_charts_is_one_the_binaries_export() {
    let exported = exported_families();
    assert!(
        exported.len() > 30,
        "the render produced {} families; it produced more than thirty when this floor was \
         written, so the harness is broken rather than the binaries",
        exported.len()
    );
    let charted = charted_families(&dashboard());
    assert!(
        charted.len() > 20,
        "the dashboard scan found {} families across every expr; the extractor is reading \
         something other than the panels",
        charted.len()
    );
    let missing: Vec<String> = charted
        .iter()
        .filter(|(name, _)| !exported.contains(*name))
        .map(|(name, panels)| format!("{name} (panels: {panels:?})"))
        .collect();
    assert!(
        missing.is_empty(),
        "{DASHBOARD} charts metric families no binary in this tree exports: {missing:#?}. A \
         panel over a family nobody publishes reads \"No data\", which is the same thing it \
         reads when the scrape is broken — so the one state an operator most needs to \
         distinguish is the one this makes indistinguishable."
    );
}

/// The reverse direction, and the one that rots quietly.
///
/// `events_dropped_total` spent eight cycles existing, being correct, and
/// having no reader. A family exported and charted nowhere is that state one
/// level out, and nothing else in this tree would go red for it.
#[test]
fn every_exported_family_is_charted_or_named_as_not_charted() {
    let exported = exported_families();
    let charted = charted_families(&dashboard());
    let excused: BTreeMap<&str, &str> = NOT_CHARTED.into_iter().collect();

    for (family, reason) in &excused {
        assert!(
            exported.contains(*family),
            "NOT_CHARTED names {family:?}, which no binary exports: the entry excuses nothing"
        );
        assert!(
            reason.chars().count() > 60,
            "{family} is excused by {reason:?}, which is not a reason"
        );
        assert!(
            !charted.contains_key(*family),
            "{family} is both charted and listed as not charted. If it got a panel, delete \
             the entry."
        );
    }

    let orphans: Vec<&String> = exported
        .iter()
        .filter(|family| !charted.contains_key(*family) && !excused.contains_key(family.as_str()))
        .collect();
    assert!(
        orphans.is_empty(),
        "these families are exported and appear in no panel and in no NOT_CHARTED entry: \
         {orphans:#?}. Publishing a counter nobody reads is the defect this whole issue is \
         about; doing it on a metrics endpoint is doing it with more steps."
    );
}

/// Control on the extractor: a renamed metric must be a failure.
///
/// Without it, the two directions above would both pass on an extractor that
/// returned the empty set for any input — which is exactly what a small change
/// to the panel shape would produce.
#[test]
fn the_dashboard_scan_notices_a_renamed_metric() {
    let intact = charted_families(&dashboard());
    assert!(intact.contains_key("ferrum_agent_events_dropped_total"));

    let text = read(DASHBOARD).replace(
        "ferrum_agent_events_dropped_total",
        "ferrum_agent_events_dropped_total_renamed",
    );
    let mutated: serde_json::Value = serde_json::from_str(&text).expect("still JSON");
    let after = charted_families(&mutated);
    assert!(
        !after.contains_key("ferrum_agent_events_dropped_total"),
        "a renamed metric read as the original: the scan cannot detect drift and the two \
         directions above prove nothing"
    );
    assert!(
        after.contains_key("ferrum_agent_events_dropped_total_renamed"),
        "the scan lost the metric entirely instead of seeing the new name"
    );
    assert!(
        !exported_families().contains("ferrum_agent_events_dropped_total_renamed"),
        "the renamed family is exported, so the mutation is not a mutation"
    );
}

/// The in-kernel drop counter is *the* counter this issue exists for, so it is
/// asserted by identity rather than by being in a set: the family carries the
/// value `Agent::events_dropped_total` returns, and it is a counter.
///
/// Also the check that the mechanical walk placed everything: a `status.json`
/// key this build could not turn into a metric raises
/// `ferrum_agent_status_keys_unmapped`, and here that must be zero.
#[test]
fn the_agent_publishes_the_in_kernel_drop_counter_it_already_had() {
    let (_, text) = agent_families();
    assert!(
        text.contains("# TYPE ferrum_agent_events_dropped_total counter\n"),
        "the in-kernel ring drop counter is not exported as a counter:\n{text}"
    );
    assert!(
        text.contains("ferrum_agent_events_dropped_total 0\n"),
        "a fresh agent did not publish a zero for its drop counter. Absent is not zero — that \
         is the whole reason this family is emitted before anything has happened:\n{text}"
    );
    assert!(
        text.contains("ferrum_agent_status_keys_unmapped 0\n"),
        "the walk over status.json left keys it could not place. Every one of them is a \
         counter that exists on the node and that nothing publishes:\n{text}"
    );
    // The three export losses are separate families and stay separate: a full
    // queue, a failed write and a writer that is gone do not recover the same
    // way and must not be summed into one number by the exporter.
    for family in [
        "ferrum_agent_export_queue_dropped_total",
        "ferrum_agent_export_write_failed_total",
        "ferrum_agent_export_writer_lost_total",
    ] {
        assert!(
            text.contains(&format!("# TYPE {family} counter\n")),
            "{family} is not exported:\n{text}"
        );
    }
}

/// A scrape must not be able to erase the operator's transition line.
///
/// `Agent::degraded_state_at` latches the reason list and hands `transition`
/// to the first caller only. The metrics render arrives on its own thread on
/// the scraper's schedule; if it called the latching form, whichever
/// transitions happened to fall between two poll ticks would go missing from
/// stderr, and there would be no red anywhere. The surface that reports may
/// not consume the report.
#[test]
fn a_scrape_does_not_consume_the_degraded_transition() {
    use ferrum_agent::{Agent, AgentConfig};
    use ferrum_export::MemorySink;

    let agent = Agent::new(AgentConfig::default());
    let sink = MemorySink::new();
    let now = std::time::Instant::now();

    // Many scrapes, all before the poll loop has ever run.
    for _ in 0..8 {
        let state = agent.degraded_snapshot_at(now);
        assert!(
            state.transition.is_none(),
            "a snapshot produced a transition, so it is the latching call under another name"
        );
        let _ = ferrum_agent::metrics_text(&agent, None, Some(&sink), &state);
    }

    // The poll loop's first tick still gets it.
    let first = agent.degraded_state_at(now);
    assert!(
        first.transition.is_some(),
        "the transition into the initial degraded state was consumed by the scrapes above: \
         the metrics endpoint ate the line the operator was supposed to read"
    );
    let second = agent.degraded_state_at(now);
    assert!(
        second.transition.is_none(),
        "the latching call handed the same transition out twice, so the assertion above \
         proves nothing about who consumed it"
    );
}

/// Every reason the agent can raise has an id that a label can carry and that
/// survives a rewording of the sentence.
///
/// Three scans, the same three `boundary_gate.rs` runs, and for the same
/// reason: `DEG_*` is a convention, `degraded_reasons_at` is the mechanism,
/// and a terminal fault reaches the list as the text it already holds and
/// appears in neither.
#[test]
fn every_degradation_reason_the_agent_can_raise_has_a_stable_metric_id() {
    let src = repo_root().join("crates/ferrum-agent/src");
    let declared = str_constants(&src);
    let lib = std::fs::read_to_string(src.join("lib.rs")).expect("ferrum-agent/src/lib.rs");

    let mut reasons: BTreeSet<String> = declared
        .keys()
        .filter(|name| name.starts_with("DEG_"))
        .cloned()
        .collect();
    assert!(
        reasons.len() >= 16,
        "found {} DEG_ constants; the scan is broken, not the agent",
        reasons.len()
    );

    let body = degraded_reasons_body(&lib);
    assert!(
        body.lines().count() > 50,
        "the body of `degraded_reasons_at` came back as {} lines; the slice is wrong",
        body.lines().count()
    );
    let pushed: BTreeSet<String> = body
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| declared.contains_key(*token))
        .map(str::to_string)
        .collect();
    assert!(
        pushed.len() >= 19,
        "`degraded_reasons_at` names {} reason constants; the scan is broken: {pushed:?}",
        pushed.len()
    );
    reasons.extend(pushed);
    let latched = terminal_fault_constants(&src, &declared);
    assert!(
        latched.len() >= 4,
        "found {} constants passed to `mark_terminal_fault`; the scan is broken: {latched:?}",
        latched.len()
    );
    reasons.extend(latched);

    // The table is keyed by the constant's *text*, which this file cannot read
    // from the source. So it is checked the other way round: every reason
    // constant's text must resolve to an id other than the fallback, and the
    // fallback is what an unnamed reason gets.
    let texts = constant_texts(&src, &reasons);
    let unnamed: Vec<&String> = reasons
        .iter()
        .filter(|name| {
            let Some(text) = texts.get(*name) else {
                return true;
            };
            ferrum_agent::degraded_reason_id(text) == ferrum_agent::UNMAPPED_REASON_ID
        })
        .collect();
    assert!(
        unnamed.is_empty(),
        "these reasons the agent can raise have no id in DEGRADED_REASON_IDS: {unnamed:#?}. \
         Each of them would be published as {:?}, which tells an operator that something is \
         wrong and nothing about what.",
        ferrum_agent::UNMAPPED_REASON_ID
    );

    // And the table cannot be padded into passing. Two directions, because the
    // bridge below is a hand-written list and both of its ends can rot:
    //
    //  * every name the bridge carries is a `pub const &str` the scan found in
    //    the crate, so a constant deleted or renamed fails here rather than
    //    leaving the bridge quietly describing something gone;
    //  * every text in `DEGRADED_REASON_IDS` is the value of one of those
    //    constants, so an id cannot be attached to a string somebody typed.
    //
    // The reason set checked above is a *subset* of the bridge, not equal to
    // it: `RESPOND_NO_HOST_PIDNS` and `WAIVERS_UNJOINED` reach
    // `degraded_reasons_at` as the text an accessor already holds — the same
    // shape as a terminal fault — so no scan over that function's body can see
    // them, and they must still have ids.
    let mut declared_texts: BTreeMap<&str, &str> = BTreeMap::new();
    for (name, value) in known_constants() {
        assert!(
            declared.contains_key(name),
            "the bridge in known_constants() names {name:?}, which is not a `pub const &str` \
             in ferrum-agent: the entry describes a constant that is gone"
        );
        declared_texts.insert(name, value);
    }
    let known: BTreeSet<&str> = declared_texts.values().copied().collect();
    let invented: Vec<&str> = ferrum_agent::DEGRADED_REASON_IDS
        .iter()
        .map(|(text, _)| *text)
        .filter(|text| !known.contains(text))
        .collect();
    assert!(
        invented.is_empty(),
        "DEGRADED_REASON_IDS carries texts that are not the value of any reason constant: \
         {invented:#?}"
    );

    let mut ids: Vec<&str> = ferrum_agent::DEGRADED_REASON_IDS
        .iter()
        .map(|(_, id)| *id)
        .collect();
    ids.push(ferrum_agent::UNMAPPED_REASON_ID);
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        before,
        ids.len(),
        "two reasons share one id, so one of them is invisible on the dashboard"
    );

    // Every id, every scrape, zero included. Otherwise an absent series means
    // both "not raised" and "this build has no such reason".
    let (_, text) = agent_families();
    for id in &ids {
        assert!(
            text.contains(&format!("ferrum_agent_degraded_reason{{reason=\"{id}\"}} ")),
            "reason id {id:?} is not in the exposition of a fresh agent. A series that only \
             appears once the reason fires cannot be alerted on: absent reads the same as \
             healthy.\n{text}"
        );
    }
}

/// The port is opened by the manifests, named, discoverable, and governed.
///
/// Every half of that is a way for this work to be code nobody collects: a
/// flag with no container port is a socket no probe or Service can name, a
/// container port with no Service is a target no scraper discovers, and a port
/// with no NetworkPolicy in front of it is an unauthenticated read of the
/// enforcement plane's health available to every Pod in the cluster.
#[test]
fn the_shipped_manifests_open_and_govern_every_metrics_port() {
    use serde_yaml::Value;

    let workloads = [
        ("deploy/admission/deployment.yaml", "ferrum-admission"),
        ("deploy/agent/daemonset.yaml", "ferrum-agent"),
    ];
    for (file, name) in workloads {
        let doc: Value = serde_yaml::from_str(&read(file)).expect("workload is not valid YAML");
        let pod = doc
            .get("spec")
            .and_then(|s| s.get("template"))
            .unwrap_or_else(|| panic!("{file}: no pod template"));
        let container = pod
            .get("spec")
            .and_then(|s| s.get("containers"))
            .and_then(Value::as_sequence)
            .and_then(|c| c.first())
            .unwrap_or_else(|| panic!("{file}: no container"));

        let args: Vec<String> = container
            .get("args")
            .and_then(Value::as_sequence)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let at = args
            .iter()
            .position(|a| a == "--metrics-listen")
            .unwrap_or_else(|| {
                panic!(
                    "{file} passes no --metrics-listen, so {name} publishes nothing and every \
                     metric in this tree is code nobody collects"
                )
            });
        let listen = args
            .get(at + 1)
            .unwrap_or_else(|| panic!("{file}: --metrics-listen has no value"));
        let (_, port) = listen
            .rsplit_once(':')
            .unwrap_or_else(|| panic!("{file}: --metrics-listen {listen:?} names no port"));

        let ports = container
            .get("ports")
            .and_then(Value::as_sequence)
            .unwrap_or_else(|| panic!("{file}: the container declares no ports"));
        let metrics = ports
            .iter()
            .find(|p| p.get("name").and_then(Value::as_str) == Some("metrics"))
            .unwrap_or_else(|| {
                panic!(
                    "{file}: --metrics-listen is passed and no containerPort is named `metrics`. \
                     The Service and the NetworkPolicy both address this port by name."
                )
            });
        assert_eq!(
            metrics
                .get("containerPort")
                .and_then(Value::as_u64)
                .map(|n| n.to_string())
                .unwrap_or_default(),
            port,
            "{file}: the container port and the address --metrics-listen binds disagree"
        );

        let annotations = pod
            .get("metadata")
            .and_then(|m| m.get("annotations"))
            .unwrap_or_else(|| panic!("{file}: the pod template carries no annotations"));
        assert_eq!(
            annotations
                .get("prometheus.io/scrape")
                .and_then(Value::as_str),
            Some("true"),
            "{file}: no prometheus.io/scrape annotation, so an annotation-driven scrape config \
             — the one shape that needs nothing installed on our side — never finds this Pod"
        );
        assert_eq!(
            annotations
                .get("prometheus.io/port")
                .and_then(Value::as_str),
            Some(port),
            "{file}: the scrape annotation names a different port from --metrics-listen"
        );
        assert_eq!(
            annotations
                .get("prometheus.io/path")
                .and_then(Value::as_str),
            Some(ferrum_metrics::METRICS_PATH),
            "{file}: the scrape annotation names a path this server does not answer"
        );
    }

    // A Service per plane, so the port is discoverable as an Endpoints object
    // and not only as a Pod annotation.
    for (file, kind) in [
        ("deploy/admission/service.yaml", "ClusterIP"),
        ("deploy/agent/metrics-service.yaml", "headless"),
    ] {
        let doc: Value = serde_yaml::from_str(&read(file)).expect("service is not valid YAML");
        let ports = doc
            .get("spec")
            .and_then(|s| s.get("ports"))
            .and_then(Value::as_sequence)
            .unwrap_or_else(|| panic!("{file}: no ports"));
        let metrics = ports
            .iter()
            .find(|p| p.get("name").and_then(Value::as_str) == Some("metrics"))
            .unwrap_or_else(|| panic!("{file}: no Service port named `metrics`"));
        assert_eq!(
            metrics.get("targetPort").and_then(Value::as_str),
            Some("metrics"),
            "{file}: the Service targets the metrics port by number. By name, so the number \
             lives in the workload manifest only and moving it cannot leave this pointing at \
             a port nothing listens on."
        );
        if kind == "headless" {
            assert_eq!(
                doc.get("spec")
                    .and_then(|s| s.get("clusterIP"))
                    .and_then(Value::as_str),
                Some("None"),
                "{file}: the agent Service is not headless. A ClusterIP load-balances the \
                 scrape across nodes, so a per-node counter becomes one flapping series and \
                 the node that is actually dropping records disappears into the average."
            );
        }
    }

    // And the policy in front of it, in a root the default install pulls in.
    let policy: Value = serde_yaml::from_str(&read("deploy/observability/networkpolicy.yaml"))
        .expect("networkpolicy is not valid YAML");
    assert_eq!(
        policy.get("kind").and_then(Value::as_str),
        Some("NetworkPolicy")
    );
    let ingress = policy
        .get("spec")
        .and_then(|s| s.get("ingress"))
        .and_then(Value::as_sequence)
        .expect("the policy states no ingress rules");
    let scrape = ingress
        .iter()
        .find(|rule| {
            rule.get("ports")
                .and_then(Value::as_sequence)
                .is_some_and(|ports| {
                    ports
                        .iter()
                        .any(|p| p.get("port").and_then(Value::as_str) == Some("metrics"))
                })
        })
        .expect("no ingress rule governs the port named `metrics`");
    assert!(
        scrape.get("from").is_some(),
        "the rule for the metrics port has no `from`, which in NetworkPolicy means every \
         source. An unauthenticated read of which nodes are currently not enforcing, open to \
         every Pod in the cluster, is the single most useful thing this product could hand an \
         attacker who is already inside."
    );
    // The webhook port has to be re-allowed in the same object: a policy that
    // selects a Pod takes over its ingress entirely, and under
    // failurePolicy: Fail an API server that cannot reach 8443 is every Pod in
    // the cluster refused.
    let webhook = ingress.iter().any(|rule| {
        rule.get("ports")
            .and_then(Value::as_sequence)
            .is_some_and(|ports| {
                ports
                    .iter()
                    .any(|p| p.get("port").and_then(Value::as_u64) == Some(8443))
            })
    });
    assert!(
        webhook,
        "the NetworkPolicy governs the metrics port and does not re-allow 8443. Installing it \
         would stop the API server reaching the webhook, and with failurePolicy: Fail that is \
         a cluster-wide refusal of every Pod."
    );

    let root = read("deploy/kustomization.yaml");
    assert!(
        root.contains("- observability"),
        "the default install does not pull in deploy/observability, so an operator who applies \
         `deploy` gets the metrics ports — they are in the workload manifests — with nothing \
         in front of them"
    );
}

/// The endpoint, exercised rather than argued about.
///
/// A real socket over a real `WebhookState`: a scrape gets the exposition, a
/// write method gets 405 with its body never read, and another path gets 404.
/// The read-only property is the one that decides whether this port is
/// acceptable on a DaemonSet at all, so it is measured here and not asserted
/// in a doc comment.
#[test]
fn the_metrics_endpoint_answers_a_read_and_refuses_everything_else() {
    use ferrum_admission::{AdmissionProgram, ReviewConfig, WebhookState};
    use ferrum_api::{AdmitSpec, PolicyMode, PolicySelector, SupplySpec};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    let program = AdmissionProgram {
        abi: ferrum_admission::ADMISSION_ABI,
        mode: PolicyMode::Enforce,
        disabled: false,
        priority: 0,
        supply: SupplySpec::default(),
        admit: AdmitSpec::default(),
        selector: PolicySelector::default(),
    };
    let state = std::sync::Arc::new(WebhookState::new(
        program,
        vec![0u8; 32],
        Vec::new(),
        ReviewConfig::default(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    ferrum_admission::spawn_metrics(listener, std::sync::Arc::clone(&state));

    let request = |raw: &str| -> String {
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream.write_all(raw.as_bytes()).expect("write");
        let mut out = String::new();
        stream.read_to_string(&mut out).expect("read");
        out
    };

    let scraped = request("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(scraped.starts_with("HTTP/1.1 200 OK\r\n"), "{scraped}");
    assert!(
        scraped.contains("ferrum_admission_reviews_denied_total 0\n"),
        "the endpoint answered without the exposition:\n{scraped}"
    );

    let posted = request("POST /metrics HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi");
    assert!(
        posted.starts_with("HTTP/1.1 405 "),
        "the metrics port accepted a write method: {posted}"
    );
    assert_eq!(
        state.reviews_denied(),
        0,
        "a POST to the metrics port reached the review path. This endpoint must never read a \
         request body, let alone evaluate one."
    );

    let elsewhere = request("GET /debug/pprof HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(
        elsewhere.starts_with("HTTP/1.1 404 "),
        "the metrics port serves a second path: {elsewhere}"
    );
}

// --- the three scans, shared with `boundary_gate.rs` in shape and not in code
//
// Deliberately duplicated rather than lifted into `ferrum-testkit`'s library.
// The two gates make different assertions about the same set, and a shared
// helper would let a change that narrows the scan quietly satisfy both: the
// second reading of a set is only worth something while it is a second reading.

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn str_constants(src: &Path) -> BTreeMap<String, PathBuf> {
    let mut files = Vec::new();
    rs_files(src, &mut files);
    let mut out = BTreeMap::new();
    for file in files {
        let body = std::fs::read_to_string(&file).expect("agent source");
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

fn degraded_reasons_body(lib: &str) -> &str {
    let start = lib
        .find("    pub fn degraded_reasons_at(")
        .expect("ferrum-agent no longer has `degraded_reasons_at`");
    let tail = &lib[start..];
    let end = tail
        .find("\n    }\n")
        .expect("degraded_reasons_at does not close at method indentation");
    &tail[..end]
}

fn terminal_fault_constants(src: &Path, declared: &BTreeMap<String, PathBuf>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut files = Vec::new();
    rs_files(src, &mut files);
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read a source file");
        for (at, _) in text.match_indices("mark_terminal_fault(") {
            let window: String = text[at..]
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join("\n")
                .to_string();
            for token in window.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                if declared.contains_key(token) {
                    out.insert(token.to_string());
                }
            }
        }
    }
    out
}

/// The runtime value of each named constant, read through the crate rather
/// than parsed out of the source: a string literal split across lines by
/// rustfmt is not reconstructible by a text scan, and half of these are.
fn constant_texts(_src: &Path, names: &BTreeSet<String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in known_constants() {
        if names.contains(name) {
            out.insert(name.to_string(), value.to_string());
        }
    }
    out
}

/// The bridge between a name found by scanning the source and the value the
/// crate exports under it.
///
/// A list, and it has to be: Rust has no reflection over `pub const` items.
/// What keeps it honest is the caller — a name the scans find and this list
/// does not carry counts as *unnamed*, so forgetting to add one here fails the
/// test rather than shrinking it.
fn known_constants() -> Vec<(&'static str, &'static str)> {
    use ferrum_agent::*;
    vec![
        ("CGROUP_ROOT_UNDERIVABLE", CGROUP_ROOT_UNDERIVABLE),
        ("DATAPATH_ABI_MISMATCH", DATAPATH_ABI_MISMATCH),
        ("DATAPATH_UNDECODABLE", DATAPATH_UNDECODABLE),
        ("DEG_BUNDLE_UNREADABLE", DEG_BUNDLE_UNREADABLE),
        ("DEG_CGROUP_INDEX_EMPTY", DEG_CGROUP_INDEX_EMPTY),
        ("DEG_CLOCK_FLOOR_UNPERSISTED", DEG_CLOCK_FLOOR_UNPERSISTED),
        ("DEG_CLOCK_ROLLBACK", DEG_CLOCK_ROLLBACK),
        ("DEG_CONTAINER_FLAG", DEG_CONTAINER_FLAG),
        ("DEG_CONTAINER_MAP", DEG_CONTAINER_MAP),
        ("DEG_CONTROL_PLANE_DOWN", DEG_CONTROL_PLANE_DOWN),
        ("DEG_DATAPATH", DEG_DATAPATH),
        ("DEG_DECODE_FAILURES", DEG_DECODE_FAILURES),
        ("DEG_EXPORT_DEAD", DEG_EXPORT_DEAD),
        ("DEG_EXPORT_LOSSY", DEG_EXPORT_LOSSY),
        ("DEG_IDENTITY_UNKNOWN", DEG_IDENTITY_UNKNOWN),
        ("DEG_LABELS_UNKNOWN", DEG_LABELS_UNKNOWN),
        ("DEG_LKG_PARTIAL", DEG_LKG_PARTIAL),
        ("DEG_LOADER", DEG_LOADER),
        ("DEG_NOT_ATTACHED", DEG_NOT_ATTACHED),
        ("DEG_PATH_TRUNCATED", DEG_PATH_TRUNCATED),
        ("DEG_RING_DROPS", DEG_RING_DROPS),
        ("DEG_STATUS_UNWRITABLE", DEG_STATUS_UNWRITABLE),
        ("DEG_WAIVERS_DROPPED", DEG_WAIVERS_DROPPED),
        ("RECORD_CHANNEL_GONE", RECORD_CHANNEL_GONE),
        ("RESPOND_NO_HOST_PIDNS", RESPOND_NO_HOST_PIDNS),
        ("RESPOND_SIGNAL_FAILING", RESPOND_SIGNAL_FAILING),
        ("SELF_TGID_UNPUBLISHED", SELF_TGID_UNPUBLISHED),
        ("TARGET_CHECK_UNPROVABLE", TARGET_CHECK_UNPROVABLE),
        ("TARGET_NEVER_PROVEN", TARGET_NEVER_PROVEN),
        ("WAIVERS_UNJOINED", WAIVERS_UNJOINED),
    ]
}
