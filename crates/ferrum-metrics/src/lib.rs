//! Prometheus text exposition, and the smallest listener that can answer it.
//!
//! Why a crate of its own rather than a module in `ferrum-agent` or
//! `ferrum-admission`: both of them need it, and the boundary table in
//! `AGENTS.md` is the reason neither may grow it. The agent must not link an
//! HTTP stack; the webhook must not grow a second one beside the TLS server it
//! already runs. One crate with no dependencies at all is reviewed once and
//! carries the same refusals in both places.
//!
//! Two refusals are structural rather than documented:
//!
//!  * **Nothing here reads a request body.** [`serve_listener`] parses a
//!    request line and discards headers up to a cap. A metrics endpoint that
//!    accepted a body would be an ingress with a parser on it, in a process
//!    whose whole job is to be the last thing an attacker gets to talk to.
//!  * **Nothing here holds state that a scrape can lose.** Counters are read
//!    from the live atomics of the process at render time; there is no queue
//!    between the counter and the reader, so a scrape that fails loses a
//!    *reading*, never a count. That is the point `ferrum-export`'s boundary
//!    makes about silent record loss, applied to the surface that reports it:
//!    a metric about losses that can itself be lost is the same defect.
//!
//! Format is the Prometheus text exposition format, version 0.0.4: `# HELP`,
//! `# TYPE`, then samples. No OpenMetrics `# EOF`, no exemplars, no protobuf.

#![deny(unsafe_code)]

mod serve;

pub use serve::{serve_listener, ServeConfig, CONTENT_TYPE, METRICS_PATH};

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

/// Metric family kinds this crate can render.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Counter,
    Gauge,
    Histogram,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
            Kind::Histogram => "histogram",
        }
    }
}

/// Bucket boundaries, in seconds, for every latency histogram in this tree.
///
/// One shared ladder rather than a per-call-site choice: a dashboard that
/// computes a p99 with `histogram_quantile` reads bucket boundaries, so two
/// histograms with different ladders cannot be put on one panel, and the panel
/// that tries reads as a latency that changed when only the ladder did. The
/// top of the ladder is 2.5s because the API server's webhook `timeoutSeconds`
/// default is 10 and anything past a couple of seconds is already an outage
/// rather than a latency.
pub const LATENCY_BUCKETS_SECONDS: [f64; 12] = [
    0.000_1, 0.000_25, 0.000_5, 0.001, 0.002_5, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5, 2.5,
];

/// A latency histogram made of atomics and nothing else.
///
/// Safe to observe from the request path: `observe` is at most
/// `LATENCY_BUCKETS_SECONDS.len()` relaxed fetch_adds and allocates nothing.
/// Rendering happens on the scrape thread and takes no lock, so a scraper that
/// stalls cannot stall a review.
///
/// The sum is kept in nanoseconds as an integer rather than as a float: there
/// is no atomic f64 in std, and the alternatives are a mutex on the hot path or
/// a CAS loop over bit patterns. Nanoseconds as `u64` overflow after 584 years
/// of accumulated latency.
#[derive(Debug)]
pub struct Histogram {
    buckets: [AtomicU64; LATENCY_BUCKETS_SECONDS.len()],
    count: AtomicU64,
    sum_nanos: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    pub fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            sum_nanos: AtomicU64::new(0),
        }
    }

    /// Record one observation. Cumulative buckets: an observation lands in its
    /// own bucket and in every wider one, which is what `le` means on the wire
    /// and what makes `histogram_quantile` correct.
    pub fn observe(&self, elapsed: std::time::Duration) {
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let seconds = elapsed.as_secs_f64();
        for (i, upper) in LATENCY_BUCKETS_SECONDS.iter().enumerate() {
            if seconds <= *upper {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_nanos.fetch_add(nanos, Ordering::Relaxed);
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn sum_seconds(&self) -> f64 {
        self.sum_nanos.load(Ordering::Relaxed) as f64 / 1e9
    }

    pub fn bucket(&self, index: usize) -> u64 {
        self.buckets[index].load(Ordering::Relaxed)
    }
}

/// One `name{labels} value` line.
struct Sample {
    labels: Vec<(String, String)>,
    value: String,
}

struct Family {
    name: String,
    help: String,
    kind: Kind,
    samples: Vec<Sample>,
}

/// The families one process publishes, built fresh on each scrape.
///
/// Built rather than registered: a global registry is state that outlives the
/// thing it describes, and this tree has already paid once for counters whose
/// only reader was a bool. Everything here is read from the live process when a
/// scrape asks and thrown away when the response is written, so a family that
/// stops being produced stops appearing rather than freezing on its last value.
#[derive(Default)]
pub struct Exposition {
    families: Vec<Family>,
    /// Names already added, so a second family under one name is caught here
    /// rather than by a parse error at the scraper — which drops the whole
    /// response, not the duplicate.
    seen: std::collections::BTreeSet<String>,
}

impl Exposition {
    pub fn new() -> Self {
        Self::default()
    }

    /// Family names this exposition carries, in insertion order. The dashboard
    /// gate reads this: a panel may only name a family a render actually
    /// produced.
    pub fn family_names(&self) -> Vec<String> {
        self.families.iter().map(|f| f.name.clone()).collect()
    }

    fn open(&mut self, name: &str, help: &str, kind: Kind) -> &mut Family {
        assert!(
            valid_name(name),
            "metric name {name:?} is not [a-zA-Z_:][a-zA-Z0-9_:]*"
        );
        assert!(
            self.seen.insert(name.to_string()),
            "metric family {name:?} declared twice: a scraper takes the second block as a parse \
             error and drops the whole response, so both families go missing at once"
        );
        assert!(
            !help.is_empty(),
            "metric family {name:?} has no HELP. The one thing a metric cannot carry in its name \
             is why it exists, and an operator paging on it at 03:00 reads this line"
        );
        self.families.push(Family {
            name: name.to_string(),
            help: help.to_string(),
            kind,
            samples: Vec::new(),
        });
        self.families.last_mut().expect("just pushed")
    }

    /// A monotonic counter. Panics unless the name ends in `_total`: the suffix
    /// is what tells a reader — and `rate()` — that a value going down means a
    /// restart rather than a subtraction.
    pub fn counter(&mut self, name: &str, help: &str, value: u64) -> &mut Self {
        assert!(
            name.ends_with("_total"),
            "counter {name:?} does not end in `_total`"
        );
        self.open(name, help, Kind::Counter).samples.push(Sample {
            labels: Vec::new(),
            value: value.to_string(),
        });
        self
    }

    pub fn gauge(&mut self, name: &str, help: &str, value: u64) -> &mut Self {
        assert!(
            !name.ends_with("_total"),
            "gauge {name:?} ends in `_total`, which promises a monotonic series"
        );
        self.open(name, help, Kind::Gauge).samples.push(Sample {
            labels: Vec::new(),
            value: value.to_string(),
        });
        self
    }

    pub fn bool_gauge(&mut self, name: &str, help: &str, value: bool) -> &mut Self {
        self.gauge(name, help, u64::from(value))
    }

    /// A gauge with one series per label set. Used for the families whose whole
    /// content is a label: `..._bundle_info` (digest) and
    /// `..._degraded_reason`.
    ///
    /// `series` must be complete: every reason a process can raise appears,
    /// with 0 for the ones it is not raising. A family that emits only the
    /// series that are currently true makes "absent" mean both "not degraded"
    /// and "this build has no such reason", and an alert written on the first
    /// meaning fires never under the second.
    pub fn labelled_gauge(
        &mut self,
        name: &str,
        help: &str,
        series: Vec<(Vec<(String, String)>, u64)>,
    ) -> &mut Self {
        let family = self.open(name, help, Kind::Gauge);
        for (labels, value) in series {
            for (key, _) in &labels {
                assert!(valid_name(key), "label name {key:?} is not an identifier");
            }
            family.samples.push(Sample {
                labels,
                value: value.to_string(),
            });
        }
        self
    }

    /// A histogram family: `_bucket{le}`, `_sum`, `_count`, with the `+Inf`
    /// bucket last and equal to `_count`.
    pub fn histogram(&mut self, name: &str, help: &str, hist: &Histogram) -> &mut Self {
        assert!(
            !name.ends_with("_total") && !name.ends_with("_bucket"),
            "histogram {name:?} must be named for its unit, e.g. `..._seconds`"
        );
        let count = hist.count();
        let sum = hist.sum_seconds();
        let family = self.open(name, help, Kind::Histogram);
        for (i, upper) in LATENCY_BUCKETS_SECONDS.iter().enumerate() {
            family.samples.push(Sample {
                labels: vec![("le".into(), format_float(*upper))],
                value: hist.bucket(i).to_string(),
            });
        }
        family.samples.push(Sample {
            labels: vec![("le".into(), "+Inf".into())],
            value: count.to_string(),
        });
        family.samples.push(Sample {
            labels: vec![(SUFFIX_LABEL.into(), "_sum".into())],
            value: format_float(sum),
        });
        family.samples.push(Sample {
            labels: vec![(SUFFIX_LABEL.into(), "_count".into())],
            value: count.to_string(),
        });
        self
    }

    /// The whole response body.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);
        for family in &self.families {
            let _ = writeln!(out, "# HELP {} {}", family.name, escape_help(&family.help));
            let _ = writeln!(out, "# TYPE {} {}", family.name, family.kind.as_str());
            for sample in &family.samples {
                // A histogram's `_sum` and `_count` are not labelled samples of
                // the family name; they are separate series whose *name*
                // carries the suffix. Encoding that as a reserved label keeps
                // `Sample` one shape.
                let reserved = sample.labels.len() == 1
                    && sample.labels[0].0 == SUFFIX_LABEL
                    && family.kind == Kind::Histogram;
                if reserved {
                    let _ = writeln!(
                        out,
                        "{}{} {}",
                        family.name, sample.labels[0].1, sample.value
                    );
                    continue;
                }
                let suffix = if family.kind == Kind::Histogram {
                    "_bucket"
                } else {
                    ""
                };
                if sample.labels.is_empty() {
                    let _ = writeln!(out, "{}{} {}", family.name, suffix, sample.value);
                } else {
                    let labels: Vec<String> = sample
                        .labels
                        .iter()
                        .map(|(k, v)| format!("{k}=\"{}\"", escape_label(v)))
                        .collect();
                    let _ = writeln!(
                        out,
                        "{}{}{{{}}} {}",
                        family.name,
                        suffix,
                        labels.join(","),
                        sample.value
                    );
                }
            }
        }
        out
    }
}

/// Not a label a caller may write: `__`-prefixed names are reserved by
/// Prometheus itself, so nothing legitimate collides with the marker the
/// histogram renderer uses for its `_sum`/`_count` lines.
const SUFFIX_LABEL: &str = "__suffix";

/// Prometheus name grammar. Checked rather than sanitised: a name that has to
/// be repaired to be legal was chosen by something that did not know the rules,
/// and quietly repairing it renames the series a dashboard is written against.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == ':' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

/// `camelCase` to `snake_case`, which is how a `status.json` key becomes a
/// metric name.
pub fn snake_case(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    for (i, c) in key.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// In `# HELP`, backslash and newline are escaped and nothing else is.
fn escape_help(text: &str) -> String {
    text.replace('\\', "\\\\").replace('\n', "\\n")
}

/// In a label value: backslash, double quote, newline.
///
/// Not cosmetic. Label values in this tree carry a bundle digest and a
/// degradation reason id; an unescaped quote in either ends the label early and
/// the rest of the string becomes syntax the scraper reads as a broken family.
fn escape_label(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Prometheus spells the infinities and NaN this way, and does not want a
/// small bucket bound rendered in exponent form.
fn format_float(value: f64) -> String {
    if value.is_infinite() {
        return if value > 0.0 { "+Inf" } else { "-Inf" }.to_string();
    }
    if value.is_nan() {
        return "NaN".to_string();
    }
    let mut text = format!("{value:.9}");
    if text.contains('.') {
        while text.ends_with('0') {
            text.pop();
        }
        if text.ends_with('.') {
            text.push('0');
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_counter_renders_help_type_and_value() {
        let mut e = Exposition::new();
        e.counter(
            "ferrum_agent_events_dropped_total",
            "in-kernel ring drops",
            7,
        );
        let text = e.render();
        assert!(text.contains("# HELP ferrum_agent_events_dropped_total in-kernel ring drops\n"));
        assert!(text.contains("# TYPE ferrum_agent_events_dropped_total counter\n"));
        assert!(text.contains("ferrum_agent_events_dropped_total 7\n"));
        assert_eq!(
            e.family_names(),
            vec!["ferrum_agent_events_dropped_total".to_string()]
        );
    }

    #[test]
    fn a_histogram_is_cumulative_and_its_inf_bucket_equals_its_count() {
        let hist = Histogram::new();
        hist.observe(Duration::from_micros(300));
        hist.observe(Duration::from_millis(20));
        let mut e = Exposition::new();
        e.histogram("ferrum_admission_review_seconds", "review latency", &hist);
        let text = e.render();
        // 300us lands in le=0.0005 and every wider bucket; 20ms only from 0.025.
        assert!(text.contains("ferrum_admission_review_seconds_bucket{le=\"0.0005\"} 1\n"));
        assert!(text.contains("ferrum_admission_review_seconds_bucket{le=\"0.025\"} 2\n"));
        assert!(text.contains("ferrum_admission_review_seconds_bucket{le=\"+Inf\"} 2\n"));
        assert!(text.contains("ferrum_admission_review_seconds_count 2\n"));
        assert!(text.contains("ferrum_admission_review_seconds_sum 0.0203\n"));
        let mut previous = 0;
        for i in 0..LATENCY_BUCKETS_SECONDS.len() {
            assert!(hist.bucket(i) >= previous, "ladder is not monotonic");
            previous = hist.bucket(i);
        }
    }

    #[test]
    fn a_label_value_cannot_end_its_own_label() {
        let mut e = Exposition::new();
        e.labelled_gauge(
            "ferrum_agent_bundle_info",
            "bundle in force",
            vec![(vec![("digest".into(), "a\"b\\c\nd".into())], 1)],
        );
        let text = e.render();
        assert!(
            text.contains(r#"ferrum_agent_bundle_info{digest="a\"b\\c\nd"} 1"#),
            "{text}"
        );
        assert_eq!(text.lines().filter(|l| !l.starts_with('#')).count(), 1);
    }

    #[test]
    #[should_panic(expected = "declared twice")]
    fn one_name_cannot_carry_two_families() {
        let mut e = Exposition::new();
        e.counter("ferrum_x_total", "a", 1);
        e.counter("ferrum_x_total", "b", 2);
    }

    #[test]
    fn camel_case_keys_become_snake_case_names() {
        assert_eq!(snake_case("eventsDroppedTotal"), "events_dropped_total");
        assert_eq!(snake_case("lkgPartial"), "lkg_partial");
        assert_eq!(snake_case("degraded"), "degraded");
    }

    #[test]
    fn a_name_that_is_not_a_prometheus_name_is_refused_rather_than_repaired() {
        assert!(valid_name("ferrum_agent_degraded"));
        assert!(!valid_name("9lives"));
        assert!(!valid_name("ferrum-agent"));
        assert!(!valid_name(""));
    }
}
