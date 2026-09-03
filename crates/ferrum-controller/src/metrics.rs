//! What this controller publishes about itself on a port.
//!
//! Until now it published `status.json` and nothing else, and the file is
//! mode 0600 on the Pod: an operator who wants to know whether policy is
//! converging has to `kubectl exec` into the control plane to find out. That
//! is the same shape as the hole `ROADMAP` closed for the agent one level
//! out — a number that exists, is correct, and has no reader.
//!
//! Two rules this module keeps, both borrowed from `ferrum-agent`:
//!
//! 1. **The exposition is a walk of the object that prints `status.json`.**
//!    Not a parallel set of counters that a future edit can leave one behind.
//!    Every family below is read from `ControllerHealth` or from the reconcile
//!    counters, and `FailureClass::ALL` is what it iterates, so a fifth class
//!    added to that enum appears here without this file being touched.
//! 2. **Label values are stable ids, never sentences.** `degraded_reasons()`
//!    returns prose — `"reconcile: 3 in a row, and no request of this class
//!    has ever succeeded; last: 403 Forbidden"` — which is right for a human
//!    reading the file and wrong for a series: it is reworded by any edit, and
//!    it carries the cause text, so the label set would be unbounded. What
//!    goes on the wire is `FailureClass::name()`, a fixed set of four, with
//!    the run and the never-succeeded flag beside it. The prose stays in
//!    `status.json`, which is where the cause is read during an incident.
//!
//! The port is opt-in — `--metrics-listen host:port`, the same grammar
//! `ferrum-agent` and `ferrum-admission` take — and the shipped manifest
//! passes `0.0.0.0:9104`. Nothing is bound when the flag is absent, which is
//! the deployment an operator gets on a cluster whose CNI does not enforce
//! NetworkPolicy and who would rather have no port at all.

use crate::health::{ControllerHealth, FailureClass, TERMINAL_RUN};
use ferrum_metrics::Exposition;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// The port the shipped manifest passes, after `ferrum-agent` and
/// `ferrum-admission` on 9102. Not a default inside the binary: a process that
/// opens a port nobody asked for is the thing `--metrics-listen` being
/// optional exists to prevent.
pub const SHIPPED_METRICS_PORT: u16 = 9104;

/// The three things about a reconcile that `ControllerHealth` does not hold.
///
/// Health counts what *failed against the API server*, by class. It has no
/// count of work done — a controller that has stopped receiving events and one
/// that is reconciling steadily are the same object to it — no memory of which
/// bundle came out, and no count of the policies that did not compile, because
/// a policy that fails to compile is not a failed request: the reconcile
/// succeeded and wrote a Failed status. That last one is kept apart rather
/// than folded into a general "errors" counter for exactly that reason. The
/// two are fixed by different people: a compile failure is the author of a
/// policy, a status_patch failure is whoever wrote the RBAC.
#[derive(Debug, Default)]
pub struct ControllerMetrics {
    reconcile_total: AtomicU64,
    compile_failures_total: AtomicU64,
    bundle_digest: RwLock<Option<String>>,
}

impl ControllerMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reconcile_total(&self) -> u64 {
        self.reconcile_total.load(Ordering::Relaxed)
    }

    pub fn compile_failures_total(&self) -> u64 {
        self.compile_failures_total.load(Ordering::Relaxed)
    }

    pub fn bundle_digest(&self) -> Option<String> {
        self.bundle_digest
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// One watch event taken up for reconciliation.
    ///
    /// Counted where the event arrives and not where it converges: the
    /// denominator of "how many of them failed" has to include the ones that
    /// failed.
    pub fn record_reconcile(&self) {
        self.reconcile_total.fetch_add(1, Ordering::Relaxed);
    }

    /// A policy the controller reconciled successfully and could not compile.
    pub fn record_compile_failure(&self) {
        self.compile_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_bundle_digest(&self, digest: impl Into<String>) {
        let mut held = self
            .bundle_digest
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *held = Some(digest.into());
    }
}

/// The families this controller publishes, read from the live objects.
///
/// Gauges that are always emitted, never conditionally: a series that vanishes
/// when the value is uninteresting cannot be told apart from a scrape that
/// failed, and every question on this port — is it converging, is a class
/// stuck, which digest did it sign — is one an operator asks *before* the
/// incident.
pub fn exposition(metrics: &ControllerMetrics, health: &ControllerHealth) -> Exposition {
    let mut out = Exposition::new();

    out.counter(
        "ferrum_controller_reconcile_total",
        "policy and namespaced-policy watch events this controller took up for reconciliation",
        metrics.reconcile_total(),
    );

    out.counter(
        "ferrum_controller_compile_failures_total",
        "policies that reconciled and did not compile; the object carries the reason in its \
         status, and this is not an API failure",
        metrics.compile_failures_total(),
    );

    // Per class, from the enum itself, under the same names `status.json`
    // uses: a reader of the file and a reader of a dashboard are looking at
    // the same number and can say so.
    for class in FailureClass::ALL {
        out.counter(
            &format!("ferrum_controller_{}_total", class.counter()),
            &format!("requests of class `{}` that failed", class.name()),
            health.failures(class),
        );
    }

    out.bool_gauge(
        "ferrum_controller_degraded",
        "1 when this controller has at least one reason in status.json; the reasons themselves \
         are prose and stay in the file",
        health.is_degraded(),
    );

    // The run, the threshold it is compared against, and whether the class has
    // ever worked — the three numbers the terminal rule in `health.rs` is
    // made of. An alert can be written against them without restating the
    // constant, which is the way the constant and the alert stay together.
    out.labelled_gauge(
        "ferrum_controller_failure_run",
        "consecutive failures of this class with nothing in between",
        FailureClass::ALL
            .iter()
            .map(|c| {
                (
                    vec![("class".to_string(), c.name().to_string())],
                    health.failure_run(*c),
                )
            })
            .collect(),
    );
    out.labelled_gauge(
        "ferrum_controller_class_never_succeeded",
        "1 when no request of this class has ever succeeded; with a run at ferrum_controller_\
         terminal_run this is the deployment being wrong rather than an object being bad",
        FailureClass::ALL
            .iter()
            .map(|c| {
                (
                    vec![("class".to_string(), c.name().to_string())],
                    u64::from(!health.ever_succeeded(*c)),
                )
            })
            .collect(),
    );
    out.gauge(
        "ferrum_controller_terminal_run",
        "the run at which a class that never succeeded ends the process, from TERMINAL_RUN",
        TERMINAL_RUN,
    );

    // Objects no retry will mend. Distinct from a failure run, which recovers
    // on its own: this is work that stays undone until a human edits something.
    out.labelled_gauge(
        "ferrum_controller_unactionable_objects",
        "objects of this class this controller cannot act on and no retry will mend",
        FailureClass::ALL
            .iter()
            .map(|c| {
                (
                    vec![("class".to_string(), c.name().to_string())],
                    health.unactionable(*c).len() as u64,
                )
            })
            .collect(),
    );

    // The reporting surface reporting on itself, as the agent does: when the
    // file cannot be written, this port is the only reader left.
    out.bool_gauge(
        "ferrum_controller_status_write_failed",
        "1 when status.json could not be written, so this port is the only surface left",
        health.status_write_failed(),
    );
    out.counter(
        "ferrum_controller_status_write_failures_total",
        "failed writes of status.json",
        health.status_write_failures(),
    );

    // Named like its two siblings, and charted beside them: the controller
    // signs a bundle, the webhook and the agents load one, and a rollout that
    // did not land is those three digests disagreeing.
    out.labelled_gauge(
        "ferrum_controller_bundle_info",
        "1, labelled with the digest of the bundle this controller last signed or observed \
         converged; empty means it has signed none since it started",
        vec![(
            vec![(
                "digest".to_string(),
                metrics.bundle_digest().unwrap_or_default(),
            )],
            1,
        )],
    );

    out
}

/// The whole response body as Prometheus exposition text.
pub fn metrics_text(metrics: &ControllerMetrics, health: &ControllerHealth) -> String {
    exposition(metrics, health).render()
}

/// Answer scrapes on `listener` until it stops, on a thread of its own.
///
/// A thread and not a task: this port must answer while the reconcile loop is
/// blocked, because "the controller stopped converging" is exactly the state
/// it is scraped for.
pub fn spawn_metrics(
    listener: std::net::TcpListener,
    metrics: std::sync::Arc<ControllerMetrics>,
    health: std::sync::Arc<ControllerHealth>,
) {
    std::thread::spawn(move || {
        let render = move || metrics_text(metrics.as_ref(), health.as_ref());
        if let Err(err) =
            ferrum_metrics::serve_listener(listener, ferrum_metrics::ServeConfig::default(), render)
        {
            eprintln!("ferrum-controller: metrics listener stopped: {err}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::Requested;

    #[test]
    fn a_fresh_process_publishes_every_family_and_hides_none() {
        let metrics = ControllerMetrics::new();
        let health = ControllerHealth::new();
        let exp = exposition(&metrics, &health);
        assert_eq!(
            exp.family_names(),
            vec![
                "ferrum_controller_reconcile_total",
                "ferrum_controller_compile_failures_total",
                "ferrum_controller_reconcile_failures_total",
                "ferrum_controller_status_patch_failures_total",
                "ferrum_controller_watch_errors_total",
                "ferrum_controller_exception_publish_failures_total",
                "ferrum_controller_degraded",
                "ferrum_controller_failure_run",
                "ferrum_controller_class_never_succeeded",
                "ferrum_controller_terminal_run",
                "ferrum_controller_unactionable_objects",
                "ferrum_controller_status_write_failed",
                "ferrum_controller_status_write_failures_total",
                "ferrum_controller_bundle_info",
            ]
        );

        let text = metrics_text(&metrics, &health);
        assert!(
            text.contains("ferrum_controller_reconcile_total 0"),
            "{text}"
        );
        assert!(
            text.contains("ferrum_controller_compile_failures_total 0"),
            "{text}"
        );
        assert!(text.contains("ferrum_controller_degraded 0"), "{text}");
        assert!(
            text.contains(&format!("ferrum_controller_terminal_run {TERMINAL_RUN}")),
            "{text}"
        );
        // Every class has a series before anything has failed, so a stuck
        // class is a value changing rather than a series appearing.
        for class in FailureClass::ALL {
            assert!(
                text.contains(&format!(
                    "ferrum_controller_failure_run{{class=\"{}\"}} 0",
                    class.name()
                )),
                "{} missing from {text}",
                class.name()
            );
            assert!(
                text.contains(&format!(
                    "ferrum_controller_class_never_succeeded{{class=\"{}\"}} 1",
                    class.name()
                )),
                "{} missing from {text}",
                class.name()
            );
        }
        assert!(
            text.contains("ferrum_controller_bundle_info{digest=\"\"} 1"),
            "{text}"
        );
    }

    /// The port says what the file says, on the same object, in the one state
    /// an operator cares about: a class that is failing and has never worked.
    #[test]
    fn a_class_that_never_worked_is_readable_without_the_status_file() {
        let metrics = ControllerMetrics::new();
        let health = ControllerHealth::new();

        metrics.record_reconcile();
        metrics.record_reconcile();
        metrics.record_compile_failure();
        metrics.set_bundle_digest("abcdef1234567890abcdef1234567890");
        health.note_success(Requested::of(FailureClass::Watch));
        for _ in 0..3 {
            health
                .note_failure(FailureClass::StatusPatch, "403 Forbidden")
                .expect("three is under the terminal run");
        }

        let text = metrics_text(&metrics, &health);
        assert!(
            text.contains("ferrum_controller_reconcile_total 2"),
            "{text}"
        );
        // A policy that did not compile is counted apart from the requests
        // that failed: one is the policy author's, the other the operator's.
        assert!(
            text.contains("ferrum_controller_compile_failures_total 1"),
            "{text}"
        );
        assert!(
            text.contains("ferrum_controller_status_patch_failures_total 3"),
            "{text}"
        );
        assert!(
            text.contains("ferrum_controller_failure_run{class=\"status_patch\"} 3"),
            "{text}"
        );
        assert!(
            text.contains("ferrum_controller_class_never_succeeded{class=\"status_patch\"} 1"),
            "{text}"
        );
        // The class that did work says so, which is what separates a bad
        // object from a deployment that was never right.
        assert!(
            text.contains("ferrum_controller_class_never_succeeded{class=\"watch\"} 0"),
            "{text}"
        );
        assert!(text.contains("ferrum_controller_degraded 1"), "{text}");
        assert!(
            text.contains(
                "ferrum_controller_bundle_info{digest=\"abcdef1234567890abcdef1234567890\"} 1"
            ),
            "{text}"
        );

        // And the prose stays where the prose belongs: no cause text reached
        // a label.
        assert!(!text.contains("403 Forbidden"), "{text}");
    }

    /// A class added to the enum has to appear on the port without this file
    /// being edited, which is the whole of rule 1 in the module comment.
    #[test]
    fn every_failure_class_is_walked_rather_than_listed() {
        let names = metrics_text(&ControllerMetrics::new(), &ControllerHealth::new());
        for class in FailureClass::ALL {
            assert!(
                names.contains(&format!("ferrum_controller_{}_total", class.counter())),
                "{} has no counter on the port",
                class.counter()
            );
        }
    }
}
