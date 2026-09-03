//! Prometheus metrics exposition for `ferrum-controller`.
//!
//! Exposes reconcile counters and active bundle digest on port 9104 (or configured port)
//! matching the pattern established by `ferrum-admission` (9102) and `ferrum-agent` (9103).

use ferrum_metrics::Exposition;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Default Prometheus exposition port for `ferrum-controller`.
pub const DEFAULT_METRICS_PORT: u16 = 9104;

/// Controller metrics state updated by the watch and reconcile loops.
#[derive(Debug, Default)]
pub struct ControllerMetrics {
    reconcile_total: AtomicU64,
    reconcile_errors_total: AtomicU64,
    bundle_digest: RwLock<Option<String>>,
}

impl ControllerMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_counts(
        reconcile_total: u64,
        reconcile_errors_total: u64,
        bundle_digest: Option<String>,
    ) -> Self {
        Self {
            reconcile_total: AtomicU64::new(reconcile_total),
            reconcile_errors_total: AtomicU64::new(reconcile_errors_total),
            bundle_digest: RwLock::new(bundle_digest),
        }
    }

    pub fn reconcile_total(&self) -> u64 {
        self.reconcile_total.load(Ordering::Relaxed)
    }

    pub fn reconcile_errors_total(&self) -> u64 {
        self.reconcile_errors_total.load(Ordering::Relaxed)
    }

    pub fn bundle_digest(&self) -> Option<String> {
        self.bundle_digest
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn record_reconcile(&self) {
        self.reconcile_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_reconcile_error(&self) {
        self.reconcile_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_bundle_digest(&self, digest: impl Into<String>) {
        let mut held = self
            .bundle_digest
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *held = Some(digest.into());
    }

    pub fn exposition(&self) -> Exposition {
        exposition(self)
    }

    pub fn metrics_text(&self) -> String {
        metrics_text(self)
    }
}

/// The families this controller publishes, read from the live process.
pub fn exposition(metrics: &ControllerMetrics) -> Exposition {
    let mut out = Exposition::new();
    out.counter(
        "ferrum_controller_reconcile_total",
        "total reconciliations performed by the controller",
        metrics.reconcile_total(),
    );
    out.counter(
        "ferrum_controller_reconcile_errors_total",
        "total failed reconciliations",
        metrics.reconcile_errors_total(),
    );
    let digest = metrics.bundle_digest().unwrap_or_default();
    out.labelled_gauge(
        "ferrum_controller_bundle_digest",
        "active policy bundle digest",
        vec![(vec![("digest".to_string(), digest)], 1)],
    );
    out
}

/// The whole response body as Prometheus exposition text.
pub fn metrics_text(metrics: &ControllerMetrics) -> String {
    exposition(metrics).render()
}

/// Bind a TCP listener on 0.0.0.0:port (or fallback to 127.0.0.1:port).
pub fn bind_metrics_listener(port: u16) -> std::io::Result<std::net::TcpListener> {
    std::net::TcpListener::bind(("0.0.0.0", port))
        .or_else(|_| std::net::TcpListener::bind(("127.0.0.1", port)))
}

/// Answer scrapes on `listener` until it stops, on a thread of its own.
pub fn spawn_metrics(listener: std::net::TcpListener, metrics: std::sync::Arc<ControllerMetrics>) {
    std::thread::spawn(move || {
        let render = move || metrics_text(metrics.as_ref());
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

    #[test]
    fn exposition_family_names_and_rendering() {
        let metrics = ControllerMetrics::new();
        let exp = exposition(&metrics);
        assert_eq!(
            exp.family_names(),
            vec![
                "ferrum_controller_reconcile_total",
                "ferrum_controller_reconcile_errors_total",
                "ferrum_controller_bundle_digest"
            ]
        );

        let text = metrics_text(&metrics);
        assert!(text.contains("# HELP ferrum_controller_reconcile_total"));
        assert!(text.contains("# TYPE ferrum_controller_reconcile_total counter"));
        assert!(text.contains("ferrum_controller_reconcile_total 0"));
        assert!(text.contains("# HELP ferrum_controller_reconcile_errors_total"));
        assert!(text.contains("# TYPE ferrum_controller_reconcile_errors_total counter"));
        assert!(text.contains("ferrum_controller_reconcile_errors_total 0"));
        assert!(text.contains("# HELP ferrum_controller_bundle_digest"));
        assert!(text.contains("# TYPE ferrum_controller_bundle_digest gauge"));
        assert!(text.contains("ferrum_controller_bundle_digest{digest=\"\"} 1"));

        metrics.record_reconcile();
        metrics.record_reconcile();
        metrics.record_reconcile_error();
        metrics.set_bundle_digest("abcdef1234567890abcdef1234567890");

        assert_eq!(metrics.reconcile_total(), 2);
        assert_eq!(metrics.reconcile_errors_total(), 1);
        assert_eq!(
            metrics.bundle_digest().as_deref(),
            Some("abcdef1234567890abcdef1234567890")
        );

        let text2 = metrics_text(&metrics);
        assert!(text2.contains("ferrum_controller_reconcile_total 2"));
        assert!(text2.contains("ferrum_controller_reconcile_errors_total 1"));
        assert!(text2.contains(
            "ferrum_controller_bundle_digest{digest=\"abcdef1234567890abcdef1234567890\"} 1"
        ));
    }
}
