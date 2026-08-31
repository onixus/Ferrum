//! `/metrics` for the webhook.
//!
//! On its own listener and its own port, never on 8443. Three reasons, and the
//! first is the one that decides it:
//!
//!  * 8443 is served with the certificate the API server pins through
//!    `caBundle`. Putting the scrape there makes the offline PKI that
//!    `ferrumctl gen-webhook-pki` issues into a monitoring dependency: every
//!    Prometheus that wants a p99 needs that CA, and rotating the serving cert
//!    becomes a monitoring outage as well as an admission one.
//!  * The webhook port answers `POST` only. A `GET` there reads as 405 today,
//!    which is what the readiness probe was written around; teaching it a
//!    second verb would change the surface the API server talks to in order to
//!    serve something the API server never asks for.
//!  * Two ports can be governed separately, and they are: the manifests let
//!    the API server reach 8443 and let a labelled monitoring namespace reach
//!    the metrics port, and nothing else reaches either.
//!
//! What this endpoint does **not** publish is as deliberate as what it does.
//! No policy name, no rule id, no namespace, no image reference, no per-object
//! label of any kind: a webhook that reported which rule denied what would
//! hand an attacker inside the cluster a map of the policy and a way to probe
//! it one Pod at a time. The one identifier here is the bundle digest — a
//! content hash, which names no policy and is the only thing that answers "is
//! this replica on the bundle the controller published".

use ferrum_metrics::Exposition;

use crate::server::WebhookState;

/// The families this webhook publishes, read from the live process.
pub fn exposition(state: &WebhookState) -> Exposition {
    let mut out = Exposition::new();
    out.histogram(
        "ferrum_admission_review_seconds",
        "wall time spent inside handle() per AdmissionReview: the span the API server is \
         blocked on in this process, with the socket and the TLS handshake outside it",
        state.review_seconds(),
    );
    out.counter(
        "ferrum_admission_reviews_allowed_total",
        "AdmissionReviews this replica answered allow",
        state.reviews_allowed(),
    );
    out.counter(
        "ferrum_admission_reviews_denied_total",
        "AdmissionReviews this replica refused: a policy deny, a fail-closed bundle, or a \
         request it could not read",
        state.reviews_denied(),
    );
    out.gauge(
        "ferrum_admission_exceptions_active",
        "approved waivers this replica would apply right now",
        state.exception_count() as u64,
    );
    out.counter(
        "ferrum_admission_exceptions_resets_total",
        "times an unverifiable exception source emptied the waiver table; every waiver it held \
         now denies",
        state.exceptions_resets(),
    );
    out.counter(
        "ferrum_admission_exceptions_cleared_total",
        "times the waiver table was emptied because the source key is absent, which is a legal \
         state and still drops every approved waiver",
        state.exceptions_clears(),
    );
    out.counter(
        "ferrum_admission_bundle_unreadable_total",
        "times the bundle mount answered a stat with neither a readable file nor ENOENT: a poll \
         loop that has stopped seeing the changes it exists to see",
        state.bundle_unreadable(),
    );
    out.counter(
        "ferrum_admission_bundle_absent_total",
        "times the bundle key went missing from the mount, leaving this replica enforcing a \
         program whose source is gone",
        state.bundle_absent(),
    );
    // Always emitted, empty digest included: a replica that has loaded no
    // bundle is a different state from a replica this scrape did not reach,
    // and a family that disappears cannot tell the two apart.
    out.labelled_gauge(
        "ferrum_admission_bundle_info",
        "1, labelled with the digest of the PolicyBundle whose program is in force; empty means \
         none has been loaded",
        vec![(
            vec![(
                "digest".into(),
                state
                    .bundle_digest()
                    .map(|d| d.as_str().to_string())
                    .unwrap_or_default(),
            )],
            1,
        )],
    );
    break_glass_families(&mut out, state);
    out.labelled_gauge(
        "ferrum_admission_info",
        "1, labelled with the version of this webhook",
        vec![(
            vec![("version".into(), env!("CARGO_PKG_VERSION").into())],
            1,
        )],
    );
    out
}

/// The break-glass families, published by every replica whether or not it was
/// armed.
///
/// Always emitted, for the reason `ferrum_admission_bundle_info` is: a series
/// that disappears when nothing is happening cannot be told from a scrape that
/// failed, and "is break-glass armed on this cluster" is a question an operator
/// must be able to answer *before* the incident rather than during it. A
/// replica that was never armed publishes `configured 0`, which is a different
/// and readable state from `active 0`.
///
/// What is deliberately not here: `subject`, `issuer`, `reason` and `ticket`.
/// This port is reachable from a labelled monitoring namespace, and three of
/// those are a person and the fourth is an incident reference; the journal and
/// the container log carry them, and both are surfaces an operator governs
/// separately. What is here is the head of the chain — a hash, which names
/// nobody — and it is here on purpose: a Prometheus that stores it is holding
/// the off-node anchor that makes the chain worth having.
fn break_glass_families(out: &mut Exposition, state: &WebhookState) {
    let armed = state.break_glass();
    let now = chrono::Utc::now();
    let held = armed.and_then(|bg| bg.active(now));
    out.bool_gauge(
        "ferrum_admission_break_glass_configured",
        "1 when this replica was started with a break-glass mount and a writable journal; 0 \
         means the emergency suspension is unavailable on this cluster",
        armed.is_some(),
    );
    out.bool_gauge(
        "ferrum_admission_break_glass_active",
        "1 while a verified grant is suspending policy evaluation in this replica: every \
         AdmissionReview is being answered allow without evaluating anything",
        held.is_some(),
    );
    out.gauge(
        "ferrum_admission_break_glass_expires_in_seconds",
        "seconds left on the grant in force; 0 when none is",
        held.as_ref()
            .map(|g| g.remaining_seconds(now).max(0) as u64)
            .unwrap_or(0),
    );
    out.counter(
        "ferrum_admission_break_glass_admits_total",
        "AdmissionReviews this replica allowed because a grant was in force rather than because \
         a policy said so; not derivable from the allow total",
        armed.map(|bg| bg.admits()).unwrap_or(0),
    );
    out.counter(
        "ferrum_admission_break_glass_activations_total",
        "grants that came into force in this replica",
        armed.map(|bg| bg.activations()).unwrap_or(0),
    );
    out.counter(
        "ferrum_admission_break_glass_rejections_total",
        "grant documents this replica refused: a bad signature, an expired or over-long window, \
         a scope it does not honour. Every poll counts, so a retried forgery is visible here \
         even though the journal records it once",
        armed.map(|bg| bg.rejections()).unwrap_or(0),
    );
    out.counter(
        "ferrum_admission_break_glass_journal_entries_total",
        "entries in this replica's break-glass journal chain",
        armed.map(|bg| bg.journal_entries()).unwrap_or(0),
    );
    out.bool_gauge(
        "ferrum_admission_break_glass_journal_broken",
        "1 when the journal stopped accepting entries after start-up; while this is 1 no grant \
         can come into force, because a suspension that cannot be recorded is not taken",
        armed
            .map(|bg| bg.journal_broken().is_some())
            .unwrap_or(false),
    );
    out.labelled_gauge(
        "ferrum_admission_break_glass_journal_info",
        "1, labelled with the head hash of this replica's journal chain. Storing it is what \
         makes the chain tamper-evident: an edit is visible to anybody holding an older head",
        vec![(
            vec![(
                "head".into(),
                armed.map(|bg| bg.journal_head()).unwrap_or_default(),
            )],
            1,
        )],
    );
}

/// The whole response body.
pub fn metrics_text(state: &WebhookState) -> String {
    exposition(state).render()
}

/// Answer scrapes on `listener` until it fails, on a thread of its own.
///
/// The listener arrives bound: see `ferrum-agent`'s equivalent for why. The
/// render takes the same read locks a review takes and holds them for the
/// length of a format, which is why the histogram is atomics — a scrape must
/// not be able to queue behind a bundle swap and a bundle swap must not be
/// able to queue behind a scrape.
pub fn spawn_metrics(listener: std::net::TcpListener, state: std::sync::Arc<WebhookState>) {
    std::thread::spawn(move || {
        let render = move || metrics_text(state.as_ref());
        if let Err(err) =
            ferrum_metrics::serve_listener(listener, ferrum_metrics::ServeConfig::default(), render)
        {
            // Not fatal. This process denies Pods when it is unhealthy; ending
            // it because a monitoring socket failed would turn a metrics fault
            // into a cluster-wide admission outage, which is the trade
            // `failurePolicy: Fail` makes it impossible to take back.
            eprintln!("ferrum-admission: metrics listener stopped: {err}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::AdmissionProgram;
    use crate::review::ReviewConfig;
    use ferrum_api::{AdmitSpec, PolicyMode, PolicySelector, SupplySpec};

    fn state() -> WebhookState {
        let program = AdmissionProgram {
            abi: crate::ADMISSION_ABI,
            mode: PolicyMode::Enforce,
            disabled: false,
            priority: 0,
            supply: SupplySpec::default(),
            admit: AdmitSpec::default(),
            selector: PolicySelector::default(),
        };
        WebhookState::new(program, vec![0u8; 32], Vec::new(), ReviewConfig::default())
    }

    /// A fresh process publishes every family with a zero in it, rather than
    /// publishing nothing until something happens. A dashboard panel over an
    /// absent series reads "No data", which is the same thing it reads when
    /// the scrape failed.
    #[test]
    fn a_webhook_that_has_seen_no_review_still_publishes_every_family() {
        let text = metrics_text(&state());
        for family in [
            "ferrum_admission_review_seconds",
            "ferrum_admission_reviews_allowed_total",
            "ferrum_admission_reviews_denied_total",
            "ferrum_admission_exceptions_active",
            "ferrum_admission_bundle_info",
        ] {
            assert!(
                text.contains(&format!("# TYPE {family} ")),
                "{family} is absent from a fresh render:\n{text}"
            );
        }
        assert!(
            text.contains("ferrum_admission_reviews_allowed_total 0\n"),
            "{text}"
        );
        assert!(
            text.contains("ferrum_admission_bundle_info{digest=\"\"} 1\n"),
            "a replica with no bundle published no digest series at all:\n{text}"
        );
    }

    /// The counters are the request path's, not the renderer's: a review that
    /// was refused moves the denied counter and the histogram, and nothing has
    /// to be scraping for that to happen.
    #[test]
    fn a_refused_review_is_counted_and_timed_without_a_scraper() {
        let state = state();
        let before = metrics_text(&state);
        assert!(before.contains("ferrum_admission_review_seconds_count 0\n"));
        // No uid: HTTP 400, which the API server under failurePolicy: Fail
        // treats as a refusal, so it must not land on the allow side.
        let reply = state.handle(br#"{"request":{}}"#);
        assert_eq!(reply.status, 400);
        assert!(!reply.allowed);
        let after = metrics_text(&state);
        assert!(
            after.contains("ferrum_admission_reviews_denied_total 1\n"),
            "{after}"
        );
        assert!(
            after.contains("ferrum_admission_reviews_allowed_total 0\n"),
            "{after}"
        );
        assert!(
            after.contains("ferrum_admission_review_seconds_count 1\n"),
            "{after}"
        );
    }
}
