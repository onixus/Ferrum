//! The latency budget, measured rather than asserted.
//!
//! `ferrum_admission::REVIEW_LATENCY_BUDGET_SECONDS` is a number this product
//! states in public — in the boundary, on the dashboard, and to whoever has to
//! decide whether a fail-closed webhook belongs in front of their API server.
//! ROADMAP phase 1 says it in one line: *a p99 that is not measured is not
//! claimed.* This file is the measurement.
//!
//! ## What it measures, and with what
//!
//! The instrument is the one that ships. `WebhookState::handle` already times
//! every review into `ferrum_metrics::Histogram` and publishes it as
//! `ferrum_admission_review_seconds`; this file drives real AdmissionReviews
//! through a real `WebhookState` and then reads the p99 out of that same
//! histogram, through the same bucket boundaries a Grafana panel computes
//! `histogram_quantile` over. A second stopwatch here would be a second
//! measurement — it could pass while the shipped one is broken, and the number
//! an operator reads comes from the shipped one.
//!
//! The program is the one that ships too: `policies/examples/prod-restricted.yaml`
//! compiled by the real compiler and signed with the real signer, loaded
//! through `load_bundle`. Nothing is stubbed, so the signature verification
//! each image reference costs is in the number.
//!
//! ## Why it may not skip, and how it survives a slow machine anyway
//!
//! A benchmark that steps aside on a slow runner is the gate that can decide it
//! was not asked to run — the defect this repository is written against — and
//! `#[ignore]`, an env-var opt-in and a `if slow { return }` are all that same
//! thing wearing different clothes. So there is none of that here: this test
//! runs in a default `cargo test -p ferrum-testkit` on every machine.
//!
//! What makes that survivable is the choice of number, not a condition in the
//! code. The budget is three orders of magnitude below the `timeoutSeconds: 5`
//! the API server is configured with, and roughly two above what the work
//! costs; the margin absorbs a shared runner, and a run that still cannot make
//! it is telling the truth about the machine or about a change that put I/O on
//! the request path. `docs/MVP-1-BOUNDARY.md` names the hardware the reported
//! p99 was measured on, because a latency without a machine is a rumour.
//!
//! ## What it does not claim
//!
//! Not end-to-end admission latency. The socket, the TLS handshake, the API
//! server's queue and the network are outside `handle` and outside this file;
//! what an operator sees on `kubectl apply` is larger, and this repository has
//! never measured it. Not throughput, either: this drives a fixed number of
//! reviews and reads a quantile, it does not search for a saturation point.

use ferrum_admission::{
    encode_fsig, load_bundle, review_latency_budget_seconds, ReviewConfig, StaticLabels,
    WebhookState, IMAGE_SIGNATURE_ANNOTATION, REVIEW_LATENCY_BUDGET_DEBUG_SECONDS,
    REVIEW_LATENCY_BUDGET_SECONDS,
};
use ferrum_api::{ClusterSecurityPolicy, PolicyMode};
use ferrum_compiler::{bundle_digest_material, compile_cluster_policy};
use ferrum_crypto::{public_key_from_secret, sign_bundle};
use ferrum_ids::{ADMISSION_ABI, AGENT_ABI};
use ferrum_metrics::{Histogram, LATENCY_BUCKETS_SECONDS};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

/// RFC 8032 §7.1 test-1 seed: fixture only, not a prod key.
const SK: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// The namespace the review Pods are in, labelled the way `prod-restricted`'s
/// namespaceSelector wants. Without the label the policy does not apply and
/// every review returns from `program_applies` before doing any work — a
/// measurement of the cheapest path there is, dressed up as a p99.
const NS: &str = "payments";
const IMAGE: &str = "registry.internal.example/app@sha256:\
                     0000000000000000000000000000000000000000000000000000000000000000";

/// Reviews per worker thread. 4 × 2500 = 10 000 observations, so the 99th
/// percentile is decided by 100 samples rather than by one.
const REVIEWS_PER_THREAD: usize = 2_500;
/// Concurrent callers. The API server does not send reviews one at a time, and
/// `handle` clones the program under a read lock: contention on that lock is
/// part of the latency and a single-threaded run would not contain it.
const THREADS: usize = 4;
/// Discarded, on a state of its own so they land in no histogram this file
/// reads: first call through a code path pays for page faults, lazy statics and
/// a cold branch predictor, and none of that is what a webhook that has been up
/// for a week is doing.
const WARMUP: usize = 500;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// compile → sign → load: the shipped policy as the process would hold it.
fn shipped_program() -> ferrum_admission::AdmissionProgram {
    let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
    let mut obj: ClusterSecurityPolicy = serde_yaml::from_str(yaml).expect("example policy");
    obj.spec.mode = PolicyMode::Enforce;
    let pk = public_key_from_secret(&SK).expect("public key");
    obj.spec.supply.trust_roots[0].public_keys = vec![hex(&pk)];
    let bundle = compile_cluster_policy(&obj.spec).expect("compile prod-restricted");
    let frmb = bundle_digest_material(
        AGENT_ABI,
        ADMISSION_ABI,
        &bundle.admission_program,
        &bundle.ebpf_spec,
        &bundle.wasm,
    )
    .expect("frmb material");
    let sig = sign_bundle(&frmb, &SK).expect("sign");
    let fsig = encode_fsig(&frmb, &sig, &pk).expect("fsig");
    load_bundle(&fsig, &pk).expect("verify + parse")
}

fn state() -> WebhookState {
    let labels = StaticLabels::default()
        .warm()
        .with_namespace(
            NS,
            [("ferrum.io/zone".to_string(), "pci".to_string())]
                .into_iter()
                .collect(),
        )
        .with_service_account(NS, "default", BTreeMap::new());
    WebhookState::new(
        shipped_program(),
        public_key_from_secret(&SK).expect("public key"),
        Vec::new(),
        ReviewConfig {
            policy_name: "prod-restricted".into(),
            policy_namespace: String::new(),
            labels: Arc::new(labels),
        },
    )
}

fn review(object: Value, uid: &str) -> Vec<u8> {
    let ns = object
        .pointer("/metadata/namespace")
        .cloned()
        .unwrap_or(json!(""));
    serde_json::to_vec(&json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": uid,
            "namespace": ns,
            "operation": "CREATE",
            "object": object
        }
    }))
    .expect("review json")
}

/// `signed = true` carries a real Ed25519 signature over the image reference,
/// verified on the request path against the bundle's trust roots. It is the
/// most expensive single step in a review, so a benchmark whose Pods were all
/// unsigned would be timing the path that refuses before doing the work.
fn pod(name: &str, privileged: bool, image: &str, signed: bool) -> Value {
    let annotations = if signed {
        let sig = sign_bundle(image.as_bytes(), &SK).expect("image signature");
        json!({ IMAGE_SIGNATURE_ANNOTATION: hex(&sig) })
    } else {
        json!({})
    };
    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": NS,
            "labels": {"app": "checkout"},
            "annotations": annotations
        },
        "spec": {
            "serviceAccountName": "default",
            "containers": [
                {
                    "name": "app",
                    "image": image,
                    "securityContext": {
                        "privileged": privileged,
                        "runAsNonRoot": true,
                        "runAsUser": 65532,
                        "allowPrivilegeEscalation": false,
                        "capabilities": {"drop": ["ALL"]}
                    }
                },
                {
                    "name": "sidecar",
                    "image": image,
                    "securityContext": {
                        "runAsNonRoot": true,
                        "runAsUser": 65532,
                        "allowPrivilegeEscalation": false,
                        "capabilities": {"drop": ["ALL"]}
                    }
                }
            ]
        }
    })
}

fn cluster_role_binding() -> Value {
    json!({
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "break-glass"},
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": "ClusterRole",
            "name": "cluster-admin"
        },
        "subjects": [{"kind": "ServiceAccount", "name": "ops", "namespace": NS}]
    })
}

/// The four review shapes, in the proportion a cluster produces them: mostly
/// Pods, some of which are refused, and the cluster-scoped object that used to
/// be the expensive mistake.
fn bodies() -> Vec<Vec<u8>> {
    vec![
        review(pod("allowed", false, IMAGE, true), "uid-allow"),
        review(pod("privileged", true, IMAGE, true), "uid-privileged"),
        review(pod("unsigned", false, IMAGE, false), "uid-unsigned"),
        review(cluster_role_binding(), "uid-crb"),
    ]
}

/// The p99 as a Grafana panel would read it: the narrowest bucket boundary at
/// or below which 99% of the observations landed.
///
/// `None` means the top bucket does not hold 99% either, which for this ladder
/// means the observations are past 2.5 s.
fn p99_bucket(hist: &Histogram) -> Option<f64> {
    let count = hist.count();
    if count == 0 {
        return None;
    }
    // Ceil: with 10 000 observations the 99th percentile is the 9 900th, and a
    // truncating divide would let one observation past the boundary through.
    let needed = (count as f64 * 0.99).ceil() as u64;
    LATENCY_BUCKETS_SECONDS
        .iter()
        .enumerate()
        .find(|(i, _)| hist.bucket(*i) >= needed)
        .map(|(_, upper)| *upper)
}

/// What ran this, so a red run says where it was red. `available_parallelism`
/// rather than a core count: it is what a container's CPU limit actually leaves.
/// The build profile is in here because it changes the number by an order of
/// magnitude, and a reported p99 without it is not a comparable measurement.
fn machine() -> String {
    format!(
        "{}/{}, {} usable threads, {} build",
        std::env::consts::ARCH,
        std::env::consts::OS,
        std::thread::available_parallelism()
            .map(|n| n.to_string())
            .unwrap_or_else(|_| "unknown".into()),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    )
}

/// **The budget.** p99 of `handle` over 10 000 real reviews, concurrent, on the
/// shipped policy, read out of the shipped histogram.
#[test]
fn the_p99_of_a_review_stays_inside_the_declared_latency_budget() {
    // Warm-up on a throwaway state: its observations must not enter the
    // histogram that decides the verdict.
    let warm = state();
    for body in bodies() {
        for _ in 0..WARMUP {
            warm.handle(&body);
        }
    }

    let state = Arc::new(state());
    let bodies = Arc::new(bodies());
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            let state = Arc::clone(&state);
            let bodies = Arc::clone(&bodies);
            scope.spawn(move || {
                for i in 0..REVIEWS_PER_THREAD {
                    state.handle(&bodies[i % bodies.len()]);
                }
            });
        }
    });

    let hist = state.review_seconds();
    let expected = (THREADS * REVIEWS_PER_THREAD) as u64;
    assert_eq!(
        hist.count(),
        expected,
        "the histogram holds {} observations, not the {expected} this test drove: whatever it \
         measured, it is not what ran",
        hist.count()
    );
    assert!(
        hist.sum_seconds() > 0.0,
        "10 000 reviews took no time at all, which means the clock or the instrument is not \
         working and every verdict below is vacuous"
    );
    // Both verdicts, or the run measured one branch of the evaluator.
    assert!(
        state.reviews_allowed() > 0 && state.reviews_denied() > 0,
        "the run produced only one kind of verdict (allowed={}, denied={}): the review bodies \
         no longer exercise both the allow and the deny path",
        state.reviews_allowed(),
        state.reviews_denied()
    );

    let p99 = p99_bucket(hist);
    let median = hist.sum_seconds() / hist.count() as f64;
    println!(
        "ferrum_admission_review_seconds over {} reviews on {} threads, {}:\n  \
         mean {:.1} µs, p99 <= {}\n  buckets: {}",
        hist.count(),
        THREADS,
        machine(),
        median * 1e6,
        p99.map(|b| format!("{b} s"))
            .unwrap_or("2.5 s (top)".into()),
        LATENCY_BUCKETS_SECONDS
            .iter()
            .enumerate()
            .map(|(i, le)| format!("{le}={}", hist.bucket(i)))
            .collect::<Vec<_>>()
            .join(" ")
    );

    let p99 = p99.unwrap_or(f64::INFINITY);
    let budget = review_latency_budget_seconds();
    assert!(
        p99 <= budget,
        "p99 of an AdmissionReview is {p99} s, past the declared budget of {budget} s for this \
         build, on {}. The number this product states in public is \
         {REVIEW_LATENCY_BUDGET_SECONDS} s for the release build it ships (see \
         docs/MVP-1-BOUNDARY.md and deploy/observability/grafana-dashboard.json). Either the \
         request path grew work it is not supposed to do — a network call, a disk read, a lock \
         held across I/O — or the claim has to change everywhere it is written, and the second \
         is not something to do to make a build green.",
        machine()
    );
}

/// The budget has to be a boundary the shipped histogram can decide.
///
/// Between two boundaries there is no answer: the histogram knows only how many
/// observations fell in each bucket, so a budget of, say, 3 ms could be checked
/// only by interpolating inside the 2.5–5 ms bucket — asserting a resolution
/// the instrument does not have, in a build that would go green on it.
#[test]
fn the_budget_is_a_boundary_the_shipped_histogram_can_decide() {
    for (name, budget) in [
        (
            "REVIEW_LATENCY_BUDGET_SECONDS",
            REVIEW_LATENCY_BUDGET_SECONDS,
        ),
        (
            "REVIEW_LATENCY_BUDGET_DEBUG_SECONDS",
            REVIEW_LATENCY_BUDGET_DEBUG_SECONDS,
        ),
    ] {
        assert!(
            LATENCY_BUCKETS_SECONDS.contains(&budget),
            "{name} = {budget} is not one of the bucket boundaries {LATENCY_BUCKETS_SECONDS:?} \
             the histogram publishes, so no scrape of `ferrum_admission_review_seconds` can \
             decide it and neither can the test above"
        );
        assert!(
            budget < *LATENCY_BUCKETS_SECONDS.last().expect("ladder"),
            "{name} is the top of the ladder, so every observation the histogram can hold is \
             inside it and the gate cannot fail"
        );
    }
    // The debug budget is a concession to an unoptimized artefact, never a
    // relaxation of the claim: if it ever became the smaller of the two, a
    // release run would be held to the looser number and the product's own
    // claim would be the one nothing checks.
    assert!(
        REVIEW_LATENCY_BUDGET_DEBUG_SECONDS > REVIEW_LATENCY_BUDGET_SECONDS,
        "the debug budget ({REVIEW_LATENCY_BUDGET_DEBUG_SECONDS}) is not looser than the release \
         budget ({REVIEW_LATENCY_BUDGET_SECONDS}), so the two numbers no longer mean what their \
         names say"
    );
    assert_eq!(
        review_latency_budget_seconds(),
        if cfg!(debug_assertions) {
            REVIEW_LATENCY_BUDGET_DEBUG_SECONDS
        } else {
            REVIEW_LATENCY_BUDGET_SECONDS
        },
        "the budget in force does not match this build's profile"
    );
}

/// The control on the reader: a p99 past the budget must be a failure.
///
/// Without this, the verdict above passes on any reader that always says
/// "inside" — including one that reads an empty histogram, or one whose
/// percentile index is off by a bucket. So: feed the real `Histogram` an
/// observation set whose 99th percentile is deliberately past the budget, and
/// require the same function to say so.
#[test]
fn the_reader_notices_a_p99_that_is_past_the_budget() {
    let hist = Histogram::new();
    // 980 fast, 20 slow: 2% past the budget, so the 99th percentile is one of
    // the slow ones. Exactly 1% would not be — a distribution whose slowest
    // hundredth *begins* at the percentile is inside the budget by the same
    // definition Prometheus uses, and a control built on that case would fail a
    // correct reader.
    for _ in 0..980 {
        hist.observe(std::time::Duration::from_micros(50));
    }
    for _ in 0..20 {
        hist.observe(std::time::Duration::from_millis(400));
    }
    let p99 = p99_bucket(&hist).expect("a p99 inside the ladder");
    assert!(
        p99 > review_latency_budget_seconds(),
        "a distribution with 2% of its observations at 400 ms read as a p99 of {p99} s, inside \
         the {} s budget in force: the reader cannot fail and the gate above proves nothing",
        review_latency_budget_seconds()
    );

    // And the other direction: the same reader on a distribution that is
    // entirely inside the budget must not report a violation.
    let fast = Histogram::new();
    for _ in 0..1000 {
        fast.observe(std::time::Duration::from_micros(50));
    }
    assert!(
        p99_bucket(&fast).expect("a p99 inside the ladder") <= review_latency_budget_seconds(),
        "the reader reports a violation on a distribution that has none, so it fails on \
         everything and says nothing"
    );
}

/// The number is one number. It is stated in three places for three audiences —
/// the code, the operator's dashboard and the boundary document — and a
/// dashboard whose threshold disagrees with the code draws a red line where
/// nothing is wrong, or none where something is.
#[test]
fn the_dashboard_and_the_boundary_state_the_budget_the_code_enforces() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("workspace root");

    let dashboard: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("deploy/observability/grafana-dashboard.json"))
            .expect("dashboard"),
    )
    .expect("dashboard json");
    let panel = dashboard["panels"]
        .as_array()
        .expect("panels")
        .iter()
        .find(|p| {
            p["targets"].as_array().is_some_and(|t| {
                t.iter().any(|t| {
                    t["expr"]
                        .as_str()
                        .is_some_and(|e| e.contains("ferrum_admission_review_seconds_bucket"))
                })
            })
        })
        .expect("a panel charting ferrum_admission_review_seconds");
    let steps = panel["fieldConfig"]["defaults"]["thresholds"]["steps"]
        .as_array()
        .expect(
            "the review-latency panel carries a thresholds.steps list: a latency panel with no \
             budget drawn on it leaves the reader to remember the number",
        );
    let drawn: Vec<f64> = steps
        .iter()
        .filter_map(|s| s["value"].as_f64())
        .collect::<Vec<_>>();
    assert_eq!(
        drawn,
        vec![REVIEW_LATENCY_BUDGET_SECONDS],
        "the dashboard draws its budget at {drawn:?} while the code enforces \
         {REVIEW_LATENCY_BUDGET_SECONDS}"
    );

    let boundary = std::fs::read_to_string(root.join("docs/MVP-1-BOUNDARY.md")).expect("boundary");
    for budget in [
        REVIEW_LATENCY_BUDGET_SECONDS,
        REVIEW_LATENCY_BUDGET_DEBUG_SECONDS,
    ] {
        let stated = format!("{} мс", budget * 1000.0);
        assert!(
            boundary.contains(&stated),
            "docs/MVP-1-BOUNDARY.md does not state the budget as {stated:?}. The document is \
             where this product says what it claims; a budget the code holds and the boundary \
             does not name is a claim with no reader. Both numbers belong there — a document \
             that named only the release one would leave a reader unable to tell which of them \
             a green `cargo test` on their machine actually held."
        );
    }
}
