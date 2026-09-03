//! Watch ClusterSecurityPolicy, SecurityPolicy and PolicyException as
//! DynamicObject. Not kube::runtime::Controller, no kube-derive (rustc 1.75).

use crate::apply::{
    live_secret_matches, load_bundle_secret, namespaced_secret_name, patch_secret_exceptions,
    patch_status_dynamic, persist, persist_class, persist_dynamic, persist_exceptions, plan_apply,
    plan_apply_namespaced, secret_name, ApplyPlan,
};
use crate::health::{ControllerHealth, FailureClass, Requested};
use crate::metrics::{spawn_metrics, ControllerMetrics};
use crate::{
    compile_status_err, exception_status_patch, reconcile, reconcile_exception,
    reconcile_namespaced, NamespacedReconcileInput, ObservedException, ObservedNamespacedPolicy,
    ObservedPolicy, ReconcileInput, ReconcileOutcome, WatchConfig,
};
use ferrum_api::{
    ClusterSecurityPolicySpec, PolicyExceptionSpec, PolicyExceptionStatus, PolicyStatus,
    RolloutStatus, SecurityPolicySpec,
};
use ferrum_common::{FerrumError, Result};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ApiResource, DynamicObject, GroupVersionKind};
use kube::runtime::{watcher, WatchStreamExt};
use kube::Client;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub fn cluster_security_policy_gvk() -> GroupVersionKind {
    GroupVersionKind::gvk(
        ferrum_api::GROUP,
        ferrum_api::VERSION,
        "ClusterSecurityPolicy",
    )
}

pub fn cluster_security_policy_resource() -> ApiResource {
    ApiResource::from_gvk(&cluster_security_policy_gvk())
}

pub fn security_policy_gvk() -> GroupVersionKind {
    GroupVersionKind::gvk(ferrum_api::GROUP, ferrum_api::VERSION, "SecurityPolicy")
}

pub fn security_policy_resource() -> ApiResource {
    ApiResource::from_gvk(&security_policy_gvk())
}

pub fn policy_exception_gvk() -> GroupVersionKind {
    GroupVersionKind::gvk(ferrum_api::GROUP, ferrum_api::VERSION, "PolicyException")
}

pub fn policy_exception_resource() -> ApiResource {
    ApiResource::from_gvk(&policy_exception_gvk())
}

pub fn observe_policy(obj: &DynamicObject) -> Result<ObservedPolicy> {
    let name = require_name(obj, "ClusterSecurityPolicy")?;
    let generation = obj.metadata.generation.unwrap_or(0);
    let resource_version = obj.metadata.resource_version.clone().unwrap_or_default();
    let spec: ClusterSecurityPolicySpec = decode_spec(obj, "ClusterSecurityPolicy")?;
    Ok(ObservedPolicy {
        name,
        generation,
        resource_version,
        spec,
    })
}

pub fn observe_namespaced_policy(obj: &DynamicObject) -> Result<ObservedNamespacedPolicy> {
    let name = require_name(obj, "SecurityPolicy")?;
    let namespace = require_namespace(obj, "SecurityPolicy")?;
    let generation = obj.metadata.generation.unwrap_or(0);
    let resource_version = obj.metadata.resource_version.clone().unwrap_or_default();
    let spec: SecurityPolicySpec = decode_spec(obj, "SecurityPolicy")?;
    Ok(ObservedNamespacedPolicy {
        name,
        namespace,
        generation,
        resource_version,
        spec,
    })
}

/// Missing/invalid spec (e.g. no expiresAt) is a Validation error the caller
/// records in the object's status; the exception never becomes live.
pub fn observe_exception(obj: &DynamicObject) -> Result<ObservedException> {
    let name = require_name(obj, "PolicyException")?;
    let namespace = require_namespace(obj, "PolicyException")?;
    let spec: PolicyExceptionSpec = decode_spec(obj, "PolicyException")?;
    Ok(ObservedException {
        name,
        namespace,
        spec,
    })
}

fn require_name(obj: &DynamicObject, kind: &str) -> Result<String> {
    obj.metadata
        .name
        .clone()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| FerrumError::Validation(format!("{kind} metadata.name is missing")))
}

fn require_namespace(obj: &DynamicObject, kind: &str) -> Result<String> {
    obj.metadata
        .namespace
        .clone()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| FerrumError::Validation(format!("{kind} metadata.namespace is missing")))
}

fn decode_spec<T: serde::de::DeserializeOwned>(obj: &DynamicObject, kind: &str) -> Result<T> {
    let spec_val = match &obj.data {
        serde_json::Value::Object(map) => map.get("spec"),
        _ => None,
    };
    match spec_val {
        None | Some(serde_json::Value::Null) => {
            Err(FerrumError::Validation(format!("{kind} spec is missing")))
        }
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|e| FerrumError::Validation(format!("{kind} spec: {e}"))),
    }
}

fn status_compile(obj: &DynamicObject) -> (Option<i64>, bool, String) {
    let Some(status) = obj.data.get("status") else {
        return (None, false, String::new());
    };
    let observed = status.get("observedGeneration").and_then(|v| v.as_i64());
    let compile = status.get("compile");
    let ready = compile
        .and_then(|c| c.get("ready"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let digest = compile
        .and_then(|c| c.get("bundleDigest"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    (observed, ready, digest)
}

/// Skip Applied only when this generation is ready **and** the live Secret verifies.
/// Failed compile never skips as success, even if a leftover Secret exists.
pub(crate) fn should_skip_applied(
    generation: i64,
    observed_generation: Option<i64>,
    compile_ready: bool,
    expected_digest: &str,
    secret: Option<&Secret>,
    trust_root: &[u8],
) -> bool {
    if observed_generation != Some(generation) || !compile_ready || expected_digest.is_empty() {
        return false;
    }
    match secret {
        Some(secret) => live_secret_matches(secret, trust_root, expected_digest),
        None => false,
    }
}

fn failed_status_already_recorded(obj: &DynamicObject, generation: i64, plan: &ApplyPlan) -> bool {
    if plan.secret.is_some() {
        return false;
    }
    let plan_ready = plan.status["status"]["compile"]["ready"]
        .as_bool()
        .unwrap_or(true);
    if plan_ready {
        return false;
    }
    let (og, ready, digest) = status_compile(obj);
    og == Some(generation) && !ready && digest.is_empty()
}

/// Live exceptions keyed by `namespace/name` so revoked objects drop out.
type ExceptionSet = Arc<Mutex<BTreeMap<String, PolicyExceptionSpec>>>;

fn snapshot_exceptions(set: &ExceptionSet) -> Vec<PolicyExceptionSpec> {
    set.lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .cloned()
        .collect()
}

/// How often `status.json` is rewritten when nothing has happened.
///
/// The file is also published whenever a counter moves, so this interval is
/// only what keeps `ts` from going stale on a healthy controller: a reader
/// that finds an old timestamp is looking at a process that stopped.
const STATUS_INTERVAL: Duration = Duration::from_secs(15);

/// A failure together with the class of API call it came from.
///
/// The class is decided at the call site and never by reading the message: a
/// classifier that switches on error text is exactly the shape this tree keeps
/// having to delete.
struct Classified {
    class: FailureClass,
    err: FerrumError,
}

/// `Ok` or one classified failure. Distinct from `Result<()>`, which in the
/// loops below means «terminal, leave».
type Classed = std::result::Result<(), Classified>;

fn as_class(class: FailureClass) -> impl Fn(FerrumError) -> Classified {
    move |err| Classified { class, err }
}

/// Install the process-wide rustls provider before the first `kube::Client`.
///
/// `kube` builds its TLS stack through `rustls::ClientConfig::builder()`, which
/// reads a process-wide `CryptoProvider` and panics when none is installed. It
/// installs one itself only under its `aws-lc-rs` feature, which this tree does
/// not carry (ring everywhere, and the release binaries are static musl). So
/// the provider is installed here, before any client exists: without it the
/// controller panics inside rustls on the first line of `run_watch` — before a
/// watch, before a counter, before any status file could say why.
pub(crate) fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Err means another thread installed one first, which is the outcome
        // this asks for.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

pub async fn run_watch(cfg: WatchConfig) -> Result<()> {
    install_crypto_provider();
    let client = Client::try_default()
        .await
        .map_err(|e| FerrumError::Degraded(format!("kube client: {e}")))?;
    let exceptions: ExceptionSet = Arc::new(Mutex::new(BTreeMap::new()));
    let health = Arc::new(ControllerHealth::new());
    let metrics = Arc::new(ControllerMetrics::new());

    // Bound before the first watch is opened, and a failure to bind ends the
    // process rather than being logged: an operator who asked for a port and
    // got a running controller with no port has a scrape target that never
    // appears, which reads the same as a controller that is not running. The
    // same choice `ferrum-admission` makes for the same flag.
    if let Some(addr) = cfg.metrics_listen.as_deref() {
        let listener = std::net::TcpListener::bind(addr)
            .map_err(|e| FerrumError::Degraded(format!("bind --metrics-listen {addr}: {e}")))?;
        eprintln!(
            "ferrum-controller: metrics on {addr}{}",
            ferrum_metrics::METRICS_PATH
        );
        spawn_metrics(listener, Arc::clone(&metrics), Arc::clone(&health));
    }

    // Published before the first event, so an operator who finds no file at
    // all knows the process never reached its watches rather than that it is
    // idle.
    health.publish(cfg.status_dir.as_deref());
    tokio::select! {
        r = run_cluster_policy_watch(&client, &cfg, &exceptions, &health, &metrics) => r,
        r = run_namespaced_policy_watch(&client, &cfg, &exceptions, &health, &metrics) => r,
        r = run_exception_watch(&client, &cfg, &exceptions, &health) => r,
        r = publish_status(&cfg, &health) => r,
    }
}

/// Keeps the published file fresh. Never returns and never fails: a status
/// surface that can end the process is a probe, and this one is not.
async fn publish_status(cfg: &WatchConfig, health: &ControllerHealth) -> Result<()> {
    loop {
        tokio::time::sleep(STATUS_INTERVAL).await;
        health.publish(cfg.status_dir.as_deref());
    }
}

async fn run_cluster_policy_watch(
    client: &Client,
    cfg: &WatchConfig,
    exceptions: &ExceptionSet,
    health: &ControllerHealth,
    metrics: &ControllerMetrics,
) -> Result<()> {
    let api: Api<DynamicObject> =
        Api::all_with(client.clone(), &cluster_security_policy_resource());
    let mut stream = std::pin::pin!(watcher(api, watcher::Config::default()).applied_objects());
    while let Some(event) = stream.next().await {
        match event {
            Ok(obj) => {
                // The one class whose receipt is not returned by a call this
                // file made: the request is the watch itself, and an event
                // delivered is its answer.
                health.note_success(Requested::of(FailureClass::Watch));
                metrics.record_reconcile();
                if let Err(failure) =
                    reconcile_object(client, cfg, exceptions, health, metrics, obj).await
                {
                    eprintln!("ferrum-controller: {}", failure.err);
                    health.note_failure(failure.class, &failure.err)?;
                }
            }
            Err(err) => {
                eprintln!("ferrum-controller watch: {err}");
                health.note_failure(FailureClass::Watch, &err)?;
            }
        }
        health.publish_if_changed(cfg.status_dir.as_deref());
    }
    Err(FerrumError::Degraded(
        "ClusterSecurityPolicy watch ended".into(),
    ))
}

async fn run_namespaced_policy_watch(
    client: &Client,
    cfg: &WatchConfig,
    exceptions: &ExceptionSet,
    health: &ControllerHealth,
    metrics: &ControllerMetrics,
) -> Result<()> {
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &security_policy_resource());
    let mut stream = std::pin::pin!(watcher(api, watcher::Config::default()).applied_objects());
    while let Some(event) = stream.next().await {
        match event {
            Ok(obj) => {
                health.note_success(Requested::of(FailureClass::Watch));
                metrics.record_reconcile();
                if let Err(failure) =
                    reconcile_namespaced_object(client, cfg, exceptions, health, metrics, obj).await
                {
                    eprintln!("ferrum-controller: {}", failure.err);
                    health.note_failure(failure.class, &failure.err)?;
                }
            }
            Err(err) => {
                eprintln!("ferrum-controller watch: {err}");
                health.note_failure(FailureClass::Watch, &err)?;
            }
        }
        health.publish_if_changed(cfg.status_dir.as_deref());
    }
    Err(FerrumError::Degraded("SecurityPolicy watch ended".into()))
}

async fn run_exception_watch(
    client: &Client,
    cfg: &WatchConfig,
    exceptions: &ExceptionSet,
    health: &ControllerHealth,
) -> Result<()> {
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &policy_exception_resource());
    // Raw watcher events: Delete must revoke, applied_objects would hide it.
    let mut stream = std::pin::pin!(watcher(api, watcher::Config::default()));
    // kube 1.x отдаёт релист потоком Init/InitApply/InitDone вместо одного
    // Restarted(objs). Собираем его в сторонний набор и подменяем живой одним
    // шагом на InitDone: иначе в середине релиста опубликуется пустой набор,
    // то есть массовая отмена действующих exception.
    let staging: ExceptionSet = Arc::new(Mutex::new(BTreeMap::new()));
    while let Some(event) = stream.next().await {
        match event {
            Ok(ev) => {
                health.note_success(Requested::of(FailureClass::Watch));
                // Reports and counts each object's own failure itself; what
                // comes back here is the terminal case and nothing else.
                handle_exception_event(client, cfg, exceptions, &staging, health, ev).await?;
            }
            Err(err) => {
                eprintln!("ferrum-controller watch: {err}");
                health.note_failure(FailureClass::Watch, &err)?;
            }
        }
        health.publish_if_changed(cfg.status_dir.as_deref());
    }
    Err(FerrumError::Degraded("PolicyException watch ended".into()))
}

async fn handle_exception_event(
    client: &Client,
    cfg: &WatchConfig,
    exceptions: &ExceptionSet,
    staging: &ExceptionSet,
    health: &ControllerHealth,
    event: watcher::Event<DynamicObject>,
) -> Result<()> {
    // Status patches must never block publication: the in-memory set is
    // updated first, and a failed status write on one object cannot leave a
    // revoked/narrowed exception live in the Secrets (that is fail-open).
    //
    // Each object's own failure is reported and counted here rather than
    // returned, because one relist carries many objects and one bad one must
    // not stop the rest. What this function returns is the terminal case: a
    // class in which nothing has ever succeeded.
    //
    // Each object is paired with the set it belongs in: a live `Apply` goes
    // straight to the published set, while a relist is accumulated in
    // `staging` and swapped in whole at `InitDone`, so a relist in progress
    // never publishes a partial set — that would be a mass revocation of
    // exceptions that are still in force.
    let mut objects: Vec<(&DynamicObject, &ExceptionSet)> = Vec::new();
    match &event {
        watcher::Event::Apply(obj) => objects.push((obj, exceptions)),
        watcher::Event::Delete(obj) => {
            match (
                obj.metadata.namespace.as_deref(),
                obj.metadata.name.as_deref(),
            ) {
                (Some(ns), Some(name)) => {
                    exceptions
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&format!("{ns}/{name}"));
                }
                // The set is keyed by `namespace/name`, so a deletion that
                // carries neither cannot be applied to it — and dropping it
                // silently is fail-open in the one direction this controller
                // may never fail open: the exception stays in the published
                // Secrets, keeps being signed into every bundle, and goes on
                // overriding a deny on agents that have no way to know it was
                // revoked. It is the same broken object `apply_exception_object`
                // charges to `reconcile`, and it is charged there too; what
                // changes is that it is now charged at all.
                _ => {
                    let err = FerrumError::Validation(
                        "PolicyException deleted with no metadata.namespace/name: the \
                         revoked exception cannot be removed from the published set and \
                         stays live until the next relist"
                            .to_string(),
                    );
                    eprintln!("ferrum-controller: exception delete: {err}");
                    health.note_failure(FailureClass::Reconcile, &err)?;
                }
            }
        }
        watcher::Event::Init => {
            staging.lock().unwrap_or_else(|e| e.into_inner()).clear();
        }
        watcher::Event::InitApply(obj) => objects.push((obj, staging)),
        watcher::Event::InitDone => {
            let relisted = staging.lock().unwrap_or_else(|e| e.into_inner()).clone();
            *exceptions.lock().unwrap_or_else(|e| e.into_inner()) = relisted;
        }
    }
    for (obj, target) in objects {
        match apply_exception_object(client, target, obj).await {
            Ok(requested) => health.note_success(requested),
            Err(failure) => {
                eprintln!("ferrum-controller: exception status: {}", failure.err);
                health.note_failure(failure.class, &failure.err)?;
            }
        }
    }
    match persist_exceptions(
        client,
        &cfg.namespace,
        &cfg.secret_key,
        &snapshot_exceptions(exceptions),
    )
    .await
    {
        Ok(published) => {
            // `Requested::NONE` when the list matched no Secret: a fresh
            // install has none, nothing was published, and counting that as a
            // success of this class would disarm the terminal rule for it for
            // the life of the process.
            health.note_success(published.requested);
            // A Secret this controller cannot scope a list to is that Secret
            // being wrong, and it is wrong on every event until a human fixes
            // its labels. Charged as a failure it was an unbounded run by
            // construction and the process exited on the tenth event; it is a
            // reason, in the file and in `is_degraded()`, and never a run.
            let unscopable = published.unscopable.clone();
            if health.note_unactionable(FailureClass::ExceptionPublish, unscopable)
                && !published.unscopable.is_empty()
            {
                eprintln!(
                    "ferrum-controller: exception publish: secret(s) {} carry {}={} and no {} \
                     label: this controller cannot scope an exception list to them, so the list \
                     each already holds is what the agents reading it still get",
                    published.unscopable.join(", "),
                    crate::apply::MANAGED_BY_KEY,
                    crate::apply::MANAGED_BY_VALUE,
                    crate::apply::POLICY_LABEL_KEY,
                );
            }
            // A Secret the API server refused is an ordinary failure of this
            // class, counted after the receipt for the ones that went through.
            for cause in &published.refused {
                eprintln!("ferrum-controller: exception publish: {cause}");
                health.note_failure(FailureClass::ExceptionPublish, cause)?;
            }
            Ok(())
        }
        Err(err) => {
            eprintln!("ferrum-controller: exception publish: {err}");
            health.note_failure(FailureClass::ExceptionPublish, &err)?;
            Ok(())
        }
    }
}

/// Status to record on the object plus the spec to serialize, if live.
/// A spec that fails to decode (e.g. missing expiresAt) is Rejected too.
pub(crate) fn exception_disposition(
    obj: &DynamicObject,
) -> (PolicyExceptionStatus, Option<PolicyExceptionSpec>) {
    match observe_exception(obj) {
        Ok(observed) => {
            let outcome = reconcile_exception(&observed.spec);
            (outcome.status, outcome.live)
        }
        Err(err) => (
            PolicyExceptionStatus {
                active: false,
                message: err.to_string(),
            },
            None,
        ),
    }
}

/// `Classed`, plus the receipt for the one request this makes when it makes
/// it.
type ClassedRequest = std::result::Result<Requested, Classified>;

async fn apply_exception_object(
    client: &Client,
    exceptions: &ExceptionSet,
    obj: &DynamicObject,
) -> ClassedRequest {
    // A missing name is a broken object, not a broken API call: it is counted
    // against the reconcile class so that a status subresource nobody can
    // patch stays the only thing `status_patch` reports.
    let name = require_name(obj, "PolicyException").map_err(as_class(FailureClass::Reconcile))?;
    let namespace =
        require_namespace(obj, "PolicyException").map_err(as_class(FailureClass::Reconcile))?;
    let key = format!("{namespace}/{name}");
    let (status, live) = exception_disposition(obj);
    {
        let mut set = exceptions.lock().unwrap_or_else(|e| e.into_inner());
        match live {
            Some(spec) => {
                set.insert(key, spec);
            }
            None => {
                set.remove(&key);
            }
        }
    }
    // The one request this function makes, and it is nothing but a status
    // PATCH.
    patch_status_dynamic(
        client,
        &policy_exception_resource(),
        Some(&namespace),
        &name,
        &exception_status_patch(&status),
    )
    .await
    .map_err(as_class(FailureClass::StatusPatch))
}

async fn reconcile_object(
    client: &Client,
    cfg: &WatchConfig,
    exceptions: &ExceptionSet,
    health: &ControllerHealth,
    metrics: &ControllerMetrics,
    obj: DynamicObject,
) -> Classed {
    let reconcile_class = as_class(FailureClass::Reconcile);
    let name = require_name(&obj, "ClusterSecurityPolicy").map_err(&reconcile_class)?;
    let generation = obj.metadata.generation.unwrap_or(0);
    let (og, ready, digest) = status_compile(&obj);
    if ready {
        if !digest.is_empty() {
            metrics.set_bundle_digest(&digest);
        }
        let loaded = load_bundle_secret(client, &cfg.namespace, &secret_name(&name))
            .await
            .map_err(&reconcile_class)?;
        // The GET was issued and answered, whatever it answered. It is the
        // only request a converged object makes, and crediting nothing for it
        // left `reconcile` never-having-worked on a cluster where every object
        // is converged — which is a cluster in its steady state, not a broken
        // one.
        health.note_success(loaded.requested);
        if should_skip_applied(
            generation,
            og,
            ready,
            &digest,
            loaded.secret.as_ref(),
            &cfg.trust_root,
        ) {
            return Ok(());
        }
    }
    let (plan, compile_failed) = match observe_policy(&obj) {
        Ok(observed) => {
            let outcome = reconcile(ReconcileInput {
                spec: &observed.spec,
                observed_generation: observed.generation,
                secret_key: &cfg.secret_key,
                library: cfg.library.as_ref(),
                clusters: &cfg.clusters,
            });
            let failed = matches!(outcome, ReconcileOutcome::Failed(_));
            if let ReconcileOutcome::Applied(ref applied) = outcome {
                metrics.set_bundle_digest(applied.bundle.digest.as_str());
            }
            (
                plan_apply(&observed.name, &cfg.namespace, &outcome, &cfg.trust_root),
                failed,
            )
        }
        Err(err) => (
            plan_apply(
                &name,
                &cfg.namespace,
                &failed_outcome(generation, &err),
                &cfg.trust_root,
            ),
            true,
        ),
    };
    if failed_status_already_recorded(&obj, generation, &plan) {
        if compile_failed {
            metrics.record_compile_failure();
        }
        return Ok(());
    }
    let persisted = persist(client, &name, &cfg.namespace, &plan)
        .await
        .map_err(as_class(persist_class(&plan)))?;
    // One receipt for one call, from `persist_class`, which is also what a
    // failure of it is charged to.
    health.note_success(persisted);
    let attached = attach_exceptions(client, cfg, exceptions, &plan)
        .await
        .map_err(as_class(FailureClass::ExceptionPublish))?;
    health.note_success(attached);
    if compile_failed {
        metrics.record_compile_failure();
    }
    Ok(())
}

async fn reconcile_namespaced_object(
    client: &Client,
    cfg: &WatchConfig,
    exceptions: &ExceptionSet,
    health: &ControllerHealth,
    metrics: &ControllerMetrics,
    obj: DynamicObject,
) -> Classed {
    let reconcile_class = as_class(FailureClass::Reconcile);
    let name = require_name(&obj, "SecurityPolicy").map_err(&reconcile_class)?;
    let policy_namespace = require_namespace(&obj, "SecurityPolicy").map_err(&reconcile_class)?;
    let generation = obj.metadata.generation.unwrap_or(0);
    let (og, ready, digest) = status_compile(&obj);
    if ready {
        if !digest.is_empty() {
            metrics.set_bundle_digest(&digest);
        }
        let loaded = load_bundle_secret(
            client,
            &cfg.namespace,
            &namespaced_secret_name(&name, &policy_namespace),
        )
        .await
        .map_err(&reconcile_class)?;
        health.note_success(loaded.requested);
        if should_skip_applied(
            generation,
            og,
            ready,
            &digest,
            loaded.secret.as_ref(),
            &cfg.trust_root,
        ) {
            return Ok(());
        }
    }
    let (plan, compile_failed) = match observe_namespaced_policy(&obj) {
        Ok(observed) => {
            let outcome = reconcile_namespaced(NamespacedReconcileInput {
                spec: &observed.spec,
                observed_generation: observed.generation,
                secret_key: &cfg.secret_key,
                library: cfg.library.as_ref(),
                clusters: &cfg.clusters,
            });
            let failed = matches!(outcome, ReconcileOutcome::Failed(_));
            if let ReconcileOutcome::Applied(ref applied) = outcome {
                metrics.set_bundle_digest(applied.bundle.digest.as_str());
            }
            (
                plan_apply_namespaced(
                    &observed.name,
                    &observed.namespace,
                    &cfg.namespace,
                    &outcome,
                    &cfg.trust_root,
                ),
                failed,
            )
        }
        Err(err) => (
            plan_apply_namespaced(
                &name,
                &policy_namespace,
                &cfg.namespace,
                &failed_outcome(generation, &err),
                &cfg.trust_root,
            ),
            true,
        ),
    };
    if failed_status_already_recorded(&obj, generation, &plan) {
        if compile_failed {
            metrics.record_compile_failure();
        }
        return Ok(());
    }
    let persisted = persist_dynamic(
        client,
        &security_policy_resource(),
        Some(&policy_namespace),
        &name,
        &cfg.namespace,
        &plan,
    )
    .await
    .map_err(as_class(persist_class(&plan)))?;
    health.note_success(persisted);
    let attached = attach_exceptions(client, cfg, exceptions, &plan)
        .await
        .map_err(as_class(FailureClass::ExceptionPublish))?;
    health.note_success(attached);
    if compile_failed {
        metrics.record_compile_failure();
    }
    Ok(())
}

/// The Secret `attach_exceptions` would patch, if there is one.
///
/// Both `None` arms are ordinary: a plan whose compile failed carries no
/// Secret, and there is nothing to attach an exception list to. What was not
/// ordinary is what the caller did with the `Ok(())` that came back from them
/// — it credited `exception_publish` with a success, for a call that had made
/// no request, which is permanent and is the whole of the terminal rule for
/// that class. The decision is a function of the plan alone, so it is one, and
/// it is what the unit test below reads.
fn attach_target(plan: &ApplyPlan) -> Option<&str> {
    plan.secret.as_ref()?.metadata.name.as_deref()
}

/// A freshly created bundle Secret must carry the current exception list too;
/// the exception watch only patches Secrets that already exist.
async fn attach_exceptions(
    client: &Client,
    cfg: &WatchConfig,
    exceptions: &ExceptionSet,
    plan: &ApplyPlan,
) -> Result<Requested> {
    let Some(secret_name) = attach_target(plan) else {
        return Ok(Requested::NONE);
    };
    let secret = plan.secret.as_ref().expect("attach_target read the Secret");
    // The same refusal `exception_targets` makes on the publish path, and for
    // the same reason: a Secret whose policy this controller cannot name is a
    // Secret it cannot scope a list to, and publishing the unscoped list into
    // it widens every exception the list carries to a policy nobody targeted
    // them at. This arm published it. Nothing reaches it today — every plan
    // this controller builds labels its Secret — and two paths that answer one
    // question two ways is the state in which the next change picks the wrong
    // one.
    let Some(policy) = secret
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(crate::apply::POLICY_LABEL_KEY))
    else {
        return Err(FerrumError::Integrity(format!(
            "secret {secret_name} carries no {} label: refusing to attach an exception list \
             this controller cannot scope to a policy",
            crate::apply::POLICY_LABEL_KEY,
        )));
    };
    let scoped = crate::apply::exceptions_for_policy(&snapshot_exceptions(exceptions), policy);
    patch_secret_exceptions(
        client,
        &cfg.namespace,
        secret_name,
        &cfg.secret_key,
        &scoped,
    )
    .await
}

fn failed_outcome(generation: i64, err: &FerrumError) -> crate::ReconcileOutcome {
    crate::ReconcileOutcome::Failed(PolicyStatus {
        observed_generation: generation,
        compile: compile_status_err(err),
        rollout: RolloutStatus::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::{bundle_secret, plan_apply, DEFAULT_NAMESPACE};
    use crate::health::TERMINAL_RUN;
    use crate::{reconcile, ClusterAbi, ReconcileInput, ReconcileOutcome};
    use ferrum_api::{
        ClusterSecurityPolicy, ClusterSecurityPolicySpec, PolicyLibrarySpec, RuntimeAction,
        RuntimeSpec,
    };
    use ferrum_crypto::ED25519_SECRET_KEY_LEN;
    use ferrum_ids::{ADMISSION_ABI, AGENT_ABI};

    const RFC8032_SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn pk() -> Vec<u8> {
        ferrum_crypto::public_key_from_secret(&RFC8032_SK).expect("pk")
    }

    fn prod_restricted() -> ClusterSecurityPolicy {
        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        serde_yaml::from_str(yaml).expect("example yaml")
    }

    fn dynamic_from_spec(
        name: &str,
        generation: i64,
        spec: &ClusterSecurityPolicySpec,
    ) -> DynamicObject {
        let v = serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "ClusterSecurityPolicy",
            "metadata": {
                "name": name,
                "generation": generation,
                "resourceVersion": "42",
            },
            "spec": spec,
        });
        serde_json::from_value(v).expect("DynamicObject")
    }

    #[test]
    fn gvk_is_cluster_security_policy() {
        let gvk = cluster_security_policy_gvk();
        assert_eq!(gvk.group, "ferrum.io");
        assert_eq!(gvk.version, "v1");
        assert_eq!(gvk.kind, "ClusterSecurityPolicy");
        let ar = cluster_security_policy_resource();
        assert_eq!(ar.plural, "clustersecuritypolicies");
        assert_eq!(ar.api_version, "ferrum.io/v1");
    }

    #[test]
    fn prod_restricted_dynamic_object_json_ready_digest_fsig() {
        let policy = prod_restricted();
        let obj = dynamic_from_spec(&policy.metadata.name, 11, &policy.spec);
        let observed = observe_policy(&obj).expect("observe");
        assert_eq!(observed.name, "prod-restricted");
        assert_eq!(observed.generation, 11);
        assert_eq!(observed.resource_version, "42");
        let outcome = reconcile(ReconcileInput {
            spec: &observed.spec,
            observed_generation: observed.generation,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
        });
        let applied = match &outcome {
            ReconcileOutcome::Applied(a) => a,
            ReconcileOutcome::Failed(s) => panic!("{}", s.compile.message),
        };
        assert!(applied.status.compile.ready);
        assert_eq!(applied.status.compile.bundle_digest.len(), 64);
        assert_eq!(applied.status.observed_generation, 11);
        crate::verify_signed_bundle(&applied.bundle, &pk()).expect("verify");
        let plan = plan_apply(&observed.name, DEFAULT_NAMESPACE, &outcome, &pk());
        let secret = plan.secret.expect("FSIG Secret");
        let fsig = &secret
            .data
            .as_ref()
            .expect("data")
            .get("bundle.fsig")
            .expect("bundle.fsig")
            .0;
        let decoded = crate::SignedBundle::decode(fsig).expect("decode");
        let digest = crate::verify_signed_bundle(&decoded, &pk()).expect("fsig verifies");
        assert_eq!(digest.as_str().len(), 64);
        assert_eq!(digest, applied.bundle.digest);
    }

    #[test]
    fn observed_generation_comes_from_metadata() {
        let policy = prod_restricted();
        let obj = dynamic_from_spec("prod-restricted", 7, &policy.spec);
        let observed = observe_policy(&obj).expect("observe");
        assert_eq!(observed.generation, 7);
        let outcome = reconcile(ReconcileInput {
            spec: &observed.spec,
            observed_generation: observed.generation,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
        });
        match outcome {
            ReconcileOutcome::Applied(a) => {
                assert_eq!(a.status.observed_generation, 7);
            }
            ReconcileOutcome::Failed(s) => panic!("{}", s.compile.message),
        }
    }

    /// A reconcile that published nothing does not mark publishing as
    /// working.
    ///
    /// The plan of a policy whose compile failed carries no Secret — the
    /// assertion `missing_spec_is_validation_no_secret` below already holds —
    /// so `attach_exceptions` has nothing to patch and issues no request.
    /// Before the receipt, the call site marked `exception_publish` as having
    /// succeeded on exactly that path, and `ever_ok` is permanent: from the
    /// first policy in the cluster that failed to compile, an RBAC that 403s
    /// every exception publish could never reach the terminal rule again. The
    /// same three lines held for `reconcile`, which was credited for writing
    /// «compile failed» into a status.
    #[test]
    fn a_reconcile_that_published_nothing_marks_no_class_as_having_worked() {
        let failed = ReconcileOutcome::Failed(PolicyStatus {
            observed_generation: 1,
            compile: compile_status_err(&FerrumError::Validation(
                "ClusterSecurityPolicy spec is missing".into(),
            )),
            rollout: RolloutStatus::default(),
        });
        let plan = plan_apply("bare", DEFAULT_NAMESPACE, &failed, &pk());
        assert!(plan.secret.is_none(), "a failed compile writes no Secret");
        assert!(
            attach_target(&plan).is_none(),
            "there is no Secret to attach an exception list to, so no request is made"
        );

        let health = ControllerHealth::new();
        // The receipts `reconcile_object` gets for this plan, from the two
        // functions that would have made the requests.
        health.note_success(Requested::of(persist_class(&plan)));
        health.note_success(Requested::NONE);
        assert!(
            !health.ever_succeeded(FailureClass::ExceptionPublish),
            "a call that made no request marked the class as having worked"
        );
        assert!(
            !health.ever_succeeded(FailureClass::Reconcile),
            "writing a failed compile into a status is a status patch, not a reconcile that \
             converged"
        );
        assert!(
            health.ever_succeeded(FailureClass::StatusPatch),
            "the one request this plan does make is a status PATCH, and it went through"
        );

        // And that is the terminal rule, not bookkeeping: publishes that all
        // fail must still reach it.
        let mut last = Ok(());
        for _ in 0..TERMINAL_RUN {
            last = health.note_failure(FailureClass::ExceptionPublish, "secret patch: 403");
        }
        let err = last.expect_err("a class in which nothing ever worked must end the process");
        assert!(
            err.to_string().contains("exception_publish"),
            "the terminal error must name the class: {err}"
        );

        // The other direction, so this is not an assertion that nothing ever
        // counts: a plan that does carry a Secret makes both requests, and
        // both receipts say so.
        let applied = reconcile(ReconcileInput {
            spec: &prod_restricted().spec,
            observed_generation: 3,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
        });
        let live = plan_apply("prod-restricted", DEFAULT_NAMESPACE, &applied, &pk());
        assert!(live.secret.is_some());
        assert!(attach_target(&live).is_some());
        let ok = ControllerHealth::new();
        ok.note_success(Requested::of(persist_class(&live)));
        ok.note_success(Requested::of(FailureClass::ExceptionPublish));
        assert!(ok.ever_succeeded(FailureClass::Reconcile));
        assert!(ok.ever_succeeded(FailureClass::ExceptionPublish));
    }

    #[test]
    fn missing_spec_is_validation_no_secret() {
        let v = serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "ClusterSecurityPolicy",
            "metadata": { "name": "bare", "generation": 1 },
        });
        let obj: DynamicObject = serde_json::from_value(v).expect("obj");
        match observe_policy(&obj) {
            Err(FerrumError::Validation(msg)) => {
                assert!(msg.contains("spec"), "{msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
        let failed = ReconcileOutcome::Failed(PolicyStatus {
            observed_generation: 1,
            compile: compile_status_err(&FerrumError::Validation(
                "ClusterSecurityPolicy spec is missing".into(),
            )),
            rollout: RolloutStatus::default(),
        });
        let plan = plan_apply("bare", DEFAULT_NAMESPACE, &failed, &pk());
        assert!(plan.secret.is_none());
        assert_eq!(
            plan.status["status"]["compile"]["bundleDigest"]
                .as_str()
                .expect("empty"),
            ""
        );
    }

    #[test]
    fn default_action_kill_empty_rules_failed_no_secret() {
        let spec = ClusterSecurityPolicySpec {
            runtime: RuntimeSpec {
                default_action: RuntimeAction::Kill,
                rules: vec![],
            },
            ..Default::default()
        };
        let obj = dynamic_from_spec("kill-all", 2, &spec);
        let observed = observe_policy(&obj).expect("spec present");
        let outcome = reconcile(ReconcileInput {
            spec: &observed.spec,
            observed_generation: observed.generation,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
        });
        assert!(matches!(outcome, ReconcileOutcome::Failed(_)));
        let plan = plan_apply(&observed.name, DEFAULT_NAMESPACE, &outcome, &pk());
        assert!(plan.secret.is_none());
        assert_eq!(plan.status["status"]["observedGeneration"], 2);
        assert_eq!(
            plan.status["status"]["compile"]["ready"],
            serde_json::Value::Bool(false)
        );
    }

    #[test]
    fn min_agent_abi_gate_keeps_lkg() {
        let policy = prod_restricted();
        let obj = dynamic_from_spec("prod-restricted", 1, &policy.spec);
        let observed = observe_policy(&obj).expect("observe");
        let lib = PolicyLibrarySpec {
            source: "cli".into(),
            digest: String::new(),
            min_agent_abi: AGENT_ABI.saturating_add(1),
            min_admission_abi: ADMISSION_ABI,
        };
        let clusters = [ClusterAbi {
            name: "current".into(),
            agent_abi: AGENT_ABI,
            admission_abi: ADMISSION_ABI,
        }];
        let outcome = reconcile(ReconcileInput {
            spec: &observed.spec,
            observed_generation: observed.generation,
            secret_key: &RFC8032_SK,
            library: Some(&lib),
            clusters: &clusters,
        });
        match outcome {
            ReconcileOutcome::Applied(a) => {
                assert!(a.deliver.is_empty());
                assert_eq!(a.keep_lkg, vec!["current".to_string()]);
                assert_eq!(a.status.rollout.clusters_ready, Some(0));
                assert_eq!(a.status.rollout.clusters_degraded, Some(1));
            }
            ReconcileOutcome::Failed(s) => panic!("{}", s.compile.message),
        }
    }

    #[test]
    fn all_zero_seed_from_dynamic_object_has_no_bundle() {
        let policy = prod_restricted();
        let obj = dynamic_from_spec("prod-restricted", 1, &policy.spec);
        let observed = observe_policy(&obj).expect("observe");
        let outcome = reconcile(ReconcileInput {
            spec: &observed.spec,
            observed_generation: observed.generation,
            secret_key: &[0u8; ED25519_SECRET_KEY_LEN],
            library: None,
            clusters: &[],
        });
        match &outcome {
            ReconcileOutcome::Failed(s) => {
                assert!(!s.compile.ready);
                assert!(s.compile.bundle_digest.is_empty());
            }
            ReconcileOutcome::Applied(_) => panic!("all-zero seed must not produce a bundle"),
        }
        let plan = plan_apply(&observed.name, DEFAULT_NAMESPACE, &outcome, &pk());
        assert!(plan.secret.is_none());
    }

    #[test]
    fn generation_match_alone_does_not_skip() {
        assert!(!should_skip_applied(4, Some(4), false, "", None, &pk()));
        assert!(!should_skip_applied(4, Some(4), true, "ab", None, &pk()));
    }

    #[test]
    fn failed_compile_does_not_skip_even_with_leftover_secret() {
        let policy = prod_restricted();
        let signed = crate::compile_and_sign(&policy.spec, &RFC8032_SK).expect("sign");
        let secret =
            bundle_secret("prod-restricted", DEFAULT_NAMESPACE, &signed, &pk()).expect("secret");
        assert!(!should_skip_applied(
            1,
            Some(1),
            false,
            "",
            Some(&secret),
            &pk()
        ));
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "ClusterSecurityPolicy",
            "metadata": { "name": "prod-restricted", "generation": 1 },
            "spec": policy.spec,
            "status": {
                "observedGeneration": 1,
                "compile": { "ready": false, "bundleDigest": "", "compilerVersion": "0.1.0", "message": "err" },
                "rollout": { "clustersReady": 0, "clustersDegraded": 0 }
            }
        }))
        .expect("obj");
        let failed = ReconcileOutcome::Failed(PolicyStatus {
            observed_generation: 1,
            compile: compile_status_err(&FerrumError::Validation("still bad".into())),
            rollout: RolloutStatus::default(),
        });
        let plan = plan_apply("prod-restricted", DEFAULT_NAMESPACE, &failed, &pk());
        assert!(plan.secret.is_none());
        assert!(failed_status_already_recorded(&obj, 1, &plan));
        assert!(!should_skip_applied(
            1,
            Some(1),
            false,
            "",
            Some(&secret),
            &pk()
        ));
    }

    #[test]
    fn applied_skips_only_when_live_secret_verifies() {
        let policy = prod_restricted();
        let outcome = reconcile(ReconcileInput {
            spec: &policy.spec,
            observed_generation: 7,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
        });
        let applied = match &outcome {
            ReconcileOutcome::Applied(a) => a,
            ReconcileOutcome::Failed(s) => panic!("{}", s.compile.message),
        };
        let digest = applied.status.compile.bundle_digest.as_str();
        let secret = bundle_secret("prod-restricted", DEFAULT_NAMESPACE, &applied.bundle, &pk())
            .expect("secret");
        assert!(should_skip_applied(
            7,
            Some(7),
            true,
            digest,
            Some(&secret),
            &pk()
        ));
        assert!(!should_skip_applied(7, Some(7), true, digest, None, &pk()));
        assert!(!should_skip_applied(
            8,
            Some(7),
            true,
            digest,
            Some(&secret),
            &pk()
        ));

        let mut tampered = secret.clone();
        let fsig = tampered
            .data
            .as_mut()
            .expect("data")
            .get_mut("bundle.fsig")
            .expect("fsig");
        let last = fsig.0.len() - 1;
        fsig.0[last] ^= 0x01;
        assert!(!should_skip_applied(
            7,
            Some(7),
            true,
            digest,
            Some(&tampered),
            &pk()
        ));

        let mut wrong_digest = RFC8032_SK;
        wrong_digest[0] ^= 1;
        let wrong_pk = ferrum_crypto::public_key_from_secret(&wrong_digest).expect("pk");
        assert!(!should_skip_applied(
            7,
            Some(7),
            true,
            digest,
            Some(&secret),
            &wrong_pk
        ));
    }

    #[test]
    fn failed_status_elision_is_not_applied_skip() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "ClusterSecurityPolicy",
            "metadata": { "name": "bare", "generation": 2 },
            "status": {
                "observedGeneration": 2,
                "compile": { "ready": false, "bundleDigest": "" }
            }
        }))
        .expect("obj");
        let failed = ReconcileOutcome::Failed(PolicyStatus {
            observed_generation: 2,
            compile: compile_status_err(&FerrumError::Validation("missing spec".into())),
            rollout: RolloutStatus::default(),
        });
        let plan = plan_apply("bare", DEFAULT_NAMESPACE, &failed, &pk());
        assert!(failed_status_already_recorded(&obj, 2, &plan));
        assert!(!should_skip_applied(2, Some(2), false, "", None, &pk()));
    }

    fn namespaced_spec() -> ferrum_api::SecurityPolicySpec {
        let cluster = prod_restricted().spec;
        serde_json::from_value(serde_json::to_value(cluster).expect("to json"))
            .expect("SecurityPolicySpec shares the shape")
    }

    fn dynamic_namespaced(
        name: &str,
        namespace: &str,
        generation: i64,
        spec: &ferrum_api::SecurityPolicySpec,
    ) -> DynamicObject {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "SecurityPolicy",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "generation": generation,
                "resourceVersion": "7",
            },
            "spec": spec,
        }))
        .expect("DynamicObject")
    }

    #[test]
    fn namespaced_and_exception_gvks() {
        let sp = security_policy_resource();
        assert_eq!(sp.plural, "securitypolicies");
        assert_eq!(sp.api_version, "ferrum.io/v1");
        let pe = policy_exception_resource();
        assert_eq!(pe.plural, "policyexceptions");
        assert_eq!(pe.api_version, "ferrum.io/v1");
    }

    #[test]
    fn namespaced_policy_gets_namespace_suffixed_verifiable_secret() {
        let spec = namespaced_spec();
        let obj = dynamic_namespaced("prod-restricted", "payments", 3, &spec);
        let observed = observe_namespaced_policy(&obj).expect("observe");
        assert_eq!(observed.namespace, "payments");
        assert_eq!(observed.generation, 3);
        let outcome = crate::reconcile_namespaced(crate::NamespacedReconcileInput {
            spec: &observed.spec,
            observed_generation: observed.generation,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
        });
        let plan = crate::plan_apply_namespaced(
            &observed.name,
            &observed.namespace,
            DEFAULT_NAMESPACE,
            &outcome,
            &pk(),
        );
        let secret = plan.secret.expect("FSIG Secret");
        assert_eq!(
            secret.metadata.name.as_deref(),
            Some("ferrum-bundle-ns-payments-prod-restricted")
        );
        let fsig = &secret
            .data
            .as_ref()
            .expect("data")
            .get("bundle.fsig")
            .expect("bundle.fsig")
            .0;
        let decoded = crate::SignedBundle::decode(fsig).expect("decode");
        crate::verify_signed_bundle(&decoded, &pk()).expect("fsig verifies");
        assert_eq!(plan.status["status"]["observedGeneration"], 3);
    }

    #[test]
    fn namespaced_failure_policy_ignore_rejected_no_secret() {
        let mut spec = namespaced_spec();
        spec.admit.failure_policy = ferrum_api::FailurePolicy::Ignore;
        let obj = dynamic_namespaced("break-glass", "payments", 1, &spec);
        let observed = observe_namespaced_policy(&obj).expect("observe");
        let outcome = crate::reconcile_namespaced(crate::NamespacedReconcileInput {
            spec: &observed.spec,
            observed_generation: 1,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
        });
        let status = match &outcome {
            crate::ReconcileOutcome::Failed(s) => s,
            crate::ReconcileOutcome::Applied(_) => panic!("Ignore must not compile"),
        };
        assert!(!status.compile.ready);
        assert!(
            status.compile.message.contains("Ignore"),
            "{}",
            status.compile.message
        );
        let plan = crate::plan_apply_namespaced(
            "break-glass",
            "payments",
            DEFAULT_NAMESPACE,
            &outcome,
            &pk(),
        );
        assert!(plan.secret.is_none());
    }

    #[test]
    fn exception_without_expires_at_rejected_in_status_not_in_json() {
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "PolicyException",
            "metadata": { "name": "no-ttl", "namespace": "payments" },
            "spec": {
                "ticket": "JIRA-1",
                "requestedBy": "sre",
                "reason": "temporary debug sidecar",
                "target": { "policies": ["prod-restricted"], "rules": ["no-shell"] }
            }
        }))
        .expect("obj");
        assert!(observe_exception(&obj).is_err());
        let (status, live) = exception_disposition(&obj);
        assert!(!status.active);
        assert!(status.message.contains("expiresAt"), "{}", status.message);
        assert!(live.is_none());
        let json = crate::exceptions_json(&[]).expect("json");
        assert_eq!(json, b"[]");
    }

    #[test]
    fn live_exception_survives_disposition_and_json_roundtrip() {
        let expires = chrono::Utc::now() + chrono::Days::new(7);
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "PolicyException",
            "metadata": { "name": "debug-sidecar", "namespace": "payments" },
            "spec": {
                "ticket": "JIRA-18421",
                "requestedBy": "sre",
                "approvedBy": "ib",
                "reason": "temporary debug sidecar",
                "expiresAt": expires.to_rfc3339(),
                "fourEyes": true,
                "target": {
                    "namespace": "payments",
                    "policies": ["prod-restricted"],
                    "rules": ["no-shell"]
                }
            }
        }))
        .expect("obj");
        let (status, live) = exception_disposition(&obj);
        assert!(status.active, "{}", status.message);
        let spec = live.expect("live spec");
        let json = crate::exceptions_json(std::slice::from_ref(&spec)).expect("json");
        let decoded: Vec<ferrum_api::PolicyExceptionSpec> =
            serde_json::from_slice(&json).expect("admission-side decode");
        assert_eq!(decoded, vec![spec]);
    }

    #[test]
    fn over_90_day_exception_rejected() {
        let expires = chrono::Utc::now() + chrono::Days::new(120);
        let obj: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "PolicyException",
            "metadata": { "name": "forever", "namespace": "payments" },
            "spec": {
                "ticket": "JIRA-2",
                "requestedBy": "sre",
                "reason": "temporary debug sidecar",
                "expiresAt": expires.to_rfc3339(),
                "target": { "policies": ["prod-restricted"], "rules": ["no-shell"] }
            }
        }))
        .expect("obj");
        let (status, live) = exception_disposition(&obj);
        assert!(!status.active);
        assert!(live.is_none());
        assert!(!status.message.is_empty());
    }

    // ---------------------------------------------------------------------
    // The receipts, measured against a stub API server rather than modelled.
    //
    // Everything above this line reads a pure function; the defects below
    // live in what the reconcile path does with an answer the API server
    // gave it, and none of them is visible without one.
    // ---------------------------------------------------------------------

    use crate::testapi::{status_error, Req, StubApi};
    use std::sync::Arc as StdArc;

    fn stub_cfg() -> WatchConfig {
        WatchConfig {
            namespace: DEFAULT_NAMESPACE.to_string(),
            secret_key: RFC8032_SK.to_vec(),
            trust_root: pk(),
            library: None,
            clusters: Vec::new(),
            status_dir: None,
            metrics_listen: None,
        }
    }

    /// A Secret as the API server lists it: owned by this controller, and
    /// scopable when `policy` is `Some`.
    fn listed_secret(name: &str, policy: Option<&str>) -> serde_json::Value {
        let mut labels = serde_json::Map::new();
        labels.insert(
            crate::apply::MANAGED_BY_KEY.to_string(),
            serde_json::json!(crate::apply::MANAGED_BY_VALUE),
        );
        if let Some(policy) = policy {
            labels.insert(
                crate::apply::POLICY_LABEL_KEY.to_string(),
                serde_json::json!(policy),
            );
        }
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": name, "namespace": DEFAULT_NAMESPACE, "labels": labels },
            "type": "Opaque",
        })
    }

    fn secret_list(items: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "SecretList",
            "metadata": { "resourceVersion": "1" },
            "items": items,
        })
    }

    /// The first `kube::Client` this process builds must not be a panic.
    ///
    /// `kube` builds its TLS stack through `rustls::ClientConfig::builder()`,
    /// which panics when no process-wide `CryptoProvider` is installed, and it
    /// installs one itself only under its `aws-lc-rs` feature — which this
    /// tree does not carry. So `Client::try_default()` on the first line of
    /// `run_watch` panicked before a watch, before a counter and before any
    /// status file could say why: the whole surface this module publishes was
    /// unreachable on a real cluster. The tests below are the other half of
    /// this one — every one of them builds a client and gets an answer.
    #[test]
    fn the_process_has_a_crypto_provider_before_its_first_client() {
        install_crypto_provider();
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "no rustls provider is installed, so the first kube::Client this process builds \
             panics inside rustls"
        );
    }

    /// One publish pass, driven through the same function the exception watch
    /// drives: `InitDone` carries no object, so the only requests it makes are
    /// the ones `persist_exceptions` makes.
    async fn publish_pass(
        client: &Client,
        cfg: &WatchConfig,
        health: &ControllerHealth,
    ) -> Result<()> {
        let exceptions: ExceptionSet = Arc::new(Mutex::new(BTreeMap::new()));
        let staging: ExceptionSet = Arc::new(Mutex::new(BTreeMap::new()));
        handle_exception_event(
            client,
            cfg,
            &exceptions,
            &staging,
            health,
            watcher::Event::InitDone,
        )
        .await
    }

    /// One Secret that refuses every PATCH must not make the ones that
    /// succeeded invisible.
    ///
    /// `persist_exceptions` walked its targets with `?` inside the loop, so
    /// the first refusal returned before the receipt for the Secrets already
    /// patched was built. `ever_ok` for `exception_publish` therefore stayed
    /// false for the life of the process, and the tenth event ended it —
    /// naming a class in which publishing had in fact worked on every event,
    /// on every other Secret. The terminal rule exists to report a deployment
    /// that never worked; this is it firing on one 413.
    #[tokio::test(flavor = "current_thread")]
    async fn one_secret_that_refuses_every_patch_does_not_end_a_controller_that_publishes() {
        let stub = StubApi::start(StdArc::new(|req: &Req| {
            match (req.method.as_str(), req.path()) {
                ("GET", _) => (
                    200,
                    secret_list(vec![
                        listed_secret("ferrum-bundle-cluster-a", Some("a")),
                        listed_secret("ferrum-bundle-cluster-b", Some("b")),
                    ]),
                ),
                ("PATCH", p) if p.ends_with("ferrum-bundle-cluster-b") => (
                    413,
                    status_error(413, "Request entity too large: limit is 3145728"),
                ),
                ("PATCH", _) => (200, listed_secret("ferrum-bundle-cluster-a", Some("a"))),
                _ => (404, status_error(404, "not found")),
            }
        }));
        let client = stub.client();
        let cfg = stub_cfg();
        let health = ControllerHealth::new();

        for event in 1..=TERMINAL_RUN {
            publish_pass(&client, &cfg, &health)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "event {event} of {TERMINAL_RUN} ended the process: {e}. Every one of \
                         them published the exception list to ferrum-bundle-cluster-a"
                    )
                });
        }
        assert!(
            health.ever_succeeded(FailureClass::ExceptionPublish),
            "a pass that patched one Secret and was refused by another reported no publish at all"
        );
        assert_eq!(
            stub.seen_matching("PATCH", "ferrum-bundle-cluster-a").len() as u64,
            TERMINAL_RUN,
            "one publish per event, including the events after the first refusal"
        );
        assert!(
            health.is_degraded(),
            "the Secret that refuses every patch must still be a reason"
        );
    }

    /// A Secret this controller cannot scope a list to is one object being
    /// wrong, and one object may not end the process.
    ///
    /// The `unscopable` list is charged to `exception_publish` once per event,
    /// while the pass that found it patched nothing and so returned
    /// `Requested::NONE`. Ten events — ten watch relists, or ten exceptions
    /// being edited — and the controller exits, calling a hand-made Secret a
    /// deployment fault of the class that publishes exceptions.
    #[tokio::test(flavor = "current_thread")]
    async fn a_secret_that_cannot_be_scoped_is_a_reason_and_never_a_terminal_run() {
        let stub = StubApi::start(StdArc::new(|req: &Req| match req.method.as_str() {
            "GET" => (200, secret_list(vec![listed_secret("hand-made", None)])),
            _ => (404, status_error(404, "not found")),
        }));
        let client = stub.client();
        let cfg = stub_cfg();
        let health = ControllerHealth::new();

        for event in 1..=TERMINAL_RUN * 2 {
            publish_pass(&client, &cfg, &health)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "event {event} ended the process: {e}. One Secret with no {} label is \
                         that Secret being wrong; the process publishes to every other one and \
                         must keep running",
                        crate::apply::POLICY_LABEL_KEY
                    )
                });
        }
        assert!(
            stub.seen_matching("PATCH", "hand-made").is_empty(),
            "the unscoped list was published into a Secret this controller cannot scope"
        );
        let reasons = health.degraded_reasons();
        assert!(
            reasons.iter().any(|r| r.contains("hand-made")),
            "the Secret nobody can scope is not in any reason an operator reads: {reasons:?}"
        );
    }

    /// An object that is already converged asked the API server for its Secret
    /// and got an answer, and that is a request of `reconcile` that worked.
    ///
    /// The skip returned `Ok(())` and credited nothing, so on a cluster in its
    /// steady state — every object converged — `reconcile.ever_ok` stayed
    /// false for the life of the process, and ten failures with no success
    /// between them end it.
    #[tokio::test(flavor = "current_thread")]
    async fn a_converged_object_credits_the_get_it_made() {
        let outcome = reconcile(ReconcileInput {
            spec: &prod_restricted().spec,
            observed_generation: 3,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
        });
        let applied = match outcome {
            ReconcileOutcome::Applied(applied) => applied,
            ReconcileOutcome::Failed(s) => panic!("{}", s.compile.message),
        };
        let secret = bundle_secret("prod-restricted", DEFAULT_NAMESPACE, &applied.bundle, &pk())
            .expect("secret");
        let secret_json = serde_json::to_value(&secret).expect("secret json");
        let digest = applied.bundle.digest.as_str().to_string();

        let stub = StubApi::start(StdArc::new(move |req: &Req| match req.method.as_str() {
            "GET" => (200, secret_json.clone()),
            _ => (404, status_error(404, "not found")),
        }));
        let client = stub.client();
        let cfg = stub_cfg();
        let health = ControllerHealth::new();
        let metrics = ControllerMetrics::new();
        let exceptions: ExceptionSet = Arc::new(Mutex::new(BTreeMap::new()));

        let obj = converged_object("prod-restricted", 3, &digest);
        assert!(
            reconcile_object(&client, &cfg, &exceptions, &health, &metrics, obj)
                .await
                .is_ok(),
            "a converged object is not a failure"
        );
        assert_eq!(metrics.bundle_digest().as_deref(), Some(digest.as_str()));
        assert_eq!(
            stub.seen_matching("GET", "secrets").len(),
            1,
            "the skip is decided from a Secret the API server was asked for"
        );
        assert!(
            stub.seen_matching("PATCH", "").is_empty(),
            "a converged object writes nothing, which is the point of the skip"
        );
        assert!(
            health.ever_succeeded(FailureClass::Reconcile),
            "the GET that decided the skip was issued and answered, and nothing recorded it: a \
             controller in its steady state can never mark `reconcile` as having worked"
        );
    }

    /// The object the API server holds for a policy that is already applied.
    fn converged_object(name: &str, generation: i64, digest: &str) -> DynamicObject {
        let spec = prod_restricted().spec;
        let v = serde_json::json!({
            "apiVersion": "ferrum.io/v1",
            "kind": "ClusterSecurityPolicy",
            "metadata": { "name": name, "generation": generation, "resourceVersion": "42" },
            "spec": spec,
            "status": {
                "observedGeneration": generation,
                "compile": { "ready": true, "bundleDigest": digest, "message": "" },
                "rollout": {},
            },
        });
        serde_json::from_value(v).expect("DynamicObject")
    }

    /// A Secret with no policy label gets no exception list, on both paths
    /// that can publish one.
    ///
    /// `persist_exceptions` refuses it — that is what `exception_targets` is
    /// for — and `attach_exceptions` published the whole unscoped list into it
    /// instead, which is the widening the scoping exists to prevent. The plan
    /// this controller builds always carries the label, so nothing reaches
    /// this today; two paths that answer one question differently is the state
    /// in which the next change picks the wrong one.
    #[tokio::test(flavor = "current_thread")]
    async fn attaching_to_an_unlabelled_secret_publishes_nothing() {
        let stub = StubApi::start(StdArc::new(|_req: &Req| {
            (
                200,
                serde_json::json!({ "kind": "Secret", "apiVersion": "v1" }),
            )
        }));
        let client = stub.client();
        let cfg = stub_cfg();
        let exceptions: ExceptionSet = Arc::new(Mutex::new(BTreeMap::new()));

        let outcome = reconcile(ReconcileInput {
            spec: &prod_restricted().spec,
            observed_generation: 1,
            secret_key: &RFC8032_SK,
            library: None,
            clusters: &[],
        });
        let mut plan = plan_apply("prod-restricted", DEFAULT_NAMESPACE, &outcome, &pk());
        let secret = plan.secret.as_mut().expect("the plan carries a Secret");
        secret
            .metadata
            .labels
            .as_mut()
            .expect("labels")
            .remove(crate::apply::POLICY_LABEL_KEY);

        let err = attach_exceptions(&client, &cfg, &exceptions, &plan)
            .await
            .expect_err(
                "an exception list scoped to no policy was published into a Secret whose policy \
                 this controller cannot name",
            );
        assert!(
            matches!(err, FerrumError::Integrity(_)),
            "refusing to widen an exception list is an integrity refusal: {err:?}"
        );
        assert!(
            stub.seen_matching("PATCH", "").is_empty(),
            "the unscoped list reached the API server"
        );
    }
}
