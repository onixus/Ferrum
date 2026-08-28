//! Watch ClusterSecurityPolicy, SecurityPolicy and PolicyException as
//! DynamicObject. Not kube::runtime::Controller, no kube-derive (rustc 1.75).

use crate::apply::{
    live_secret_matches, load_bundle_secret, namespaced_secret_name, patch_secret_exceptions,
    patch_status_dynamic, persist, persist_dynamic, persist_exceptions, plan_apply,
    plan_apply_namespaced, secret_name, ApplyPlan,
};
use crate::health::{ControllerHealth, FailureClass};
use crate::{
    compile_status_err, exception_status_patch, reconcile, reconcile_exception,
    reconcile_namespaced, NamespacedReconcileInput, ObservedException, ObservedNamespacedPolicy,
    ObservedPolicy, ReconcileInput, WatchConfig,
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

pub async fn run_watch(cfg: WatchConfig) -> Result<()> {
    let client = Client::try_default()
        .await
        .map_err(|e| FerrumError::Degraded(format!("kube client: {e}")))?;
    let exceptions: ExceptionSet = Arc::new(Mutex::new(BTreeMap::new()));
    let health = ControllerHealth::new();
    // Published before the first event, so an operator who finds no file at
    // all knows the process never reached its watches rather than that it is
    // idle.
    health.publish(cfg.status_dir.as_deref());
    tokio::select! {
        r = run_cluster_policy_watch(&client, &cfg, &exceptions, &health) => r,
        r = run_namespaced_policy_watch(&client, &cfg, &exceptions, &health) => r,
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
) -> Result<()> {
    let api: Api<DynamicObject> =
        Api::all_with(client.clone(), &cluster_security_policy_resource());
    let mut stream = std::pin::pin!(watcher(api, watcher::Config::default()).applied_objects());
    while let Some(event) = stream.next().await {
        match event {
            Ok(obj) => {
                health.note_success(FailureClass::Watch);
                if let Err(failure) = reconcile_object(client, cfg, exceptions, health, obj).await {
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
) -> Result<()> {
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &security_policy_resource());
    let mut stream = std::pin::pin!(watcher(api, watcher::Config::default()).applied_objects());
    while let Some(event) = stream.next().await {
        match event {
            Ok(obj) => {
                health.note_success(FailureClass::Watch);
                if let Err(failure) =
                    reconcile_namespaced_object(client, cfg, exceptions, health, obj).await
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
    // Raw watcher events: Deleted must revoke, applied_objects would hide it.
    let mut stream = std::pin::pin!(watcher(api, watcher::Config::default()));
    while let Some(event) = stream.next().await {
        match event {
            Ok(ev) => {
                health.note_success(FailureClass::Watch);
                // Reports and counts each object's own failure itself; what
                // comes back here is the terminal case and nothing else.
                handle_exception_event(client, cfg, exceptions, health, ev).await?;
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
    health: &ControllerHealth,
    event: watcher::Event<DynamicObject>,
) -> Result<()> {
    // Status patches must never block publication: the in-memory set is
    // updated first, and a failed status write on one object cannot leave a
    // revoked/narrowed exception live in the Secrets (that is fail-open).
    //
    // Each object's own failure is reported and counted here rather than
    // returned, because one `Restarted` carries many objects and one bad one
    // must not stop the rest. What this function returns is the terminal case:
    // a class in which nothing has ever succeeded.
    let mut objects: Vec<&DynamicObject> = Vec::new();
    match &event {
        watcher::Event::Applied(obj) => objects.push(obj),
        watcher::Event::Deleted(obj) => {
            if let (Some(ns), Some(name)) = (
                obj.metadata.namespace.as_deref(),
                obj.metadata.name.as_deref(),
            ) {
                exceptions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&format!("{ns}/{name}"));
            }
        }
        watcher::Event::Restarted(objs) => {
            exceptions.lock().unwrap_or_else(|e| e.into_inner()).clear();
            objects.extend(objs.iter());
        }
    }
    for obj in objects {
        match apply_exception_object(client, exceptions, obj).await {
            Ok(()) => health.note_success(FailureClass::StatusPatch),
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
        Ok(()) => {
            health.note_success(FailureClass::ExceptionPublish);
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

async fn apply_exception_object(
    client: &Client,
    exceptions: &ExceptionSet,
    obj: &DynamicObject,
) -> Classed {
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

/// The class a `persist` of `plan` fails in.
///
/// `persist_dynamic` upserts the plan's Secret and then PATCHes the object's
/// status. When the plan carries no Secret — a failed compile, an
/// unverifiable bundle — that call issues exactly one request and it is the
/// status PATCH, so a failure of it belongs to `status_patch`: this is the
/// shape a mis-edited RBAC produces on every object it touches. When the plan
/// does carry a Secret the call is a superset of that and the failure is a
/// reconcile that did not converge.
///
/// Structural, not textual: it reads the plan, never the error. Splitting the
/// two requests apart so that a Secret-carrying plan can report them
/// separately is a change in `apply.rs`.
fn persist_class(plan: &ApplyPlan) -> FailureClass {
    if plan.secret.is_some() {
        FailureClass::Reconcile
    } else {
        FailureClass::StatusPatch
    }
}

async fn reconcile_object(
    client: &Client,
    cfg: &WatchConfig,
    exceptions: &ExceptionSet,
    health: &ControllerHealth,
    obj: DynamicObject,
) -> Classed {
    let reconcile_class = as_class(FailureClass::Reconcile);
    let name = require_name(&obj, "ClusterSecurityPolicy").map_err(&reconcile_class)?;
    let generation = obj.metadata.generation.unwrap_or(0);
    let (og, ready, digest) = status_compile(&obj);
    if ready {
        let secret = load_bundle_secret(client, &cfg.namespace, &secret_name(&name))
            .await
            .map_err(&reconcile_class)?;
        if should_skip_applied(
            generation,
            og,
            ready,
            &digest,
            secret.as_ref(),
            &cfg.trust_root,
        ) {
            // Nothing was requested, so nothing succeeded: an object that is
            // already converged must not mark a class as having worked, or a
            // controller that can PATCH nothing would be protected from the
            // terminal rule by the objects it never touched.
            return Ok(());
        }
    }
    let plan = match observe_policy(&obj) {
        Ok(observed) => {
            let outcome = reconcile(ReconcileInput {
                spec: &observed.spec,
                observed_generation: observed.generation,
                secret_key: &cfg.secret_key,
                library: cfg.library.as_ref(),
                clusters: &cfg.clusters,
            });
            plan_apply(&observed.name, &cfg.namespace, &outcome, &cfg.trust_root)
        }
        Err(err) => plan_apply(
            &name,
            &cfg.namespace,
            &failed_outcome(generation, &err),
            &cfg.trust_root,
        ),
    };
    if failed_status_already_recorded(&obj, generation, &plan) {
        return Ok(());
    }
    persist(client, &name, &cfg.namespace, &plan)
        .await
        .map_err(as_class(persist_class(&plan)))?;
    // The call above ends in a status PATCH whatever else it did.
    health.note_success(FailureClass::Reconcile);
    health.note_success(FailureClass::StatusPatch);
    attach_exceptions(client, cfg, exceptions, &plan)
        .await
        .map_err(as_class(FailureClass::ExceptionPublish))?;
    health.note_success(FailureClass::ExceptionPublish);
    Ok(())
}

async fn reconcile_namespaced_object(
    client: &Client,
    cfg: &WatchConfig,
    exceptions: &ExceptionSet,
    health: &ControllerHealth,
    obj: DynamicObject,
) -> Classed {
    let reconcile_class = as_class(FailureClass::Reconcile);
    let name = require_name(&obj, "SecurityPolicy").map_err(&reconcile_class)?;
    let policy_namespace = require_namespace(&obj, "SecurityPolicy").map_err(&reconcile_class)?;
    let generation = obj.metadata.generation.unwrap_or(0);
    let (og, ready, digest) = status_compile(&obj);
    if ready {
        let secret = load_bundle_secret(
            client,
            &cfg.namespace,
            &namespaced_secret_name(&name, &policy_namespace),
        )
        .await
        .map_err(&reconcile_class)?;
        if should_skip_applied(
            generation,
            og,
            ready,
            &digest,
            secret.as_ref(),
            &cfg.trust_root,
        ) {
            return Ok(());
        }
    }
    let plan = match observe_namespaced_policy(&obj) {
        Ok(observed) => {
            let outcome = reconcile_namespaced(NamespacedReconcileInput {
                spec: &observed.spec,
                observed_generation: observed.generation,
                secret_key: &cfg.secret_key,
                library: cfg.library.as_ref(),
                clusters: &cfg.clusters,
            });
            plan_apply_namespaced(
                &observed.name,
                &observed.namespace,
                &cfg.namespace,
                &outcome,
                &cfg.trust_root,
            )
        }
        Err(err) => plan_apply_namespaced(
            &name,
            &policy_namespace,
            &cfg.namespace,
            &failed_outcome(generation, &err),
            &cfg.trust_root,
        ),
    };
    if failed_status_already_recorded(&obj, generation, &plan) {
        return Ok(());
    }
    persist_dynamic(
        client,
        &security_policy_resource(),
        Some(&policy_namespace),
        &name,
        &cfg.namespace,
        &plan,
    )
    .await
    .map_err(as_class(persist_class(&plan)))?;
    health.note_success(FailureClass::Reconcile);
    health.note_success(FailureClass::StatusPatch);
    attach_exceptions(client, cfg, exceptions, &plan)
        .await
        .map_err(as_class(FailureClass::ExceptionPublish))?;
    health.note_success(FailureClass::ExceptionPublish);
    Ok(())
}

/// A freshly created bundle Secret must carry the current exception list too;
/// the exception watch only patches Secrets that already exist.
async fn attach_exceptions(
    client: &Client,
    cfg: &WatchConfig,
    exceptions: &ExceptionSet,
    plan: &ApplyPlan,
) -> Result<()> {
    let Some(secret) = &plan.secret else {
        return Ok(());
    };
    let Some(secret_name) = secret.metadata.name.as_deref() else {
        return Ok(());
    };
    let scoped = match secret
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get(crate::apply::POLICY_LABEL_KEY))
    {
        Some(policy) => {
            crate::apply::exceptions_for_policy(&snapshot_exceptions(exceptions), policy)
        }
        None => snapshot_exceptions(exceptions),
    };
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
                assert_eq!(a.status.rollout.clusters_ready, 0);
                assert_eq!(a.status.rollout.clusters_degraded, 1);
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
        let json = crate::exceptions_json(&[spec.clone()]).expect("json");
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
}
