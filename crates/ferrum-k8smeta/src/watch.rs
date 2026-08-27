//! Pod watch: parsing (always compiled, offline-testable) plus a thin network
//! wrapper behind the `apiserver` feature.
//!
//! No kube client: it would pull tokio into a crate that sits on the decision
//! path. The stream is plain HTTP/1.1 over rustls, same shape as
//! `ferrum-admission::server`.

use crate::labels::{LabelObject, LabelWatchEvent};
use crate::source::{normalize_runtime_id, ContainerRecord, PodCache, PodRecord};
use ferrum_common::{FerrumError, Result};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodWatchEvent {
    Added(PodRecord),
    Modified(PodRecord),
    Deleted(PodRecord),
    /// `allowWatchBookmarks`: resourceVersion only, no object change.
    Bookmark(String),
    /// `410 Gone` in-band: the caller must relist, not resume.
    Gone(String),
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchOutcome {
    Applied,
    Removed,
    /// Object was for another node, or unusable. Cache untouched.
    Ignored,
    /// Caller must relist from scratch.
    MustRelist,
}

/// Parse `GET /api/v1/pods` (a `PodList`) into (resourceVersion, pods).
pub fn parse_pod_list(bytes: &[u8]) -> Result<(String, Vec<PodRecord>)> {
    let root: Value = serde_json::from_slice(bytes)
        .map_err(|e| FerrumError::Degraded(format!("pod list json: {e}")))?;
    let kind = root.get("kind").and_then(Value::as_str).unwrap_or_default();
    if kind != "PodList" {
        return Err(FerrumError::Degraded(format!(
            "expected PodList from apiserver, got {kind:?}"
        )));
    }
    let rv = root
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let pods = root
        .get("items")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(parse_pod).collect())
        .unwrap_or_default();
    Ok((rv, pods))
}

/// Parse one line of a `watch=1` stream. Pure: no I/O, no cache.
pub fn parse_watch_event(line: &[u8]) -> Result<PodWatchEvent> {
    let root: Value = serde_json::from_slice(line)
        .map_err(|e| FerrumError::Degraded(format!("watch json: {e}")))?;
    let kind = root.get("type").and_then(Value::as_str).unwrap_or_default();
    let object = root.get("object").unwrap_or(&Value::Null);
    match kind {
        "ADDED" | "MODIFIED" | "DELETED" => {
            let pod = parse_pod(object).ok_or_else(|| {
                FerrumError::Degraded(format!("watch {kind} object is not a usable Pod"))
            })?;
            Ok(match kind {
                "ADDED" => PodWatchEvent::Added(pod),
                "MODIFIED" => PodWatchEvent::Modified(pod),
                _ => PodWatchEvent::Deleted(pod),
            })
        }
        "BOOKMARK" => Ok(PodWatchEvent::Bookmark(
            object
                .pointer("/metadata/resourceVersion")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        )),
        "ERROR" => {
            let (gone, message) = watch_error(object);
            if gone {
                Ok(PodWatchEvent::Gone(message))
            } else {
                Ok(PodWatchEvent::Error(message))
            }
        }
        other => Err(FerrumError::Degraded(format!("unknown watch type {other}"))),
    }
}

/// Fold one event into the cache. DELETE removes by UID, so every cgroup of
/// that pod disappears from the next resolver refresh.
pub fn apply_watch_event(cache: &mut PodCache, event: PodWatchEvent) -> WatchOutcome {
    match event {
        PodWatchEvent::Added(pod) | PodWatchEvent::Modified(pod) => {
            if cache.upsert(pod) {
                WatchOutcome::Applied
            } else {
                WatchOutcome::Ignored
            }
        }
        PodWatchEvent::Deleted(pod) => {
            cache.remove(&pod.uid);
            WatchOutcome::Removed
        }
        PodWatchEvent::Bookmark(rv) => {
            cache.set_resource_version(rv);
            WatchOutcome::Ignored
        }
        PodWatchEvent::Gone(_) => WatchOutcome::MustRelist,
        PodWatchEvent::Error(_) => WatchOutcome::Ignored,
    }
}

/// Feed a whole recorded stream (one JSON object per line). Stops at the first
/// event demanding a relist and reports it.
pub fn apply_watch_stream(cache: &mut PodCache, body: &[u8]) -> Result<WatchOutcome> {
    let mut outcome = WatchOutcome::Ignored;
    for line in body.split(|b| *b == b'\n') {
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let event = parse_watch_event(line)?;
        if let Some(rv) = event_resource_version(&event) {
            cache.set_resource_version(rv);
        }
        outcome = apply_watch_event(cache, event);
        if outcome == WatchOutcome::MustRelist {
            return Ok(outcome);
        }
    }
    Ok(outcome)
}

fn event_resource_version(event: &PodWatchEvent) -> Option<String> {
    match event {
        PodWatchEvent::Bookmark(rv) => Some(rv.clone()),
        PodWatchEvent::Added(p) | PodWatchEvent::Modified(p) | PodWatchEvent::Deleted(p) => {
            Some(p.resource_version.clone()).filter(|s| !s.is_empty())
        }
        _ => None,
    }
}

/// Parse a `NamespaceList` or `ServiceAccountList` into (resourceVersion,
/// objects). Only `metadata.name`, `metadata.namespace` and `metadata.labels`
/// are read: nothing else in those objects is a policy input, and a selector
/// must not start depending on secrets or annotations by accident.
pub fn parse_labels_list(kind: &str, bytes: &[u8]) -> Result<(String, Vec<LabelObject>)> {
    let root: Value = serde_json::from_slice(bytes)
        .map_err(|e| FerrumError::Degraded(format!("{kind} json: {e}")))?;
    let got = root.get("kind").and_then(Value::as_str).unwrap_or_default();
    if got != kind {
        return Err(FerrumError::Degraded(format!(
            "expected {kind} from apiserver, got {got:?}"
        )));
    }
    let rv = root
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let objects = root
        .get("items")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(parse_label_object).collect())
        .unwrap_or_default();
    Ok((rv, objects))
}

/// Parse one line of a namespaces/serviceaccounts `watch=1` stream. Pure.
pub fn parse_labels_watch_event(line: &[u8]) -> Result<LabelWatchEvent> {
    let root: Value = serde_json::from_slice(line)
        .map_err(|e| FerrumError::Degraded(format!("watch json: {e}")))?;
    let kind = root.get("type").and_then(Value::as_str).unwrap_or_default();
    let object = root.get("object").unwrap_or(&Value::Null);
    match kind {
        "ADDED" | "MODIFIED" | "DELETED" => {
            let parsed = parse_label_object(object).ok_or_else(|| {
                FerrumError::Degraded(format!("watch {kind} object has no metadata.name"))
            })?;
            Ok(match kind {
                "ADDED" => LabelWatchEvent::Added(parsed),
                "MODIFIED" => LabelWatchEvent::Modified(parsed),
                _ => LabelWatchEvent::Deleted(parsed),
            })
        }
        "BOOKMARK" => Ok(LabelWatchEvent::Bookmark(
            object
                .pointer("/metadata/resourceVersion")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        )),
        "ERROR" => {
            let (gone, message) = watch_error(object);
            if gone {
                Ok(LabelWatchEvent::Gone(message))
            } else {
                Ok(LabelWatchEvent::Error(message))
            }
        }
        other => Err(FerrumError::Degraded(format!("unknown watch type {other}"))),
    }
}

/// `410 Gone` / `Expired` means the resourceVersion is unusable and resuming
/// would skip changes silently.
fn watch_error(object: &Value) -> (bool, String) {
    let code = object.get("code").and_then(Value::as_i64).unwrap_or(0);
    let message = object
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("watch error")
        .to_string();
    let gone = code == 410 || object.get("reason").and_then(Value::as_str) == Some("Expired");
    (gone, message)
}

fn parse_label_object(object: &Value) -> Option<LabelObject> {
    let meta = object.get("metadata")?;
    let name = meta.get("name").and_then(Value::as_str)?.to_string();
    if name.is_empty() {
        return None;
    }
    Some(LabelObject {
        namespace: meta
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        name,
        labels: string_map(meta.get("labels")),
        resource_version: meta
            .get("resourceVersion")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

/// A Pod object without a UID or a name is unusable; returning None keeps it
/// out of the cache instead of producing an identity with empty fields.
pub fn parse_pod(object: &Value) -> Option<PodRecord> {
    let meta = object.get("metadata")?;
    let uid = meta.get("uid").and_then(Value::as_str)?.to_string();
    let name = meta.get("name").and_then(Value::as_str)?.to_string();
    let namespace = meta
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if uid.is_empty() || name.is_empty() || namespace.is_empty() {
        return None;
    }
    let spec = object.get("spec");
    let node_name = spec
        .and_then(|s| s.get("nodeName"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let service_account = spec
        .and_then(|s| {
            s.get("serviceAccountName")
                .or_else(|| s.get("serviceAccount"))
        })
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();

    let mut images: BTreeMap<String, (String, String, String)> = BTreeMap::new();
    if let Some(list) = object
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
    {
        for status in list {
            let cname = status
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let id = status
                .get("containerID")
                .and_then(Value::as_str)
                .map(normalize_runtime_id)
                .unwrap_or_default();
            let image = status
                .get("image")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let digest = status
                .get("imageID")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if !cname.is_empty() && !id.is_empty() {
                images.insert(cname, (id, image, image_digest(&digest)));
            }
        }
    }

    let containers = images
        .into_iter()
        .map(|(name, (id, image, image_digest))| ContainerRecord {
            name,
            id,
            image,
            image_digest,
        })
        .collect::<Vec<_>>();

    Some(PodRecord {
        uid,
        namespace,
        name,
        node_name,
        service_account,
        resource_version: meta
            .get("resourceVersion")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        labels: string_map(meta.get("labels")),
        // Namespace/ServiceAccount labels are not on the Pod object; the label
        // caches fill them in on the way out of PodCache::snapshot.
        namespace_labels: BTreeMap::new(),
        service_account_labels: BTreeMap::new(),
        containers,
    })
}

/// `imageID` is `<repo>@sha256:...` or a bare digest depending on runtime.
/// Anything else is reported as no digest rather than as a made-up one.
fn image_digest(image_id: &str) -> String {
    image_id
        .rsplit_once('@')
        .map(|(_, d)| d.to_string())
        .unwrap_or_else(|| {
            if image_id.starts_with("sha256:") {
                image_id.to_string()
            } else {
                String::new()
            }
        })
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod label_parse_tests {
    use super::*;
    use crate::labels::{apply_labels_event, apply_labels_stream, LabelCache};

    const NS_LIST: &[u8] = br#"{
        "kind": "NamespaceList",
        "metadata": {"resourceVersion": "2001"},
        "items": [
          {"metadata": {"name": "prod", "resourceVersion": "1900",
                        "labels": {"ferrum.io/zone": "pci"}}},
          {"metadata": {"name": "dev", "resourceVersion": "1901", "labels": {}}},
          {"metadata": {"resourceVersion": "1902"}}
        ]
    }"#;

    #[test]
    fn namespace_list_keeps_only_name_and_labels() {
        let (rv, objects) = parse_labels_list("NamespaceList", NS_LIST).expect("list");
        assert_eq!(rv, "2001");
        // The nameless item is dropped, not stored under an empty key.
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].name, "prod");
        assert!(objects[0].namespace.is_empty());
        assert_eq!(
            objects[0].labels.get("ferrum.io/zone").map(String::as_str),
            Some("pci")
        );
        assert!(objects[1].labels.is_empty());
    }

    #[test]
    fn wrong_kind_is_degraded_not_an_empty_list() {
        let err = parse_labels_list("ServiceAccountList", NS_LIST).expect_err("kind mismatch");
        assert!(err.to_string().contains("ServiceAccountList"), "{err}");
    }

    #[test]
    fn service_account_list_carries_its_namespace() {
        let raw = br#"{
            "kind": "ServiceAccountList",
            "metadata": {"resourceVersion": "3001"},
            "items": [
              {"metadata": {"name": "default", "namespace": "prod",
                            "labels": {"tier": "front"}}},
              {"metadata": {"name": "default", "namespace": "dev",
                            "labels": {"tier": "sandbox"}}}
            ]
        }"#;
        let (_, objects) = parse_labels_list("ServiceAccountList", raw).expect("list");
        let mut cache = LabelCache::new();
        cache.replace_all(objects);
        assert_eq!(
            cache.labels_or_empty("prod", "default").get("tier"),
            Some(&"front".to_string())
        );
        assert_eq!(
            cache.labels_or_empty("dev", "default").get("tier"),
            Some(&"sandbox".to_string())
        );
    }

    #[test]
    fn watch_events_add_modify_delete_and_bookmark() {
        let mut cache = LabelCache::new();
        cache.replace_all(Vec::new());
        let added = parse_labels_watch_event(
            br#"{"type":"ADDED","object":{"metadata":{"name":"prod","resourceVersion":"5",
                 "labels":{"ferrum.io/zone":"pci"}}}}"#,
        )
        .expect("added");
        assert_eq!(apply_labels_event(&mut cache, added), WatchOutcome::Applied);
        assert_eq!(
            cache.labels_or_empty("", "prod").get("ferrum.io/zone"),
            Some(&"pci".to_string())
        );

        let modified = parse_labels_watch_event(
            br#"{"type":"MODIFIED","object":{"metadata":{"name":"prod","resourceVersion":"6",
                 "labels":{"ferrum.io/zone":"public"}}}}"#,
        )
        .expect("modified");
        apply_labels_event(&mut cache, modified);
        assert_eq!(
            cache.labels_or_empty("", "prod").get("ferrum.io/zone"),
            Some(&"public".to_string())
        );

        let bookmark = parse_labels_watch_event(
            br#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"7"}}}"#,
        )
        .expect("bookmark");
        apply_labels_event(&mut cache, bookmark);
        assert_eq!(cache.resource_version(), "7");

        let deleted = parse_labels_watch_event(
            br#"{"type":"DELETED","object":{"metadata":{"name":"prod","resourceVersion":"8"}}}"#,
        )
        .expect("deleted");
        assert_eq!(
            apply_labels_event(&mut cache, deleted),
            WatchOutcome::Removed
        );
        assert!(cache.labels_of("", "prod").is_none());
    }

    #[test]
    fn expired_resource_version_demands_a_relist() {
        let line = br#"{"type":"ERROR","object":{"kind":"Status","reason":"Expired","message":"too old resource version: 2 (9)","code":410}}"#;
        match parse_labels_watch_event(line).expect("parse") {
            LabelWatchEvent::Gone(msg) => {
                assert!(msg.contains("too old resource version"), "{msg}")
            }
            other => panic!("410 must be Gone, got {other:?}"),
        }
        let mut cache = LabelCache::new();
        cache.replace_all(parse_labels_list("NamespaceList", NS_LIST).expect("list").1);
        let outcome = apply_labels_stream(&mut cache, line).expect("apply");
        assert_eq!(outcome, WatchOutcome::MustRelist);
        // A relist demand must not empty the cache we already have.
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn non_410_watch_error_is_not_a_relist() {
        let line = br#"{"type":"ERROR","object":{"kind":"Status","message":"boom","code":500}}"#;
        match parse_labels_watch_event(line).expect("parse") {
            LabelWatchEvent::Error(msg) => assert_eq!(msg, "boom"),
            other => panic!("500 must stay Error, got {other:?}"),
        }
    }
}

#[cfg(feature = "apiserver")]
pub use client::{ApiserverConfig, ApiserverWatcher, LabelWatcher, SERVICE_ACCOUNT_DIR};

#[cfg(feature = "apiserver")]
mod client {
    use super::{
        apply_watch_event, event_resource_version, parse_labels_list, parse_labels_watch_event,
        parse_pod_list, parse_watch_event,
    };
    use crate::labels::{apply_labels_event, label_event_resource_version, LabelCache};
    use crate::source::PodCache;
    use crate::watch::WatchOutcome;
    use ferrum_common::{FerrumError, Result};
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::net::TcpStream;
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, Instant};

    pub const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
    /// The apiserver certificate carries this SAN; the Service IP we dial does
    /// not have to be in it, so verification uses the name, not the address.
    const DEFAULT_SERVER_NAME: &str = "kubernetes.default.svc";
    const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
    /// A header line longer than this, or more than [`MAX_HEADER_LINES`] of
    /// them, is an unhealthy or hostile apiserver trying to grow our heap:
    /// refuse instead of buffering.
    const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
    const MAX_HEADER_LINES: usize = 100;
    /// Relist body ceiling. A node's PodList is orders of magnitude smaller;
    /// anything past this is not a list we are willing to hold in memory.
    const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
    const RECONNECT_BACKOFF: Duration = Duration::from_secs(2);
    const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);
    /// A cycle that streamed at least this long was a healthy connection, so
    /// the next reconnect starts from the base delay again.
    const HEALTHY_STREAM: Duration = Duration::from_secs(60);

    #[derive(Debug, Clone)]
    pub struct ApiserverConfig {
        pub host: String,
        pub port: u16,
        pub server_name: String,
        pub node_name: String,
        pub token_path: PathBuf,
        pub ca_path: PathBuf,
    }

    impl ApiserverConfig {
        /// In-cluster config for a cluster-wide watch. No node name: the
        /// namespaces/serviceaccounts watches carry no fieldSelector, so there
        /// is nothing to scope them to.
        pub fn cluster_wide() -> Result<Self> {
            Self::in_cluster(String::new())
        }

        /// In-cluster config: Service env vars plus the projected SA volume.
        pub fn from_service_account(node_name: impl Into<String>) -> Result<Self> {
            let node_name = node_name.into();
            if node_name.is_empty() {
                return Err(FerrumError::Degraded(
                    "node name required: an unscoped pod watch is a cluster-wide read".into(),
                ));
            }
            Self::in_cluster(node_name)
        }

        fn in_cluster(node_name: String) -> Result<Self> {
            let host = std::env::var("KUBERNETES_SERVICE_HOST")
                .map_err(|_| FerrumError::Degraded("KUBERNETES_SERVICE_HOST unset".into()))?;
            let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
                .or_else(|_| std::env::var("KUBERNETES_SERVICE_PORT"))
                .unwrap_or_else(|_| "443".into())
                .parse::<u16>()
                .map_err(|e| FerrumError::Degraded(format!("KUBERNETES_SERVICE_PORT: {e}")))?;
            let dir = PathBuf::from(SERVICE_ACCOUNT_DIR);
            Ok(Self {
                host,
                port,
                server_name: DEFAULT_SERVER_NAME.to_string(),
                node_name,
                token_path: dir.join("token"),
                ca_path: dir.join("ca.crt"),
            })
        }

        /// Re-read every connect: projected tokens rotate.
        fn token(&self) -> Result<String> {
            let raw = std::fs::read_to_string(&self.token_path).map_err(|e| {
                FerrumError::Degraded(format!(
                    "service account token {}: {e}",
                    self.token_path.display()
                ))
            })?;
            Ok(raw.trim().to_string())
        }

        fn connect(&self) -> Result<TlsStream> {
            let cfg = self.tls_config()?;
            let name = rustls::ServerName::try_from(self.server_name.as_str())
                .map_err(|e| FerrumError::Degraded(format!("apiserver server name: {e}")))?;
            let conn = rustls::ClientConnection::new(cfg, name)
                .map_err(|e| FerrumError::Degraded(format!("tls client: {e}")))?;
            let tcp = TcpStream::connect((self.host.as_str(), self.port))
                .map_err(|e| FerrumError::Degraded(format!("apiserver connect: {e}")))?;
            let _ = tcp.set_nodelay(true);
            Ok(rustls::StreamOwned::new(conn, tcp))
        }

        fn request(&self, stream: &mut TlsStream, path: &str) -> Result<()> {
            let token = self.token()?;
            let mut req = String::new();
            req.push_str(&format!("GET {path} HTTP/1.1\r\n"));
            req.push_str(&format!("Host: {}\r\n", self.server_name));
            req.push_str(&format!("Authorization: Bearer {token}\r\n"));
            req.push_str("Accept: application/json\r\n");
            req.push_str("User-Agent: ferrum-k8smeta\r\n");
            req.push_str("Connection: close\r\n\r\n");
            stream
                .write_all(req.as_bytes())
                .and_then(|_| stream.flush())
                .map_err(|e| FerrumError::Degraded(format!("apiserver request: {e}")))
        }

        fn tls_config(&self) -> Result<Arc<rustls::ClientConfig>> {
            let pem = std::fs::read(&self.ca_path).map_err(|e| {
                FerrumError::Degraded(format!("cluster CA {}: {e}", self.ca_path.display()))
            })?;
            let mut reader = io::Cursor::new(pem);
            let certs = rustls_pemfile::certs(&mut reader)
                .map_err(|e| FerrumError::Degraded(format!("cluster CA parse: {e}")))?;
            if certs.is_empty() {
                return Err(FerrumError::Degraded(
                    "cluster CA has no certificate".into(),
                ));
            }
            let mut roots = rustls::RootCertStore::empty();
            for cert in certs {
                roots
                    .add(&rustls::Certificate(cert))
                    .map_err(|e| FerrumError::Degraded(format!("cluster CA rejected: {e}")))?;
            }
            // Cluster CA only: no system roots, no fallback to webpki defaults.
            Ok(Arc::new(
                rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ))
        }
    }

    type TlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

    /// Live pod cache fed by a watch. Owns no threads of its own; the caller
    /// decides where `run` spins.
    pub struct ApiserverWatcher {
        config: ApiserverConfig,
        cache: Arc<RwLock<PodCache>>,
    }

    impl ApiserverWatcher {
        pub fn new(config: ApiserverConfig) -> Self {
            let cache = PodCache::new(config.node_name.clone());
            Self {
                config,
                cache: Arc::new(RwLock::new(cache)),
            }
        }

        pub fn cache(&self) -> Arc<RwLock<PodCache>> {
            Arc::clone(&self.cache)
        }

        fn with_cache<T>(&self, f: impl FnOnce(&mut PodCache) -> T) -> T {
            let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
            f(&mut guard)
        }

        fn list_path(&self) -> String {
            format!(
                "/api/v1/pods?fieldSelector={}&resourceVersion=0",
                percent_encode(&format!("spec.nodeName={}", self.config.node_name))
            )
        }

        fn watch_path(&self, rv: &str) -> String {
            format!(
                "/api/v1/pods?fieldSelector={}&watch=1&allowWatchBookmarks=true&resourceVersion={}",
                percent_encode(&format!("spec.nodeName={}", self.config.node_name)),
                percent_encode(rv)
            )
        }

        /// Full list; replaces the cache. Returns the resourceVersion to watch from.
        pub fn relist(&self) -> Result<String> {
            let mut stream = self.config.connect()?;
            let path = self.list_path();
            self.config.request(&mut stream, &path)?;
            let mut reader = BufReader::new(stream);
            let head = read_head(&mut reader)?;
            if head.status != 200 {
                return Err(FerrumError::Degraded(format!(
                    "apiserver list returned {}",
                    head.status
                )));
            }
            let mut body = Vec::new();
            read_body(&mut reader, &head, &mut body)?;
            let (rv, pods) = parse_pod_list(&body)?;
            self.with_cache(|c| {
                c.replace_all(pods);
                c.set_resource_version(rv.clone());
            });
            Ok(rv)
        }

        /// Stream events until the connection ends. `Ok(MustRelist)` means the
        /// resourceVersion expired (410) and resuming would silently skip
        /// changes; the caller must relist.
        pub fn watch_once(&self, rv: &str) -> Result<WatchOutcome> {
            let mut stream = self.config.connect()?;
            let path = self.watch_path(rv);
            self.config.request(&mut stream, &path)?;
            let mut reader = BufReader::new(stream);
            let head = read_head(&mut reader)?;
            match head.status {
                200 => {}
                410 => return Ok(WatchOutcome::MustRelist),
                other => {
                    return Err(FerrumError::Degraded(format!(
                        "apiserver watch returned {other}"
                    )))
                }
            }
            let mut body = BodyReader::new(&mut reader, &head);
            loop {
                let mut line = Vec::new();
                match read_line(&mut body, &mut line) {
                    Ok(0) => return Ok(WatchOutcome::Applied),
                    Ok(_) => {}
                    Err(e) => return Err(FerrumError::Degraded(format!("watch stream: {e}"))),
                }
                if line.iter().all(|b| b.is_ascii_whitespace()) {
                    continue;
                }
                let event = match parse_watch_event(&line) {
                    Ok(e) => e,
                    // One malformed frame must not drop the whole cache.
                    Err(err) => {
                        eprintln!("ferrum-k8smeta: skipping watch frame: {err}");
                        continue;
                    }
                };
                if let Some(next_rv) = event_resource_version(&event) {
                    self.with_cache(|c| c.set_resource_version(next_rv));
                }
                let outcome = self.with_cache(|c| apply_watch_event(c, event));
                if outcome == WatchOutcome::MustRelist {
                    return Ok(outcome);
                }
            }
        }

        /// One relist plus watch streams until the connection ends or the
        /// resourceVersion expires. Returning is normal; the caller backs off.
        fn cycle(&self) -> Result<()> {
            let mut rv = self.relist()?;
            loop {
                match self.watch_once(&rv)? {
                    WatchOutcome::MustRelist => return Ok(()),
                    _ => {
                        rv = self
                            .cache
                            .read()
                            .unwrap_or_else(|e| e.into_inner())
                            .resource_version()
                            .to_string();
                        if rv.is_empty() {
                            return Ok(());
                        }
                    }
                }
            }
        }

        /// List, watch, reconnect forever. 410 relists instead of resuming.
        /// Namespace and ServiceAccount labels ride along on their own threads:
        /// they feed the same `PodCache`, so no caller has to ask for them.
        pub fn run(&self) -> ! {
            for service_accounts in [false, true] {
                let stream = LabelStream {
                    config: self.config.clone(),
                    kind: if service_accounts {
                        SERVICE_ACCOUNTS
                    } else {
                        NAMESPACES
                    },
                    sink: Box::new(PodCacheLabels {
                        cache: self.cache(),
                        service_accounts,
                    }),
                };
                std::thread::spawn(move || stream.run());
            }
            watch_loop(|| self.cycle(), std::thread::sleep, None);
            unreachable!("watch_loop without a budget never returns")
        }
    }

    const NAMESPACES: LabelKind = LabelKind {
        list_kind: "NamespaceList",
        resource: "namespaces",
    };
    const SERVICE_ACCOUNTS: LabelKind = LabelKind {
        list_kind: "ServiceAccountList",
        resource: "serviceaccounts",
    };

    #[derive(Debug, Clone, Copy)]
    struct LabelKind {
        list_kind: &'static str,
        resource: &'static str,
    }

    /// Where a label stream writes. The two label caches of a `PodCache` live
    /// inside it, behind the same lock as the pods, so they cannot be handed
    /// out as separate `Arc`s.
    trait LabelSink: Send + Sync {
        fn with(&self, f: &mut dyn FnMut(&mut LabelCache));
    }

    struct SharedLabels(Arc<RwLock<LabelCache>>);

    impl LabelSink for SharedLabels {
        fn with(&self, f: &mut dyn FnMut(&mut LabelCache)) {
            f(&mut self.0.write().unwrap_or_else(|e| e.into_inner()));
        }
    }

    struct PodCacheLabels {
        cache: Arc<RwLock<PodCache>>,
        service_accounts: bool,
    }

    impl LabelSink for PodCacheLabels {
        fn with(&self, f: &mut dyn FnMut(&mut LabelCache)) {
            let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
            if self.service_accounts {
                f(guard.service_accounts_mut());
            } else {
                f(guard.namespaces_mut());
            }
        }
    }

    /// One cluster-wide list+watch of a label-bearing kind.
    struct LabelStream {
        config: ApiserverConfig,
        kind: LabelKind,
        sink: Box<dyn LabelSink>,
    }

    impl LabelStream {
        fn relist(&self) -> Result<String> {
            let mut stream = self.config.connect()?;
            let path = format!("/api/v1/{}?resourceVersion=0", self.kind.resource);
            self.config.request(&mut stream, &path)?;
            let mut reader = BufReader::new(stream);
            let head = read_head(&mut reader)?;
            if head.status != 200 {
                return Err(FerrumError::Degraded(format!(
                    "apiserver {} list returned {}",
                    self.kind.resource, head.status
                )));
            }
            let mut body = Vec::new();
            read_body(&mut reader, &head, &mut body)?;
            let (rv, objects) = parse_labels_list(self.kind.list_kind, &body)?;
            let mut objects = Some(objects);
            let listed_rv = rv.clone();
            self.sink.with(&mut |cache| {
                cache.replace_all(objects.take().unwrap_or_default());
                cache.set_resource_version(listed_rv.clone());
            });
            Ok(rv)
        }

        fn watch_once(&self, rv: &str) -> Result<WatchOutcome> {
            let mut stream = self.config.connect()?;
            let path = format!(
                "/api/v1/{}?watch=1&allowWatchBookmarks=true&resourceVersion={}",
                self.kind.resource,
                percent_encode(rv)
            );
            self.config.request(&mut stream, &path)?;
            let mut reader = BufReader::new(stream);
            let head = read_head(&mut reader)?;
            match head.status {
                200 => {}
                410 => return Ok(WatchOutcome::MustRelist),
                other => {
                    return Err(FerrumError::Degraded(format!(
                        "apiserver {} watch returned {other}",
                        self.kind.resource
                    )))
                }
            }
            let mut body = BodyReader::new(&mut reader, &head);
            loop {
                let mut line = Vec::new();
                match read_line(&mut body, &mut line) {
                    Ok(0) => return Ok(WatchOutcome::Applied),
                    Ok(_) => {}
                    Err(e) => return Err(FerrumError::Degraded(format!("watch stream: {e}"))),
                }
                if line.iter().all(|b| b.is_ascii_whitespace()) {
                    continue;
                }
                let event = match parse_labels_watch_event(&line) {
                    Ok(e) => e,
                    // One malformed frame must not drop the whole cache.
                    Err(err) => {
                        eprintln!(
                            "ferrum-k8smeta: skipping {} watch frame: {err}",
                            self.kind.resource
                        );
                        continue;
                    }
                };
                let next_rv = label_event_resource_version(&event);
                let mut event = Some(event);
                let mut outcome = WatchOutcome::Ignored;
                self.sink.with(&mut |cache| {
                    if let Some(next) = next_rv.clone() {
                        cache.set_resource_version(next);
                    }
                    if let Some(event) = event.take() {
                        outcome = apply_labels_event(cache, event);
                    }
                });
                if outcome == WatchOutcome::MustRelist {
                    return Ok(outcome);
                }
            }
        }

        fn cycle(&self) -> Result<()> {
            let mut rv = self.relist()?;
            loop {
                match self.watch_once(&rv)? {
                    WatchOutcome::MustRelist => return Ok(()),
                    _ => {
                        let mut current = String::new();
                        self.sink
                            .with(&mut |cache| current = cache.resource_version().to_string());
                        if current.is_empty() {
                            return Ok(());
                        }
                        rv = current;
                    }
                }
            }
        }

        fn run(self) -> ! {
            watch_loop(|| self.cycle(), std::thread::sleep, None);
            unreachable!("watch_loop without a budget never returns")
        }
    }

    /// Cluster-wide Namespace and ServiceAccount label caches. This is the
    /// admission-side entry point: it never reads Pods, so the webhook's RBAC
    /// stays get/list/watch on those two kinds.
    pub struct LabelWatcher {
        config: ApiserverConfig,
        namespaces: Arc<RwLock<LabelCache>>,
        service_accounts: Arc<RwLock<LabelCache>>,
    }

    impl LabelWatcher {
        pub fn new(config: ApiserverConfig) -> Self {
            Self {
                config,
                namespaces: Arc::new(RwLock::new(LabelCache::new())),
                service_accounts: Arc::new(RwLock::new(LabelCache::new())),
            }
        }

        pub fn namespaces(&self) -> Arc<RwLock<LabelCache>> {
            Arc::clone(&self.namespaces)
        }

        pub fn service_accounts(&self) -> Arc<RwLock<LabelCache>> {
            Arc::clone(&self.service_accounts)
        }

        /// Both streams on their own threads. Returns immediately: the caller
        /// keeps serving while the caches are still cold.
        pub fn spawn(&self) {
            for (sink, kind) in [
                (
                    Box::new(SharedLabels(self.namespaces())) as Box<dyn LabelSink>,
                    NAMESPACES,
                ),
                (
                    Box::new(SharedLabels(self.service_accounts())) as Box<dyn LabelSink>,
                    SERVICE_ACCOUNTS,
                ),
            ] {
                let stream = LabelStream {
                    config: self.config.clone(),
                    kind,
                    sink,
                };
                std::thread::spawn(move || stream.run());
            }
        }
    }

    /// Reconnect delay: doubles up to [`MAX_RECONNECT_BACKOFF`] so an apiserver
    /// that closes every connection at once cannot turn us into a busy loop.
    struct Backoff {
        next: Duration,
    }

    impl Backoff {
        fn new() -> Self {
            Self {
                next: RECONNECT_BACKOFF,
            }
        }

        fn take(&mut self) -> Duration {
            let now = self.next;
            self.next = (now * 2).min(MAX_RECONNECT_BACKOFF);
            now
        }

        fn reset(&mut self) {
            self.next = RECONNECT_BACKOFF;
        }
    }

    /// Drives `cycle`, sleeping between every iteration — including the ones
    /// that returned `Ok`, because an apiserver that answers with an immediate
    /// EOF would otherwise spin here. `budget` bounds the iteration count for
    /// tests; production passes `None` and never returns.
    fn watch_loop<C, S>(mut cycle: C, mut sleep: S, budget: Option<usize>)
    where
        C: FnMut() -> Result<()>,
        S: FnMut(Duration),
    {
        let mut backoff = Backoff::new();
        let mut left = budget;
        loop {
            let started = Instant::now();
            if let Err(err) = cycle() {
                eprintln!("ferrum-k8smeta: pod watch cycle failed: {err}");
            }
            // A connection that streamed for a while was healthy, whatever
            // ended it; only repeated short cycles are worth backing off from.
            if started.elapsed() >= HEALTHY_STREAM {
                backoff.reset();
            }
            sleep(backoff.take());
            if let Some(left) = left.as_mut() {
                *left -= 1;
                if *left == 0 {
                    return;
                }
            }
        }
    }

    #[derive(Debug)]
    struct Head {
        status: u16,
        chunked: bool,
        content_length: Option<usize>,
    }

    fn read_head<R: BufRead>(reader: &mut R) -> Result<Head> {
        let mut status = 0u16;
        let mut chunked = false;
        let mut content_length = None;
        let mut first = true;
        let mut seen = 0usize;
        loop {
            seen += 1;
            if seen > MAX_HEADER_LINES {
                return Err(FerrumError::Degraded(format!(
                    "apiserver sent more than {MAX_HEADER_LINES} header lines"
                )));
            }
            let mut line = String::new();
            let n = read_text_line(reader, &mut line)
                .map_err(|e| FerrumError::Degraded(format!("apiserver response: {e}")))?;
            if n == 0 {
                return Err(FerrumError::Degraded(
                    "apiserver closed before headers".into(),
                ));
            }
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            if first {
                status = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| FerrumError::Degraded(format!("bad status line {line:?}")))?;
                first = false;
                continue;
            }
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let value = value.trim();
                if name.eq_ignore_ascii_case("transfer-encoding")
                    && value.to_ascii_lowercase().contains("chunked")
                {
                    chunked = true;
                } else if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse::<usize>().ok();
                }
            }
        }
        Ok(Head {
            status,
            chunked,
            content_length,
        })
    }

    enum BodyReader<'a, R: BufRead> {
        Chunked { inner: &'a mut R, remaining: usize },
        Plain { inner: &'a mut R, remaining: usize },
    }

    impl<'a, R: BufRead> BodyReader<'a, R> {
        fn new(inner: &'a mut R, head: &Head) -> Self {
            if head.chunked {
                BodyReader::Chunked {
                    inner,
                    remaining: 0,
                }
            } else {
                BodyReader::Plain {
                    inner,
                    remaining: head.content_length.unwrap_or(usize::MAX),
                }
            }
        }
    }

    impl<R: BufRead> Read for BodyReader<'_, R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self {
                BodyReader::Plain { inner, remaining } => {
                    if *remaining == 0 {
                        return Ok(0);
                    }
                    let cap = buf.len().min(*remaining);
                    let n = inner.read(&mut buf[..cap])?;
                    *remaining -= n;
                    Ok(n)
                }
                BodyReader::Chunked { inner, remaining } => {
                    if *remaining == 0 {
                        let mut size_line = String::new();
                        if read_text_line(*inner, &mut size_line)? == 0 {
                            return Ok(0);
                        }
                        let size_text = size_line
                            .trim_end_matches(['\r', '\n'])
                            .split(';')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if size_text.is_empty() {
                            return Ok(0);
                        }
                        let size = usize::from_str_radix(&size_text, 16).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, format!("chunk size: {e}"))
                        })?;
                        if size == 0 {
                            return Ok(0);
                        }
                        *remaining = size;
                    }
                    let cap = buf.len().min(*remaining);
                    let n = inner.read(&mut buf[..cap])?;
                    *remaining -= n;
                    if *remaining == 0 {
                        // Consume the CRLF that terminates the chunk.
                        let mut trailer = String::new();
                        let _ = read_text_line(*inner, &mut trailer);
                    }
                    Ok(n)
                }
            }
        }
    }

    fn read_body<R: BufRead>(reader: &mut R, head: &Head, out: &mut Vec<u8>) -> Result<()> {
        if head.content_length.is_some_and(|len| len > MAX_BODY_BYTES) {
            return Err(body_too_large());
        }
        let mut body = BodyReader::new(reader, head);
        let mut buf = [0u8; 8192];
        loop {
            let n = body
                .read(&mut buf)
                .map_err(|e| FerrumError::Degraded(format!("apiserver body: {e}")))?;
            if n == 0 {
                return Ok(());
            }
            if out.len() + n > MAX_BODY_BYTES {
                return Err(body_too_large());
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    fn body_too_large() -> FerrumError {
        FerrumError::Degraded(format!(
            "apiserver body exceeds {MAX_BODY_BYTES} bytes; refusing to buffer it"
        ))
    }

    /// Bounded `read_until`. Used for status/header lines and for chunk-size
    /// lines: all of them are short by construction, and an unbounded read here
    /// lets the peer choose our allocation size.
    fn read_text_line<R: BufRead>(reader: &mut R, out: &mut String) -> io::Result<usize> {
        let mut raw = Vec::new();
        let limit = MAX_HEADER_LINE_BYTES as u64 + 1;
        let n = reader.take(limit).read_until(b'\n', &mut raw)?;
        if n > MAX_HEADER_LINE_BYTES || (n > 0 && raw.last() != Some(&b'\n')) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("header line exceeds {MAX_HEADER_LINE_BYTES} bytes"),
            ));
        }
        out.push_str(&String::from_utf8_lossy(&raw));
        Ok(n)
    }

    /// Line reader over a body stream that is not `BufRead`.
    fn read_line<R: Read>(reader: &mut R, out: &mut Vec<u8>) -> io::Result<usize> {
        let mut byte = [0u8; 1];
        loop {
            match reader.read(&mut byte)? {
                0 => return Ok(out.len()),
                _ => {
                    if byte[0] == b'\n' {
                        return Ok(out.len() + 1);
                    }
                    out.push(byte[0]);
                    if out.len() > MAX_LINE_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "watch frame too large",
                        ));
                    }
                }
            }
        }
    }

    fn percent_encode(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        for b in raw.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::cell::RefCell;

        fn head_of(raw: &[u8]) -> Result<Head> {
            read_head(&mut io::Cursor::new(raw.to_vec()))
        }

        fn degraded_text(err: FerrumError) -> String {
            match err {
                FerrumError::Degraded(msg) => msg,
                other => panic!("expected Degraded, got {other:?}"),
            }
        }

        #[test]
        fn ordinary_head_still_parses() {
            let head = head_of(
                b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .expect("head");
            assert_eq!(head.status, 200);
            assert_eq!(head.content_length, Some(7));
            assert!(head.chunked);
        }

        #[test]
        fn giant_header_line_is_degraded_not_buffered() {
            let mut raw = b"HTTP/1.1 200 OK\r\nX-Flood: ".to_vec();
            raw.extend(std::iter::repeat(b'A').take(MAX_HEADER_LINE_BYTES * 4));
            raw.extend_from_slice(b"\r\n\r\n");
            let msg = degraded_text(head_of(&raw).expect_err("must refuse"));
            assert!(msg.contains("header line exceeds"), "{msg}");
        }

        #[test]
        fn giant_status_line_is_degraded() {
            let mut raw = b"HTTP/1.1 200 ".to_vec();
            raw.extend(std::iter::repeat(b'X').take(MAX_HEADER_LINE_BYTES + 1));
            raw.extend_from_slice(b"\r\n\r\n");
            let msg = degraded_text(head_of(&raw).expect_err("must refuse"));
            assert!(msg.contains("header line exceeds"), "{msg}");
        }

        #[test]
        fn endless_header_count_is_degraded() {
            let mut raw = b"HTTP/1.1 200 OK\r\n".to_vec();
            for i in 0..MAX_HEADER_LINES * 2 {
                raw.extend_from_slice(format!("X-Pad-{i}: v\r\n").as_bytes());
            }
            raw.extend_from_slice(b"\r\n");
            let msg = degraded_text(head_of(&raw).expect_err("must refuse"));
            assert!(msg.contains("header lines"), "{msg}");
        }

        #[test]
        fn body_past_the_ceiling_is_degraded() {
            // Chunked, so the peer never has to declare the total up front.
            let chunk = vec![b'x'; 1 << 20];
            let mut raw = Vec::new();
            for _ in 0..(MAX_BODY_BYTES / chunk.len()) + 2 {
                raw.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                raw.extend_from_slice(&chunk);
                raw.extend_from_slice(b"\r\n");
            }
            let head = Head {
                status: 200,
                chunked: true,
                content_length: None,
            };
            let mut out = Vec::new();
            let err =
                read_body(&mut io::Cursor::new(raw), &head, &mut out).expect_err("must refuse");
            assert!(
                degraded_text(err).contains("exceeds"),
                "message names the cap"
            );
            assert!(out.len() <= MAX_BODY_BYTES, "buffer stayed under the cap");
        }

        #[test]
        fn declared_content_length_past_the_ceiling_is_refused_before_reading() {
            let head = Head {
                status: 200,
                chunked: false,
                content_length: Some(MAX_BODY_BYTES + 1),
            };
            let mut out = Vec::new();
            let err = read_body(&mut io::Cursor::new(Vec::new()), &head, &mut out)
                .expect_err("must refuse");
            assert!(degraded_text(err).contains("exceeds"));
            assert!(out.is_empty());
        }

        #[test]
        fn small_body_still_reads() {
            let head = Head {
                status: 200,
                chunked: false,
                content_length: Some(5),
            };
            let mut out = Vec::new();
            read_body(&mut io::Cursor::new(b"hello".to_vec()), &head, &mut out).expect("body");
            assert_eq!(out, b"hello");
        }

        #[test]
        fn immediate_eof_still_sleeps_between_cycles() {
            let slept: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
            // Every cycle returns Ok instantly, the EOF-on-connect case.
            watch_loop(|| Ok(()), |d| slept.borrow_mut().push(d), Some(4));
            let slept = slept.into_inner();
            assert_eq!(slept.len(), 4, "one sleep per iteration, Ok included");
            assert!(slept.iter().all(|d| *d >= RECONNECT_BACKOFF));
        }

        #[test]
        fn backoff_grows_and_is_capped() {
            let slept: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
            watch_loop(
                || Err(FerrumError::Degraded("connect refused".into())),
                |d| slept.borrow_mut().push(d),
                Some(8),
            );
            let slept = slept.into_inner();
            assert_eq!(slept[0], RECONNECT_BACKOFF);
            assert_eq!(slept[1], RECONNECT_BACKOFF * 2);
            assert_eq!(slept[2], RECONNECT_BACKOFF * 4);
            assert!(
                slept.windows(2).all(|w| w[1] >= w[0]),
                "delay never shrinks while cycles keep failing"
            );
            assert_eq!(*slept.last().expect("delays"), MAX_RECONNECT_BACKOFF);
            assert!(slept.iter().all(|d| *d <= MAX_RECONNECT_BACKOFF));
        }

        #[test]
        fn a_long_healthy_cycle_resets_the_backoff() {
            let mut backoff = Backoff::new();
            assert_eq!(backoff.take(), RECONNECT_BACKOFF);
            assert_eq!(backoff.take(), RECONNECT_BACKOFF * 2);
            backoff.reset();
            assert_eq!(backoff.take(), RECONNECT_BACKOFF);
            assert!(HEALTHY_STREAM > MAX_RECONNECT_BACKOFF);
        }
    }
}
