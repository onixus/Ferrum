//! Pod watch: parsing (always compiled, offline-testable) plus a thin network
//! wrapper behind the `apiserver` feature.
//!
//! No kube client: it would pull tokio into a crate that sits on the decision
//! path. The stream is plain HTTP/1.1 over rustls, same shape as
//! `ferrum-admission::server`.

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
            let code = object.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = object
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("watch error")
                .to_string();
            if code == 410 || object.get("reason").and_then(Value::as_str) == Some("Expired") {
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
        namespace_labels: BTreeMap::new(),
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

#[cfg(feature = "apiserver")]
pub use client::{ApiserverConfig, ApiserverWatcher, SERVICE_ACCOUNT_DIR};

#[cfg(feature = "apiserver")]
mod client {
    use super::{apply_watch_event, event_resource_version, parse_pod_list, parse_watch_event};
    use crate::source::PodCache;
    use crate::watch::WatchOutcome;
    use ferrum_common::{FerrumError, Result};
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::net::TcpStream;
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    pub const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
    /// The apiserver certificate carries this SAN; the Service IP we dial does
    /// not have to be in it, so verification uses the name, not the address.
    const DEFAULT_SERVER_NAME: &str = "kubernetes.default.svc";
    const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
    const RECONNECT_BACKOFF: Duration = Duration::from_secs(2);

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
        /// In-cluster config: Service env vars plus the projected SA volume.
        pub fn from_service_account(node_name: impl Into<String>) -> Result<Self> {
            let host = std::env::var("KUBERNETES_SERVICE_HOST")
                .map_err(|_| FerrumError::Degraded("KUBERNETES_SERVICE_HOST unset".into()))?;
            let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
                .or_else(|_| std::env::var("KUBERNETES_SERVICE_PORT"))
                .unwrap_or_else(|_| "443".into())
                .parse::<u16>()
                .map_err(|e| FerrumError::Degraded(format!("KUBERNETES_SERVICE_PORT: {e}")))?;
            let node_name = node_name.into();
            if node_name.is_empty() {
                return Err(FerrumError::Degraded(
                    "node name required: an unscoped pod watch is a cluster-wide read".into(),
                ));
            }
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

        fn connect(&self) -> Result<TlsStream> {
            let cfg = self.config.tls_config()?;
            let name = rustls::ServerName::try_from(self.config.server_name.as_str())
                .map_err(|e| FerrumError::Degraded(format!("apiserver server name: {e}")))?;
            let conn = rustls::ClientConnection::new(cfg, name)
                .map_err(|e| FerrumError::Degraded(format!("tls client: {e}")))?;
            let tcp = TcpStream::connect((self.config.host.as_str(), self.config.port))
                .map_err(|e| FerrumError::Degraded(format!("apiserver connect: {e}")))?;
            let _ = tcp.set_nodelay(true);
            Ok(rustls::StreamOwned::new(conn, tcp))
        }

        fn request(&self, stream: &mut TlsStream, path: &str) -> Result<()> {
            let token = self.config.token()?;
            let mut req = String::new();
            req.push_str(&format!("GET {path} HTTP/1.1\r\n"));
            req.push_str(&format!("Host: {}\r\n", self.config.server_name));
            req.push_str(&format!("Authorization: Bearer {token}\r\n"));
            req.push_str("Accept: application/json\r\n");
            req.push_str("User-Agent: ferrum-agent\r\n");
            req.push_str("Connection: close\r\n\r\n");
            stream
                .write_all(req.as_bytes())
                .and_then(|_| stream.flush())
                .map_err(|e| FerrumError::Degraded(format!("apiserver request: {e}")))
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
            let mut stream = self.connect()?;
            let path = self.list_path();
            self.request(&mut stream, &path)?;
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
            let mut stream = self.connect()?;
            let path = self.watch_path(rv);
            self.request(&mut stream, &path)?;
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

        /// List, watch, reconnect forever. 410 relists instead of resuming.
        pub fn run(&self) -> ! {
            loop {
                let mut rv = match self.relist() {
                    Ok(rv) => rv,
                    Err(err) => {
                        eprintln!("ferrum-k8smeta: pod relist failed: {err}");
                        std::thread::sleep(RECONNECT_BACKOFF);
                        continue;
                    }
                };
                loop {
                    match self.watch_once(&rv) {
                        Ok(WatchOutcome::MustRelist) => break,
                        Ok(_) => {
                            rv = self
                                .cache
                                .read()
                                .unwrap_or_else(|e| e.into_inner())
                                .resource_version()
                                .to_string();
                            if rv.is_empty() {
                                break;
                            }
                        }
                        Err(err) => {
                            eprintln!("ferrum-k8smeta: pod watch dropped: {err}");
                            std::thread::sleep(RECONNECT_BACKOFF);
                            break;
                        }
                    }
                }
            }
        }
    }

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
        loop {
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
        let mut body = BodyReader::new(reader, head);
        let mut buf = [0u8; 8192];
        loop {
            let n = body
                .read(&mut buf)
                .map_err(|e| FerrumError::Degraded(format!("apiserver body: {e}")))?;
            if n == 0 {
                return Ok(());
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    fn read_text_line<R: BufRead>(reader: &mut R, out: &mut String) -> io::Result<usize> {
        let mut raw = Vec::new();
        let n = reader.read_until(b'\n', &mut raw)?;
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
}
