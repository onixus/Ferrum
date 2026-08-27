//! HTTP/1.1 webhook. std::net only; TLS optional via rustls 0.21.

use chrono::Utc;
use ferrum_api::PolicyExceptionSpec;
use ferrum_ids::Digest;
use rustls::ServerConfig;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime};

use crate::bundle::{
    exceptions_file_path, load_source_with_digest, read_exceptions_path, read_source_path,
    source_snapshot_dir, BUNDLE_DIGEST_KEY, BUNDLE_FSIG_KEY,
};
use crate::program::AdmissionProgram;
use crate::review::ReviewConfig;
use ferrum_common::FerrumError;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Verified program plus pinned trust-root. Bundle reload never fail-opens;
/// the exception list is hot-swappable TTL'd data, re-scoped by eval per request.
pub struct WebhookState {
    program: RwLock<AdmissionProgram>,
    trust_root: Vec<u8>,
    exceptions: RwLock<Vec<PolicyExceptionSpec>>,
    config: ReviewConfig,
}

impl WebhookState {
    pub fn new(
        program: AdmissionProgram,
        trust_root: Vec<u8>,
        exceptions: Vec<PolicyExceptionSpec>,
        config: ReviewConfig,
    ) -> Self {
        Self {
            program: RwLock::new(program),
            trust_root,
            exceptions: RwLock::new(exceptions),
            config,
        }
    }

    /// Clone the current program under a read lock, then evaluate. No disk I/O.
    pub fn handle(&self, body: &[u8]) -> crate::review::ReviewReply {
        let program = self
            .program
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let exceptions = self
            .exceptions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        self.config
            .handle_bytes(body, Some(&program), &exceptions, Utc::now())
    }

    pub fn set_exceptions(&self, list: Vec<PolicyExceptionSpec>) {
        *self.exceptions.write().unwrap_or_else(|e| e.into_inner()) = list;
    }

    /// Parse a PolicyExceptionSpec JSON array (controller `exceptions.json`).
    /// Garbage keeps the previous list: the bundle is fail-closed, but a broken
    /// exception file must not flip decisions either way.
    pub fn try_reload_exceptions(&self, bytes: &[u8]) -> ferrum_common::Result<usize> {
        let list: Vec<PolicyExceptionSpec> = serde_json::from_slice(bytes)
            .map_err(|e| FerrumError::Validation(format!("exceptions.json: {e}")))?;
        let n = list.len();
        self.set_exceptions(list);
        Ok(n)
    }

    /// Missing file = empty list; unreadable or garbage = keep previous (Err).
    pub fn try_reload_exceptions_path(&self, path: &Path) -> ferrum_common::Result<usize> {
        match read_exceptions_path(path)? {
            Some(bytes) => self.try_reload_exceptions(&bytes),
            None => {
                self.set_exceptions(Vec::new());
                Ok(0)
            }
        }
    }

    /// Verify `bytes` (raw FSIG or Secret JSON). On success swap; on error keep last-good.
    pub fn try_reload(&self, bytes: &[u8]) -> ferrum_common::Result<Digest> {
        self.try_reload_with_digest(bytes, None)
    }

    /// Verify bytes plus an expected SHA-256(raw) (directory sibling `digest`).
    pub fn try_reload_with_digest(
        &self,
        bytes: &[u8],
        expected_digest: Option<&Digest>,
    ) -> ferrum_common::Result<Digest> {
        let (program, digest) = load_source_with_digest(bytes, &self.trust_root, expected_digest)?;
        *self.program.write().unwrap_or_else(|e| e.into_inner()) = program;
        Ok(digest)
    }

    /// Load a file or directory mount. Directory `digest` mismatch does not swap.
    pub fn try_reload_path(&self, path: &Path) -> ferrum_common::Result<Digest> {
        let (bytes, expected) = read_source_path(path)?;
        self.try_reload_with_digest(&bytes, expected.as_ref())
    }
}

/// Bind and serve until the listener fails. One thread per connection.
pub fn serve(
    listen: &str,
    state: Arc<WebhookState>,
    tls: Option<Arc<ServerConfig>>,
) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    serve_listener(listener, state, tls)
}

/// Accept loop for an already-bound listener (poll starts after listen).
pub fn serve_listener(
    listener: TcpListener,
    state: Arc<WebhookState>,
    tls: Option<Arc<ServerConfig>>,
) -> io::Result<()> {
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        let state = Arc::clone(&state);
        let tls = tls.clone();
        thread::spawn(move || {
            let _ = handle_connection(stream, &state, tls);
        });
    }
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    state: &WebhookState,
    tls: Option<Arc<ServerConfig>>,
) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    match tls {
        Some(cfg) => {
            let conn = rustls::ServerConnection::new(cfg)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let mut tls_stream = rustls::StreamOwned::new(conn, stream);
            serve_http(&mut tls_stream, state)
        }
        None => serve_http(&mut stream, state),
    }
}

fn serve_http<S>(stream: &mut S, state: &WebhookState) -> io::Result<()>
where
    S: Read + Write,
{
    let mut reader = BufReader::new(stream);
    let (method, body) = match read_request(&mut reader) {
        Ok(v) => v,
        Err(err) if err.kind() == io::ErrorKind::InvalidData => {
            let inner = reader.get_mut();
            return write_response(
                inner,
                400,
                "Bad Request",
                br#"{"error":"invalid HTTP request"}"#,
            );
        }
        Err(err) => return Err(err),
    };
    let inner = reader.get_mut();
    if method != "POST" {
        return write_response(inner, 405, "Method Not Allowed", b"");
    }
    let reply = state.handle(&body);
    let reason = match reply.status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Error",
    };
    write_response(inner, reply.status, reason, &reply.body)
}

fn read_request<R: BufRead>(reader: &mut R) -> io::Result<(String, Vec<u8>)> {
    let mut header = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "eof before headers",
            ));
        }
        header.extend_from_slice(&line);
        if header.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
        if header.windows(4).any(|w| w == b"\r\n\r\n") || header.windows(2).any(|w| w == b"\n\n") {
            break;
        }
    }
    let header_text = String::from_utf8_lossy(&header);
    let mut lines = header_text.split('\n');
    let request_line = lines.next().unwrap_or("").trim_end_matches('\r');
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let mut content_length: Option<usize> = None;
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().ok();
            }
        }
    }
    let len = content_length
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Content-Length required"))?;
    if len > MAX_BODY_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    Ok((method, body))
}

fn write_response<W: Write>(w: &mut W, status: u16, reason: &str, body: &[u8]) -> io::Result<()> {
    write!(w, "HTTP/1.1 {status} {reason}\r\n")?;
    write!(w, "Content-Type: application/json\r\n")?;
    write!(w, "Content-Length: {}\r\n", body.len())?;
    write!(w, "Connection: close\r\n")?;
    write!(w, "\r\n")?;
    w.write_all(body)?;
    w.flush()
}

/// Load PEM cert + PKCS8/RSA key for optional HTTPS.
pub fn load_tls_config(cert_path: &str, key_path: &str) -> Result<Arc<ServerConfig>, String> {
    let cert_file = std::fs::File::open(cert_path).map_err(|e| format!("tls cert: {e}"))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .map_err(|e| format!("tls cert parse: {e}"))?
        .into_iter()
        .map(rustls::Certificate)
        .collect::<Vec<_>>();
    if certs.is_empty() {
        return Err("tls cert file contains no certificates".into());
    }
    let key_file = std::fs::File::open(key_path).map_err(|e| format!("tls key: {e}"))?;
    let mut key_reader = BufReader::new(key_file);
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .map_err(|e| format!("tls key parse: {e}"))?;
    if keys.is_empty() {
        let key_file = std::fs::File::open(key_path).map_err(|e| format!("tls key: {e}"))?;
        let mut key_reader = BufReader::new(key_file);
        keys = rustls_pemfile::rsa_private_keys(&mut key_reader)
            .map_err(|e| format!("tls key parse: {e}"))?;
    }
    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| "tls key file contains no private key".to_string())?;
    let cfg = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, rustls::PrivateKey(key))
        .map_err(|e| format!("tls config: {e}"))?;
    Ok(Arc::new(cfg))
}

/// Watch `path` (file, or directory containing `bundle.fsig` + `digest`) on a std thread.
/// Uses mtime+len and follows kubelet `..data`; a vanished file keeps last-good.
pub fn poll_bundle_file(path: impl Into<PathBuf>, interval: Duration, state: Arc<WebhookState>) {
    let path = path.into();
    thread::spawn(move || poll_loop(path, interval, state));
}

fn poll_loop(path: PathBuf, interval: Duration, state: Arc<WebhookState>) {
    // Stat the path as given so kubelet `..data` rotates are visible; do not canonicalize.
    // Start with no stamp so a rotation between first load and this thread is not skipped.
    let mut stamp = None;
    loop {
        thread::sleep(interval);
        let Some(next) = file_stamp(&path) else {
            continue;
        };
        if Some(next) == stamp {
            continue;
        }
        stamp = Some(next);
        if let Err(err) = state.try_reload_path(&path) {
            eprintln!("ferrum-admission: bundle reload failed, keeping last-known-good: {err}");
        }
    }
}

/// Watch the `--exceptions` mount (dir with `exceptions.json`, or the file
/// itself). File gone = swap to empty; garbage = keep the previous list.
pub fn poll_exceptions_file(
    path: impl Into<PathBuf>,
    interval: Duration,
    state: Arc<WebhookState>,
) {
    let path = path.into();
    thread::spawn(move || poll_exceptions_loop(path, interval, state));
}

fn poll_exceptions_loop(path: PathBuf, interval: Duration, state: Arc<WebhookState>) {
    let mut stamp: Option<FileStamp> = None;
    let mut cleared = false;
    loop {
        thread::sleep(interval);
        // Re-resolve every tick: kubelet `..data` rotation moves the file.
        match stamp_one(&exceptions_file_path(&path)) {
            None => {
                if !cleared {
                    state.set_exceptions(Vec::new());
                    cleared = true;
                    stamp = None;
                }
            }
            Some(next) => {
                cleared = false;
                if Some(next) == stamp {
                    continue;
                }
                stamp = Some(next);
                if let Err(err) = state.try_reload_exceptions_path(&path) {
                    eprintln!(
                        "ferrum-admission: exceptions reload failed, keeping previous list: {err}"
                    );
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    mtime: SystemTime,
    len: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct SourceStamp {
    fsig: FileStamp,
    digest: Option<FileStamp>,
}

fn stamp_one(path: &Path) -> Option<FileStamp> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.is_dir() {
        return None;
    }
    Some(FileStamp {
        mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        len: meta.len(),
    })
}

fn file_stamp(path: &Path) -> Option<SourceStamp> {
    if let Some(snap) = source_snapshot_dir(path) {
        Some(SourceStamp {
            fsig: stamp_one(&snap.join(BUNDLE_FSIG_KEY))?,
            digest: Some(stamp_one(&snap.join(BUNDLE_DIGEST_KEY))?),
        })
    } else {
        Some(SourceStamp {
            fsig: stamp_one(path)?,
            digest: None,
        })
    }
}
