//! HTTP/1.1 webhook. std::net only; TLS optional via rustls 0.21.

use chrono::Utc;
use ferrum_api::PolicyExceptionSpec;
use ferrum_ids::Digest;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, SystemTime};

use crate::bundle::{
    exceptions_file_path, load_source_with_digest, read_exceptions_path, read_source_path,
    source_snapshot_dir, verify_exceptions_fsig, BUNDLE_DIGEST_KEY, BUNDLE_FSIG_KEY,
    EXCEPTIONS_FSIG_KEY,
};
use crate::program::AdmissionProgram;
use crate::review::ReviewConfig;
use crate::serving_cert::TlsSource;
use ferrum_common::FerrumError;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Verified program plus pinned trust-root. Bundle reload never fail-opens;
/// the exception list is a signed `exceptions.fsig` verified against the same
/// pin, hot-swappable, and re-scoped by eval per request.
pub struct WebhookState {
    program: RwLock<AdmissionProgram>,
    trust_root: Vec<u8>,
    exceptions: RwLock<Vec<PolicyExceptionSpec>>,
    exceptions_resets: std::sync::atomic::AtomicU64,
    exceptions_cleared: std::sync::atomic::AtomicU64,
    bundle_unreadable: std::sync::atomic::AtomicU64,
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
            exceptions_resets: std::sync::atomic::AtomicU64::new(0),
            exceptions_cleared: std::sync::atomic::AtomicU64::new(0),
            bundle_unreadable: std::sync::atomic::AtomicU64::new(0),
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

    /// How many exceptions the webhook would apply right now.
    pub fn exception_count(&self) -> usize {
        self.exceptions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// How many times a broken/unverifiable exception source reset the list.
    pub fn exceptions_resets(&self) -> u64 {
        self.exceptions_resets
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many times the waiver table was emptied because the source key is
    /// gone. Separate from [`WebhookState::exceptions_resets`]: an absent
    /// `exceptions.fsig` is a Secret that carries no waivers, which is a
    /// legitimate state and not a failure — but it drops every approved waiver
    /// just the same, so it is counted rather than left to be inferred from
    /// denies that look like ordinary policy.
    pub fn exceptions_clears(&self) -> u64 {
        self.exceptions_cleared
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// How many times the bundle mount answered a stat with something that is
    /// neither a readable file nor ENOENT. Each one is a poll loop that has
    /// stopped seeing the changes it exists to see.
    pub fn bundle_unreadable(&self) -> u64 {
        self.bundle_unreadable
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn note_bundle_unreadable(&self) -> u64 {
        self.bundle_unreadable
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1
    }

    /// Empty the table because the source carries no waivers, and count it.
    fn clear_exceptions_absent(&self) -> (usize, u64) {
        let had = self.exception_count();
        self.set_exceptions(Vec::new());
        let total = self
            .exceptions_cleared
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        (had, total)
    }

    fn reset_exceptions(&self, err: FerrumError) -> FerrumError {
        self.exceptions_resets
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.set_exceptions(Vec::new());
        err
    }

    /// Verify a controller `exceptions.fsig` against the pinned trust root,
    /// then parse the signed JSON array. Unsigned plain JSON, a foreign key,
    /// a tampered payload, or garbage RESETS the list to empty (counted,
    /// returned as Err): a Secret writer without the signing key must not be
    /// able to keep — or forge — a live exception.
    pub fn try_reload_exceptions(&self, bytes: &[u8]) -> ferrum_common::Result<usize> {
        let payload = verify_exceptions_fsig(bytes, &self.trust_root)
            .map_err(|e| self.reset_exceptions(e))?;
        let list: Vec<PolicyExceptionSpec> = serde_json::from_slice(&payload).map_err(|e| {
            self.reset_exceptions(FerrumError::Validation(format!(
                "exceptions.fsig payload: {e}"
            )))
        })?;
        let n = list.len();
        self.set_exceptions(list);
        Ok(n)
    }

    /// Missing file = empty list; unreadable or unverifiable = reset to empty (Err).
    pub fn try_reload_exceptions_path(&self, path: &Path) -> ferrum_common::Result<usize> {
        match read_exceptions_path(path) {
            Ok(Some(bytes)) => self.try_reload_exceptions(&bytes),
            Ok(None) => {
                self.set_exceptions(Vec::new());
                Ok(0)
            }
            Err(err) => Err(self.reset_exceptions(err)),
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
    tls: Option<Arc<TlsSource>>,
) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    serve_listener(listener, state, tls)
}

/// Accept loop for an already-bound listener (poll starts after listen).
pub fn serve_listener(
    listener: TcpListener,
    state: Arc<WebhookState>,
    tls: Option<Arc<TlsSource>>,
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
    tls: Option<Arc<TlsSource>>,
) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    match tls {
        // Read the config per connection: rotation swaps it, and a handshake
        // already in flight keeps the certificate it started with.
        Some(source) => {
            let conn = rustls::ServerConnection::new(source.config())
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

/// Watch `path` (file, or directory containing `bundle.fsig` + `digest`) on a std thread.
/// Uses mtime+len and follows kubelet `..data`; a vanished file keeps last-good.
pub fn poll_bundle_file(path: impl Into<PathBuf>, interval: Duration, state: Arc<WebhookState>) {
    let path = path.into();
    thread::spawn(move || poll_loop(path, interval, state));
}

fn poll_loop(path: PathBuf, interval: Duration, state: Arc<WebhookState>) {
    // Stat the path as given so kubelet `..data` rotates are visible; do not canonicalize.
    // Start with no answer so a rotation between first load and this thread is not skipped.
    let mut stat: Option<MountStat<SourceStamp>> = None;
    loop {
        thread::sleep(interval);
        let next = source_stat(&path);
        if Some(next) == stat {
            continue;
        }
        stat = Some(next);
        match next {
            MountStat::Present(_) => {
                if let Err(err) = state.try_reload_path(&path) {
                    eprintln!(
                        "ferrum-admission: bundle reload failed, keeping last-known-good: {err}"
                    );
                }
            }
            // A key that vanished from the mount is a Secret mid-rewrite: keep
            // the last-known-good program and wait for the next Present tick.
            MountStat::Absent => {}
            MountStat::Unreadable => {
                let total = state.note_bundle_unreadable();
                eprintln!(
                    "ferrum-admission: bundle mount {} is present but cannot be stat'd; the \
                     webhook keeps the program it has and will not see any further change until \
                     that stops (bundle_unreadable_total={total})",
                    path.display()
                );
            }
        }
    }
}

/// Watch the `--exceptions` mount (dir with `exceptions.fsig`, or the file
/// itself). File gone = swap to empty; unverifiable = reset to empty.
pub fn poll_exceptions_file(
    path: impl Into<PathBuf>,
    interval: Duration,
    state: Arc<WebhookState>,
) {
    let path = path.into();
    thread::spawn(move || poll_exceptions_loop(path, interval, state));
}

fn poll_exceptions_loop(path: PathBuf, interval: Duration, state: Arc<WebhookState>) {
    let mut stat: Option<MountStat<FileStamp>> = None;
    loop {
        thread::sleep(interval);
        // Re-resolve every tick: kubelet `..data` rotation moves the file.
        let next = stat_one(&exceptions_file_path(&path));
        if Some(next) == stat {
            continue;
        }
        stat = Some(next);
        match next {
            MountStat::Absent => {
                let (had, total) = state.clear_exceptions_absent();
                eprintln!(
                    "ferrum-admission: {} carries no {EXCEPTIONS_FSIG_KEY}; {had} waiver(s) \
                     dropped, every one of them now denies \
                     (exceptions_cleared_total={total})",
                    path.display()
                );
            }
            // Present and unreadable both go through the reload, which is the
            // one place that separates ENOENT from a read that refused. An
            // unreadable file cannot be verified, so its waivers stop applying
            // — the same direction as a failed reload, and counted as one.
            MountStat::Present(_) | MountStat::Unreadable => {
                if let Err(err) = state.try_reload_exceptions_path(&path) {
                    eprintln!(
                        "ferrum-admission: exceptions reload failed, list reset to empty \
                         (resets_total={}): {err}",
                        state.exceptions_resets()
                    );
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileStamp {
    mtime: SystemTime,
    len: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceStamp {
    fsig: FileStamp,
    digest: Option<FileStamp>,
}

/// What a stat of a mounted file established.
///
/// Three answers, not two. `std::fs::metadata(..).ok()` collapses "no such
/// file" into "there, but the stat refused", and every poll loop in this crate
/// answered both with `continue` — so a mount that went EACCES after a
/// remount, EIO, or ELOOP on a `..data` symlink caught mid-rotation left the
/// process frozen on whatever it had loaded at startup, for the life of the
/// process, without a line of output.
///
/// The shape is `ferrum-agent`'s `ExceptionsStamp`; the enforcement is not.
/// The agent has a last-known-good on disk to fall back to, so `Unreadable` is
/// a degradation it reports and recovers from. This process has none: what it
/// holds in memory is all there is, so `Unreadable` is a *stall* — the loop
/// stops seeing changes it exists to see — and the log line plus counter are
/// the whole of what makes it visible. A deliberately shared helper is
/// rejected: `ferrum-common` holds no filesystem code, and the two crates give
/// the third answer opposite meanings.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MountStat<T> {
    /// ENOENT: the key is not in the mount.
    Absent,
    Present(T),
    /// The stat failed for a reason that is not ENOENT, or succeeded on
    /// something that is not a regular file — a directory where the file was.
    /// Never equal to `Absent`.
    Unreadable,
}

pub(crate) fn stat_one(path: &Path) -> MountStat<FileStamp> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => MountStat::Present(FileStamp {
            mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            len: meta.len(),
        }),
        Ok(_) => MountStat::Unreadable,
        Err(err) if err.kind() == io::ErrorKind::NotFound => MountStat::Absent,
        Err(_) => MountStat::Unreadable,
    }
}

fn source_stat(path: &Path) -> MountStat<SourceStamp> {
    let Some(snap) = source_snapshot_dir(path) else {
        return match stat_one(path) {
            MountStat::Present(fsig) => MountStat::Present(SourceStamp { fsig, digest: None }),
            MountStat::Absent => MountStat::Absent,
            MountStat::Unreadable => MountStat::Unreadable,
        };
    };
    match (
        stat_one(&snap.join(BUNDLE_FSIG_KEY)),
        stat_one(&snap.join(BUNDLE_DIGEST_KEY)),
    ) {
        (MountStat::Unreadable, _) | (_, MountStat::Unreadable) => MountStat::Unreadable,
        (MountStat::Present(fsig), MountStat::Present(digest)) => MountStat::Present(SourceStamp {
            fsig,
            digest: Some(digest),
        }),
        _ => MountStat::Absent,
    }
}
