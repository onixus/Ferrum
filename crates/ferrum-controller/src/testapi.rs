//! A stub API server for the tests in this crate. Test-only: `lib.rs` declares
//! it under `cfg(test)` and nothing here is compiled into a binary.
//!
//! It exists because the receipts the health surface runs on are produced by
//! the call that reaches the API server, and the defects they carry — a
//! receipt dropped on the first refusal, a converged object that credits
//! nothing — are invisible to any test that stops at a pure function. The
//! server speaks enough HTTP/1.1 for `kube::Client`: one blocking thread, one
//! request at a time, a canned answer per route, and a log of what was asked.

use kube::Client;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// One request as the stub saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Req {
    pub method: String,
    /// Path with its query string, exactly as it arrived.
    pub target: String,
    pub body: String,
}

impl Req {
    /// The path without the query string.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }
}

type Route = Arc<dyn Fn(&Req) -> (u16, serde_json::Value) + Send + Sync>;

pub struct StubApi {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Req>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl StubApi {
    /// Start a server that answers every request with `route`.
    pub fn start(route: Route) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen: Arc<Mutex<Vec<Req>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let seen = Arc::clone(&seen);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let Ok(stream) = stream else { return };
                    // One thread per connection, detached: `kube` keeps its
                    // connections pooled and idle, so an accept loop that
                    // served them inline would sit in `read` on the first one
                    // while the client opened a second.
                    let seen = Arc::clone(&seen);
                    let route = Arc::clone(&route);
                    let stop = Arc::clone(&stop);
                    std::thread::spawn(move || serve(stream, &seen, &route, &stop));
                }
            })
        };
        StubApi {
            addr,
            seen,
            stop,
            handle: Some(handle),
        }
    }

    pub fn client(&self) -> Client {
        // The same call `run_watch` makes before its own client: `kube` builds
        // a rustls config even for an `http://` server and panics without a
        // provider.
        crate::watch::install_crypto_provider();
        let url = format!("http://{}", self.addr)
            .parse()
            .expect("stub url parses");
        let mut config = kube::Config::new(url);
        config.default_namespace = "ferrum".into();
        // A test that hangs on a stub that did not answer is a test that says
        // nothing; the real default is minutes.
        config.connect_timeout = Some(std::time::Duration::from_secs(2));
        config.read_timeout = Some(std::time::Duration::from_secs(3));
        Client::try_from(config).expect("client from stub config")
    }

    pub fn seen(&self) -> Vec<Req> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn seen_matching(&self, method: &str, path_infix: &str) -> Vec<Req> {
        self.seen()
            .into_iter()
            .filter(|r| r.method == method && r.path().contains(path_infix))
            .collect()
    }
}

impl Drop for StubApi {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Unblock `incoming()`.
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve(stream: TcpStream, seen: &Arc<Mutex<Vec<Req>>>, route: &Route, stop: &Arc<AtomicBool>) {
    // So an idle pooled connection cannot hold this thread past the end of the
    // test: every read returns within the poll interval and the loop rechecks
    // `stop`.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(100)));
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut out = stream;
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let req = match read_request(&mut reader, stop) {
            Some(req) => req,
            None => return,
        };
        seen.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(req.clone());
        let (code, body) = route(&req);
        let body = serde_json::to_vec(&body).expect("json");
        let head = format!(
            "HTTP/1.1 {code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            reason(code),
            body.len()
        );
        if out.write_all(head.as_bytes()).is_err() || out.write_all(&body).is_err() {
            return;
        }
        let _ = out.flush();
    }
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Content Too Large",
        _ => "Status",
    }
}

/// One request, or `None` when the peer went away or the stub is stopping.
///
/// Every read is retried across the socket's poll timeout, so a line that
/// arrives in two packets is still read whole.
fn read_request(reader: &mut BufReader<TcpStream>, stop: &Arc<AtomicBool>) -> Option<Req> {
    let line = read_line(reader, stop)?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut len = 0usize;
    loop {
        let header = read_line(reader, stop)?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some(v) = header
            .split_once(':')
            .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        {
            len = v.1.trim().parse().unwrap_or(0);
        }
    }
    let mut body = Vec::new();
    while body.len() < len {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        let mut chunk = vec![0u8; len - body.len()];
        match reader.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(err) if would_block(&err) => continue,
            Err(_) => return None,
        }
    }
    Some(Req {
        method,
        target,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// A line, retried over the socket's poll timeout. `None` on EOF or stop.
fn read_line(reader: &mut BufReader<TcpStream>, stop: &Arc<AtomicBool>) -> Option<String> {
    let mut line = String::new();
    loop {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        match reader.read_line(&mut line) {
            Ok(0) => return None,
            Ok(_) if line.ends_with('\n') => return Some(line),
            // A partial line: `read_line` appends, so the next read resumes it.
            Ok(_) => continue,
            Err(err) if would_block(&err) => continue,
            Err(_) => return None,
        }
    }
}

fn would_block(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}

/// A `Status` object with `code`, which is what `kube` turns into an error.
pub fn status_error(code: u16, message: &str) -> serde_json::Value {
    serde_json::json!({
        "kind": "Status",
        "apiVersion": "v1",
        "status": "Failure",
        "message": message,
        "code": code,
    })
}
