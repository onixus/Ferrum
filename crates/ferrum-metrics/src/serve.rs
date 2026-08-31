//! The listener. HTTP/1.1 over `std::net`, `GET /metrics`, nothing else.
//!
//! This is the part of the crate that is an attack surface, so it is written
//! to be boring and is enumerated here rather than reviewed by reading it:
//!
//!  * **No body is ever read.** There is no `Content-Length` handling and no
//!    `read_exact`. A request is a request line plus headers up to
//!    [`MAX_HEADER_BYTES`], and everything after the blank line is discarded
//!    with the connection.
//!  * **Only `GET` and only [`METRICS_PATH`].** Any other method is 405, any
//!    other path 404. A query string is refused rather than ignored: a scraper
//!    does not send one, and a request that carries one wants something this
//!    endpoint does not have.
//!  * **No TLS and no authentication.** Deliberate, and it is why the manifests
//!    ship a NetworkPolicy: an endpoint that is authenticated by a shared
//!    secret in a mounted Secret would put a credential in every namespace that
//!    wanted to scrape, and one authenticated by the webhook's serving
//!    certificate would make the API server's CA a monitoring dependency. What
//!    limits who can reach this port is the network, stated as a policy object
//!    an operator can read, not a check that lives in this file.
//!  * **Timeouts on both directions.** Without them one held-open connection
//!    per thread is a thread leak, and this runs on a DaemonSet where the
//!    reachable-from-a-pod surface is the whole point of the threat model.
//!  * **A bounded number of connections in flight.** Past
//!    [`ServeConfig::max_in_flight`] a connection is answered 503 and closed by
//!    the accept thread itself, so a scrape storm costs no threads.
//!
//! The render closure is called on the connection thread. It must not block on
//! anything the process needs for its real work — in this tree it takes a read
//! guard on already-computed state and formats a string.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// The only path this server answers.
pub const METRICS_PATH: &str = "/metrics";
/// Prometheus text exposition format, version 0.0.4.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Enough for any scraper's headers and small enough that a client sending an
/// endless header stream is cut off rather than accumulating in this process.
const MAX_HEADER_BYTES: usize = 8 * 1024;

pub struct ServeConfig {
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub max_in_flight: usize,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
            // A scrape interval of 15s across a handful of Prometheus replicas
            // never reaches this; a client opening connections in a loop does,
            // and gets 503 instead of a thread each.
            max_in_flight: 16,
        }
    }
}

/// Accept loop for an already-bound listener. Returns only if accept fails.
///
/// Takes the listener rather than an address so a caller can bind before
/// forking off the thread and fail loudly at startup: a metrics port that could
/// not be bound must be a startup error the operator sees, not a silent absence
/// discovered later as a target that never came up.
pub fn serve_listener<F>(listener: TcpListener, config: ServeConfig, render: F) -> io::Result<()>
where
    F: Fn() -> String + Send + Sync + 'static,
{
    let render = Arc::new(render);
    let in_flight = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(s) => s,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        let _ = stream.set_read_timeout(Some(config.read_timeout));
        let _ = stream.set_write_timeout(Some(config.write_timeout));
        if in_flight.load(Ordering::Relaxed) >= config.max_in_flight {
            let mut stream = stream;
            let _ = respond(
                &mut stream,
                503,
                "Service Unavailable",
                "text/plain",
                b"busy\n",
            );
            continue;
        }
        in_flight.fetch_add(1, Ordering::Relaxed);
        let render = Arc::clone(&render);
        let in_flight = Arc::clone(&in_flight);
        thread::spawn(move || {
            let _ = handle(stream, render.as_ref());
            in_flight.fetch_sub(1, Ordering::Relaxed);
        });
    }
    Ok(())
}

fn handle<F>(mut stream: TcpStream, render: &F) -> io::Result<()>
where
    F: Fn() -> String,
{
    let request = { read_request_line_and_drain_headers(BufReader::new(&mut stream))? };
    match request {
        Request::Metrics => {
            let body = render();
            respond(&mut stream, 200, "OK", CONTENT_TYPE, body.as_bytes())
        }
        Request::NotFound => respond(
            &mut stream,
            404,
            "Not Found",
            "text/plain",
            b"only /metrics\n",
        ),
        Request::NotAllowed => respond(
            &mut stream,
            405,
            "Method Not Allowed",
            "text/plain",
            b"only GET\n",
        ),
        Request::Bad => respond(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"bad request\n",
        ),
    }
}

enum Request {
    Metrics,
    NotFound,
    NotAllowed,
    Bad,
}

/// Read the request line, then read and discard headers to the blank line.
///
/// Discard, not parse: the only header a scraper sends that could matter is
/// `Accept`, and this endpoint has one representation. Reading them at all is
/// so that the client's write completes before the response is sent — a server
/// that answers and closes while the client is still writing gets an RST on
/// some stacks and the scrape reads as a failure.
fn read_request_line_and_drain_headers<R: BufRead>(reader: R) -> io::Result<Request> {
    let mut capped = reader.take(MAX_HEADER_BYTES as u64);
    let mut line = String::new();
    if capped.read_line(&mut line)? == 0 {
        return Ok(Request::Bad);
    }
    let verdict = classify(line.trim_end_matches(['\r', '\n']));
    loop {
        let mut header = String::new();
        let n = capped.read_line(&mut header)?;
        if n == 0 {
            // The cap was reached mid-header-block, or the peer went away
            // before the blank line. Either way the request was never
            // complete, and answering a partial one is answering a guess.
            return Ok(if capped.limit() == 0 {
                Request::Bad
            } else {
                verdict
            });
        }
        if header.trim_end_matches(['\r', '\n']).is_empty() {
            break;
        }
    }
    Ok(verdict)
}

fn classify(request_line: &str) -> Request {
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Request::Bad;
    };
    if method != "GET" {
        return Request::NotAllowed;
    }
    // A query string is refused rather than trimmed: a scraper sends none, and
    // silently ignoring one would let a caller believe it selected something.
    if target == METRICS_PATH {
        Request::Metrics
    } else {
        Request::NotFound
    }
}

fn respond<W: Write>(
    w: &mut W,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> io::Result<()> {
    write!(w, "HTTP/1.1 {status} {reason}\r\n")?;
    write!(w, "Content-Type: {content_type}\r\n")?;
    write!(w, "Content-Length: {}\r\n", body.len())?;
    // Nothing here is cacheable and nothing here is a document a browser should
    // be guessing the type of.
    write!(w, "Cache-Control: no-store\r\n")?;
    write!(w, "X-Content-Type-Options: nosniff\r\n")?;
    write!(w, "Connection: close\r\n\r\n")?;
    w.write_all(body)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpStream;

    fn spawn(body: &'static str) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            let _ = serve_listener(listener, ServeConfig::default(), move || body.to_string());
        });
        addr
    }

    fn request(addr: std::net::SocketAddr, raw: &str) -> String {
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream.write_all(raw.as_bytes()).expect("write");
        let mut out = String::new();
        stream.read_to_string(&mut out).expect("read");
        out
    }

    #[test]
    fn a_scrape_gets_the_rendered_body_and_the_prometheus_content_type() {
        let addr = spawn("ferrum_agent_degraded 0\n");
        let response = request(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains(CONTENT_TYPE), "{response}");
        assert!(
            response.ends_with("ferrum_agent_degraded 0\n"),
            "{response}"
        );
    }

    /// The endpoint is read-only by construction, and this is the assertion of
    /// it: a POST carrying a body is refused without the body ever being read.
    #[test]
    fn nothing_but_a_get_of_the_metrics_path_is_answered() {
        let addr = spawn("x 1\n");
        let posted = request(
            addr,
            "POST /metrics HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
        );
        assert!(
            posted.starts_with("HTTP/1.1 405 "),
            "a write method was accepted: {posted}"
        );
        assert!(!posted.contains("x 1"), "a refused method got the body");

        let elsewhere = request(addr, "GET /debug/pprof HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(elsewhere.starts_with("HTTP/1.1 404 "), "{elsewhere}");

        let with_query = request(addr, "GET /metrics?name=x HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(
            with_query.starts_with("HTTP/1.1 404 "),
            "a query string was honoured rather than refused: {with_query}"
        );
    }

    /// A header block that never ends is cut off at the cap, and what the
    /// client gets back is never the metrics.
    ///
    /// The response may not arrive at all: the server stops reading at the cap
    /// and closes, so the client is still writing into a socket the peer has
    /// gone from and the OS answers RST. That is the intended shape — refusing
    /// early is the point — so the assertion is on what may not happen (a
    /// rendered body) rather than on a status line that a reset denies us.
    #[test]
    fn a_header_stream_with_no_end_is_cut_off_rather_than_accumulated() {
        let addr = spawn("x 1\n");
        let mut raw = String::from("GET /metrics HTTP/1.1\r\n");
        while raw.len() < MAX_HEADER_BYTES * 4 {
            raw.push_str("X-Pad: 0123456789abcdef\r\n");
        }
        raw.push_str("\r\n");
        let mut stream = TcpStream::connect(addr).expect("connect");
        let _ = stream.write_all(raw.as_bytes());
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert!(
            !response.contains("x 1"),
            "an unterminated header block was served the metrics body: {response}"
        );
        assert!(
            response.is_empty() || response.starts_with("HTTP/1.1 400 "),
            "unexpected answer to an oversized header block: {}",
            &response[..response.len().min(64)]
        );
    }
}
