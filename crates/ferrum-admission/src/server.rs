//! HTTP/1.1 webhook. std::net only; TLS optional via rustls 0.21.

use chrono::Utc;
use ferrum_api::PolicyExceptionSpec;
use rustls::ServerConfig;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use crate::program::AdmissionProgram;
use crate::review::ReviewConfig;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Loaded once at process start. Missing pin/bundle never reach this type.
pub struct WebhookState {
    pub program: AdmissionProgram,
    pub exceptions: Vec<PolicyExceptionSpec>,
    pub config: ReviewConfig,
}

impl WebhookState {
    pub fn handle(&self, body: &[u8]) -> crate::review::ReviewReply {
        self.config
            .handle_bytes(body, Some(&self.program), &self.exceptions, Utc::now())
    }
}

/// Bind and serve until the listener fails. One thread per connection.
pub fn serve(
    listen: &str,
    state: Arc<WebhookState>,
    tls: Option<Arc<ServerConfig>>,
) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
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
