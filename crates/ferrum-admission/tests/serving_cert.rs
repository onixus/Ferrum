//! Serving certificate: refuse to start on expired material, swap on rotation,
//! keep the current certificate when the new material is unusable.
//!
//! Fixtures in `tests/fixtures/pki` are a test-only CA and five leaves for the
//! Service names `ferrum-admission.ferrum`. `serving` and `rotated` are two
//! different leaves of the same CA, `narrow` carries one SAN instead of four,
//! `expired` is what the cluster ends up with when nobody rotates, and
//! `foreign` is a leaf from a second CA that reuses the first one's name —
//! usable material by every other measure, and not the CA in the caBundle.

mod common;

use ferrum_admission::{
    parse_program, poll_serving_cert, serve_listener, ReviewConfig, TlsSource, WebhookState,
};
use ferrum_api::ClusterSecurityPolicySpec;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const SERVICE_NAME: &str = "ferrum-admission.ferrum.svc";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pki")
        .join(name)
}

fn fixture_der(name: &str) -> Vec<u8> {
    let pem = std::fs::read(fixture(name)).expect("fixture");
    rustls_pemfile::certs(&mut pem.as_slice())
        .expect("pem")
        .remove(0)
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ferrum-serving-{tag}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Install `<name>.crt` / `<name>.key` as the mounted serving material.
fn install(dir: &Path, name: &str) {
    std::fs::write(
        dir.join("tls.crt"),
        std::fs::read(fixture(&format!("{name}.crt"))).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.join("tls.key"),
        std::fs::read(fixture(&format!("{name}.key"))).unwrap(),
    )
    .unwrap();
}

fn source(dir: &Path) -> Arc<TlsSource> {
    TlsSource::load(
        dir.join("tls.crt").to_str().unwrap(),
        dir.join("tls.key").to_str().unwrap(),
    )
    .expect("serving material")
}

fn state() -> Arc<WebhookState> {
    let fadm = common::encode_cluster(&ClusterSecurityPolicySpec::default());
    let program = parse_program(&fadm).expect("program");
    Arc::new(WebhookState::new(
        program,
        vec![0u8; 32],
        Vec::new(),
        ReviewConfig::default(),
    ))
}

/// Handshake once and report the leaf the server presented.
fn served_certificate(addr: SocketAddr) -> Vec<u8> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(&rustls::Certificate(fixture_der("ca.crt")))
        .expect("test CA");
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::ServerName::try_from(SERVICE_NAME).expect("server name");
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name).expect("client");
    let mut sock = TcpStream::connect(addr).expect("connect");
    {
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write_all(b"POST /validate HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
            .expect("handshake and request");
        tls.flush().expect("flush");
        let mut sink = Vec::new();
        // The server answers with Connection: close and no close_notify.
        let _ = tls.read_to_end(&mut sink);
    }
    conn.peer_certificates()
        .expect("peer certificates")
        .first()
        .expect("leaf")
        .0
        .clone()
}

#[test]
fn an_expired_certificate_refuses_to_start() {
    let dir = temp_dir("expired");
    install(&dir, "expired");
    let err = match TlsSource::load(
        dir.join("tls.crt").to_str().unwrap(),
        dir.join("tls.key").to_str().unwrap(),
    ) {
        Ok(_) => panic!("expired material must not start the server"),
        Err(err) => err,
    };
    assert!(err.contains("expired"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_far_off_expiry_does_not_warn() {
    let dir = temp_dir("nowarn");
    install(&dir, "serving");
    let source = source(&dir);
    assert_eq!(source.expiry_warnings(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

/// The swap is driven by `reload`, not by racing the poller: what this asserts
/// is that a completed reload reaches the *next* handshake, and a wall-clock
/// deadline around a background thread proves that no better than one
/// connection opened after the reload returned. The poller's own job — noticing
/// the mount changed at all — is the test below.
#[test]
fn rotation_reaches_new_connections() {
    let dir = temp_dir("rotate");
    install(&dir, "serving");
    let source = source(&dir);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let served = Arc::clone(&source);
    std::thread::spawn(move || serve_listener(listener, state(), Some(served)));

    assert_eq!(
        served_certificate(addr),
        fixture_der("serving.crt"),
        "the server must present the mounted certificate"
    );

    install(&dir, "rotated");
    source.reload().expect("same CA, four SANs, not expired");
    assert_eq!(
        served_certificate(addr),
        fixture_der("rotated.crt"),
        "rotated material never reached a new connection"
    );
    assert_eq!(source.reload_failures(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

/// The poller is what notices a kubelet-rotated mount when nobody calls
/// `reload`. The rotation is written *before* the thread starts, so the loop
/// below waits on one thing only — that the thread ran — and never reads a
/// half-installed pair, which is a reload failure, not a rotation.
#[test]
fn the_poller_picks_up_a_rotated_mount() {
    let dir = temp_dir("poll");
    install(&dir, "serving");
    let source = source(&dir);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let served = Arc::clone(&source);
    std::thread::spawn(move || serve_listener(listener, state(), Some(served)));
    // Two leaves of one CA with the same names and the same window have equal
    // `facts`, so the swap is observed on the served config itself.
    let mounted = source.config();

    install(&dir, "rotated");
    poll_serving_cert(Arc::clone(&source), Duration::from_millis(10));

    let deadline = Instant::now() + Duration::from_secs(30);
    while Arc::ptr_eq(&mounted, &source.config()) {
        assert!(
            Instant::now() < deadline,
            "the poller never picked up the rotated mount"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        served_certificate(addr),
        fixture_der("rotated.crt"),
        "what the poller loaded must be what the next handshake gets"
    );
    assert_eq!(source.reload_failures(), 0);
    std::fs::remove_dir_all(&dir).ok();
}

/// A swap is not final: with `failurePolicy: Fail` there is no fetching the old
/// Secret back from the cluster, so the material it replaced stays in memory.
#[test]
fn a_swap_can_be_undone() {
    let dir = temp_dir("rollback");
    install(&dir, "serving");
    let source = source(&dir);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let served = Arc::clone(&source);
    std::thread::spawn(move || serve_listener(listener, state(), Some(served)));
    let first = source.facts();

    source
        .roll_back()
        .expect_err("nothing has been swapped yet");

    install(&dir, "rotated");
    source.reload().expect("same CA, four SANs, not expired");
    assert_eq!(served_certificate(addr), fixture_der("rotated.crt"));

    source.roll_back().expect("the replaced material is usable");
    assert_eq!(source.rollbacks(), 1);
    assert_eq!(source.facts(), first);
    assert_eq!(
        served_certificate(addr),
        fixture_der("serving.crt"),
        "new connections must get the material the rollback restored"
    );
    source
        .roll_back()
        .expect_err("there is only ever one step back");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn unusable_material_keeps_the_current_certificate() {
    let dir = temp_dir("broken");
    install(&dir, "serving");
    let source = source(&dir);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let served = Arc::clone(&source);
    std::thread::spawn(move || serve_listener(listener, state(), Some(served)));
    let good = source.facts();

    std::fs::write(dir.join("tls.crt"), b"-----BEGIN CERTIFICATE-----\nnope\n").unwrap();
    let err = source
        .reload()
        .expect_err("garbage must not replace the certificate");
    assert!(err.contains("tls cert"), "{err}");

    install(&dir, "narrow");
    let err = source
        .reload()
        .expect_err("material that drops a Service name must not replace the certificate");
    assert!(err.contains("drops names"), "{err}");

    install(&dir, "expired");
    let err = source
        .reload()
        .expect_err("expired material must not replace the certificate");
    assert!(err.contains("expired"), "{err}");

    // Parses, four SANs, valid for decades — and signed by a CA the applied
    // caBundle does not name, so the API server would reject every handshake.
    install(&dir, "foreign");
    let err = source
        .reload()
        .expect_err("material from another CA must not replace the certificate");
    assert!(err.contains("issued by"), "{err}");

    assert_eq!(source.reload_failures(), 4);
    assert_eq!(source.facts(), good, "the last-known-good facts must stand");
    assert_eq!(
        served_certificate(addr),
        fixture_der("serving.crt"),
        "new connections must still get the last-known-good certificate"
    );
    std::fs::remove_dir_all(&dir).ok();
}
