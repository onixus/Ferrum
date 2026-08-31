//! The socket, and what happens when there is nothing on the other end.
//!
//! This is the file the boundary rule is about. `ferrum-export` may not do a
//! blocking write on the hot path and may not lose a record silently, and a
//! network destination is where both are easiest to get wrong: a TCP write to
//! a SIEM that stopped acknowledging blocks for as long as the kernel's send
//! buffer and retransmit timers say, which is minutes, and the usual repair —
//! buffer it and retry — turns a bounded process into an unbounded one.
//!
//! What is done instead, in three parts:
//!
//! 1. **The decision path never reaches this file.** The agent puts
//!    [`SyslogSink`] behind `ferrum_export::QueueSink`, whose `emit` is a
//!    `try_send` on a bounded channel. Everything below runs on the export
//!    writer thread. A SIEM that answers slowly costs queue depth, and a full
//!    queue is counted in `export_queue_dropped_total` — the counter that
//!    already exists, already reaches `/metrics`, and already raises
//!    `DEG_EXPORT_LOSSY`.
//!
//! 2. **Even on that thread, nothing waits long.** `connect_timeout` and
//!    `set_write_timeout` bound every syscall this file makes. After a
//!    failure the destination is not touched again until [`BACKOFF`] has
//!    passed — so a SIEM that is down for an hour costs one connect attempt
//!    per backoff window and nothing per event, and the file sink beside it
//!    keeps writing at full speed.
//!
//! 3. **Every event that did not go out is counted.** As
//!    `export_write_failed_total`, which is the existing counter for "the sink
//!    accepted this and could not write it out", not a second one invented for
//!    this destination. It reaches the operator through the same three routes
//!    everything else does: `status.json`, `ferrum_agent_export_write_failed_total`
//!    on `/metrics`, and `DEG_EXPORT_LOSSY` on the node's degraded state.
//!
//! What that costs, said out loud rather than left to be discovered: the three
//! export counters are a sum over the sinks the agent fans out to, so a node
//! whose SIEM is down and whose disk is fine reports export loss and is
//! Degraded, and the counter alone does not say which destination failed. That
//! is the correct alarm — an enforcement event that did not reach the system
//! the SOC watches *is* lost, whatever else it also reached — and the wrong
//! resolution: a second per-destination counter would answer it, and this
//! cycle deliberately does not add one, because the counter this product
//! already publishes and nobody reads is the defect the previous cycle was
//! about. The line that names the destination is on stderr, once per
//! transition, and in `stderr` of the Pod.
//!
//! One cost that is not mitigated: `to_socket_addrs` resolves DNS, and std
//! gives no timeout for it. A resolver that hangs stalls the export writer
//! thread — not the decision path — for as long as the system resolver takes,
//! once per backoff window, and delays SIGTERM by the same. Use an IP address
//! in `--siem-address` where that matters; the manifests say so.

use std::io::Write;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ferrum_export::EventSink;
use ferrum_proto::{EnforcementEvent, EventEnvelope};

use crate::Profile;

/// How long a connect or a write may take before the event is counted lost.
///
/// Two seconds and not thirty: this runs on the thread that also writes
/// `events.jsonl`, and every second spent here is a second the bounded queue
/// in front of it is filling. A SIEM that cannot answer in two seconds is one
/// whose records this node would have dropped anyway, later and with more
/// events behind them.
pub const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Quiet period after a failure. Nothing is sent and nothing is attempted
/// until it passes; every event that arrives meanwhile is counted immediately
/// and costs no syscall at all.
pub const BACKOFF: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    /// One datagram per record. Lossy by design and it is the receiver's
    /// loss to see; what this end guarantees is that a record is one datagram,
    /// so a truncated one is a dropped one and never half of two.
    Udp,
    /// LF-framed stream. Reconnects after a failure, at most once per
    /// [`BACKOFF`].
    Tcp,
}

impl Transport {
    pub fn parse_name(text: &str) -> Result<Transport, String> {
        match text {
            "udp" => Ok(Transport::Udp),
            "tcp" => Ok(Transport::Tcp),
            other => Err(format!(
                "unknown --siem-transport {other:?}; known: udp, tcp"
            )),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
        }
    }
}

pub struct SinkConfig {
    /// `host:port`, as typed. Resolved lazily so a name that does not resolve
    /// at startup is a counted export failure rather than a node that refuses
    /// to enforce.
    pub address: String,
    pub transport: Transport,
    pub profile: Profile,
}

/// A syslog destination that never blocks the process for long and never
/// loses a record without counting it.
pub struct SyslogSink {
    config: SinkConfig,
    conn: Mutex<Conn>,
    failed: AtomicU64,
    /// Whether the destination was reachable on the last attempt, so the
    /// stderr line is printed on transitions and not once per event.
    up: AtomicBool,
}

enum Conn {
    /// Nothing open, and nothing may be attempted before this instant.
    Idle {
        retry_after: Option<Instant>,
    },
    Udp {
        socket: UdpSocket,
        peer: SocketAddr,
    },
    Tcp {
        stream: TcpStream,
    },
}

impl SyslogSink {
    /// Build the sink. Deliberately infallible and deliberately does no I/O:
    /// a SIEM that is down when the DaemonSet rolls must not be able to stop a
    /// node from enforcing, and a constructor that returned an error here
    /// would make the operator choose between the two.
    pub fn new(config: SinkConfig) -> SyslogSink {
        SyslogSink {
            config,
            conn: Mutex::new(Conn::Idle { retry_after: None }),
            failed: AtomicU64::new(0),
            up: AtomicBool::new(true),
        }
    }

    pub fn address(&self) -> &str {
        &self.config.address
    }

    pub fn profile(&self) -> Profile {
        self.config.profile
    }

    pub fn transport(&self) -> Transport {
        self.config.transport
    }

    /// True while the destination answered the last attempt.
    pub fn reachable(&self) -> bool {
        self.up.load(Ordering::Relaxed)
    }

    fn resolve(&self) -> std::io::Result<SocketAddr> {
        self.config
            .address
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| {
                std::io::Error::other(format!("{} resolved to no address", self.config.address))
            })
    }

    fn open(&self) -> std::io::Result<Conn> {
        let peer = self.resolve()?;
        match self.config.transport {
            Transport::Udp => {
                let bind = if peer.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let socket = UdpSocket::bind(bind)?;
                socket.set_write_timeout(Some(IO_TIMEOUT))?;
                Ok(Conn::Udp { socket, peer })
            }
            Transport::Tcp => {
                let stream = TcpStream::connect_timeout(&peer, IO_TIMEOUT)?;
                stream.set_write_timeout(Some(IO_TIMEOUT))?;
                // Records are small and latency to a SIEM is the whole point;
                // Nagle would hold a record back waiting for a second one.
                stream.set_nodelay(true)?;
                Ok(Conn::Tcp { stream })
            }
        }
    }

    fn send(&self, line: &[u8]) -> std::io::Result<()> {
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        if let Conn::Idle { retry_after } = &*guard {
            if let Some(at) = retry_after {
                if Instant::now() < *at {
                    return Err(std::io::Error::other(
                        "destination is in its backoff window",
                    ));
                }
            }
            *guard = self.open()?;
        }
        let result = match &mut *guard {
            Conn::Udp { socket, peer } => socket.send_to(line, *peer).map(|_| ()),
            Conn::Tcp { stream } => stream.write_all(line).and_then(|_| stream.flush()),
            Conn::Idle { .. } => unreachable!("opened above"),
        };
        if result.is_err() {
            // Drop the connection rather than reusing one whose write failed:
            // on TCP the stream's position in the record stream is unknown
            // from here, and a reused one would glue half a record to the next.
            *guard = Conn::Idle {
                retry_after: Some(Instant::now() + BACKOFF),
            };
        }
        result
    }

    /// Note the transition and say it once. Enforcement does not depend on the
    /// SIEM, so this is never fatal; what it must not be is silent.
    fn note(&self, outcome: Result<(), std::io::Error>) {
        match outcome {
            Ok(()) => {
                if !self.up.swap(true, Ordering::Relaxed) {
                    eprintln!(
                        "ferrum-siem: {} is answering again ({}, {})",
                        self.config.address,
                        self.config.transport.name(),
                        self.config.profile.name()
                    );
                }
            }
            Err(err) => {
                self.failed.fetch_add(1, Ordering::Relaxed);
                if self.up.swap(false, Ordering::Relaxed) {
                    eprintln!(
                        "ferrum-siem: {} unreachable, events are being counted as export \
                         write failures: {err}",
                        self.config.address
                    );
                }
            }
        }
    }
}

impl EventSink for SyslogSink {
    /// Only reached from the export writer thread; see the module docs.
    fn emit(&self, _event: &EnforcementEvent) {
        // A bare `EnforcementEvent` has no node, no bundle digest and no
        // timestamp, and a SIEM record without those is not a record. The
        // agent always emits through the envelope path below; this arm exists
        // because the trait has one method and it must not silently do
        // nothing.
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    fn emit_envelope(&self, envelope: &EventEnvelope) {
        let mut line = self.config.profile.render(envelope).into_bytes();
        line.push(b'\n');
        let outcome = self.send(&line);
        self.note(outcome);
    }

    fn export_write_failed_total(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::envelope;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;

    #[test]
    fn a_tcp_receiver_gets_one_line_per_event_in_the_configured_profile() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let reader = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut lines = Vec::new();
            for line in BufReader::new(stream).lines() {
                match line {
                    Ok(line) => lines.push(line),
                    Err(_) => break,
                }
                if lines.len() == 3 {
                    break;
                }
            }
            lines
        });

        let sink = SyslogSink::new(SinkConfig {
            address: addr.to_string(),
            transport: Transport::Tcp,
            profile: Profile::Rfc5424,
        });
        for _ in 0..3 {
            sink.emit_envelope(&envelope());
        }
        let lines = reader.join().expect("reader thread");
        assert_eq!(lines.len(), 3, "{lines:?}");
        for line in &lines {
            assert!(line.starts_with("<131>1 "), "{line}");
            assert!(line.contains("[ferrum@32473 "), "{line}");
        }
        assert_eq!(
            sink.export_write_failed_total(),
            0,
            "a delivered event was counted as lost"
        );
        assert!(sink.reachable());
    }

    #[test]
    fn a_udp_receiver_gets_one_datagram_per_event() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let addr = socket.local_addr().expect("addr");
        let sink = SyslogSink::new(SinkConfig {
            address: addr.to_string(),
            transport: Transport::Udp,
            profile: Profile::Cef,
        });
        sink.emit_envelope(&envelope());
        let mut buf = [0u8; 4096];
        let (n, _) = socket.recv_from(&mut buf).expect("one datagram");
        let text = std::str::from_utf8(&buf[..n]).expect("utf8");
        assert!(text.contains("CEF:0|Ferrum|ferrum|"), "{text}");
        assert!(text.ends_with('\n'));
        assert_eq!(sink.export_write_failed_total(), 0);
    }

    /// The property the whole file exists for: a destination that is not there
    /// costs bounded time and counts every event it did not deliver.
    #[test]
    fn an_unreachable_destination_counts_every_event_and_does_not_hang() {
        // A port nothing listens on: bound, then dropped, so the address is
        // valid and the connect is refused rather than filtered.
        let addr = {
            let probe = TcpListener::bind("127.0.0.1:0").expect("bind");
            probe.local_addr().expect("addr")
        };
        let sink = SyslogSink::new(SinkConfig {
            address: addr.to_string(),
            transport: Transport::Tcp,
            profile: Profile::Ecs,
        });
        let start = Instant::now();
        for _ in 0..200 {
            sink.emit_envelope(&envelope());
        }
        let elapsed = start.elapsed();
        assert_eq!(
            sink.export_write_failed_total(),
            200,
            "an event that never reached the SIEM was not counted: that is the silent loss the \
             boundary forbids"
        );
        assert!(!sink.reachable());
        // 200 events against a dead destination must cost one connect attempt,
        // not 200: the backoff window is longer than this loop takes.
        assert!(
            elapsed < BACKOFF,
            "{elapsed:?} for 200 events against a refused port: the backoff is not holding and \
             the export writer is being made to wait per event"
        );
    }

    /// A name that does not resolve is the same failure as a refused port and
    /// must not be a different one: no panic, no exit, counted.
    #[test]
    fn an_unresolvable_address_is_a_counted_failure_and_not_a_crash() {
        let sink = SyslogSink::new(SinkConfig {
            address: "siem.invalid.:514".into(),
            transport: Transport::Udp,
            profile: Profile::Rfc5424,
        });
        sink.emit_envelope(&envelope());
        assert_eq!(sink.export_write_failed_total(), 1);
    }

    /// A receiver that goes away mid-stream: the sink must not keep writing
    /// into a dead stream and must not stop counting.
    #[test]
    fn a_receiver_that_disappears_is_noticed_and_the_loss_is_counted() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accepted = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            // Read one record, then close both directions.
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            let _ = stream.shutdown(std::net::Shutdown::Both);
            line
        });
        let sink = SyslogSink::new(SinkConfig {
            address: addr.to_string(),
            transport: Transport::Tcp,
            profile: Profile::Cef,
        });
        sink.emit_envelope(&envelope());
        let first = accepted.join().expect("reader");
        assert!(first.contains("CEF:0|"), "{first}");

        // Writes into the closed stream fail, once the peer's RST arrives.
        // Everything after that is counted, and none of it costs a connect:
        // the failure puts the destination into its backoff window.
        let deadline = Instant::now() + Duration::from_secs(5);
        while sink.export_write_failed_total() == 0 && Instant::now() < deadline {
            sink.emit_envelope(&envelope());
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            sink.export_write_failed_total() > 0,
            "the receiver closed the connection and every subsequent event was reported as \
             delivered"
        );
        assert!(!sink.reachable());
    }
}
