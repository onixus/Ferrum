//! Bounded hand-off between the decision path and a blocking sink.
//!
//! The decision path must never wait on a disk write: `emit` does a
//! `try_send` on a bounded channel and, when the queue is full, counts the
//! event as an export drop and returns. Enforcement itself is unaffected —
//! only telemetry is lost, and the loss is visible in
//! `export_queue_dropped_total`.
//!
//! A full queue and a dead writer are different failures and are counted
//! separately: the first is a burst, the second means export is over until
//! the process restarts.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use ferrum_proto::EnforcementEvent;

use crate::EventSink;

/// How long the writer waits for the next event before re-checking the
/// shutdown flag. Only the SIGTERM path pays it.
const WORKER_TICK: Duration = Duration::from_millis(50);

pub struct QueueSink<S: EventSink + Send + Sync + 'static> {
    tx: SyncSender<EnforcementEvent>,
    worker: Mutex<Option<JoinHandle<()>>>,
    stopping: Arc<AtomicBool>,
    inner: Arc<S>,
    queue_dropped: AtomicU64,
    writer_lost: AtomicU64,
    writer_dead: AtomicBool,
}

impl<S: EventSink + Send + Sync + 'static> QueueSink<S> {
    /// Wrap `sink` in a writer thread fed by a queue of `cap` events.
    pub fn new(sink: S, cap: usize) -> Self {
        let inner = Arc::new(sink);
        let (tx, rx) = sync_channel::<EnforcementEvent>(cap.max(1));
        let worker_sink = Arc::clone(&inner);
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stopping);
        let worker = std::thread::spawn(move || loop {
            match rx.recv_timeout(WORKER_TICK) {
                Ok(event) => worker_sink.emit(&event),
                Err(RecvTimeoutError::Disconnected) => return,
                Err(RecvTimeoutError::Timeout) => {
                    if worker_stop.load(Ordering::Relaxed) {
                        // Drain what was already accepted, then stop: those
                        // events are enforcement history, not scratch data.
                        while let Ok(event) = rx.try_recv() {
                            worker_sink.emit(&event);
                        }
                        return;
                    }
                }
            }
        });
        Self {
            tx,
            worker: Mutex::new(Some(worker)),
            stopping,
            inner,
            queue_dropped: AtomicU64::new(0),
            writer_lost: AtomicU64::new(0),
            writer_dead: AtomicBool::new(false),
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Stop the writer and wait for it to flush what it accepted. Callable
    /// through an `Arc` (the SIGTERM path) and idempotent.
    pub fn close(&self) {
        self.stopping.store(true, Ordering::Relaxed);
        let handle = self.worker.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }

    /// Close the queue and wait for the writer to flush what it accepted.
    /// Explicit, so a caller (and a test) can be sure the file is complete.
    /// Returns the wrapped sink, still usable for counters.
    pub fn shutdown(self) -> Arc<S> {
        self.close();
        Arc::clone(&self.inner)
    }
}

impl<S: EventSink + Send + Sync + 'static> EventSink for QueueSink<S> {
    fn emit(&self, event: &EnforcementEvent) {
        match self.tx.try_send(event.clone()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.queue_dropped.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                // The writer thread is gone (panic, or after close): nothing
                // will ever be exported again, which is not a burst.
                self.writer_lost.fetch_add(1, Ordering::Relaxed);
                self.writer_dead.store(true, Ordering::Relaxed);
            }
        }
    }

    fn events_dropped_total(&self) -> u64 {
        self.inner.events_dropped_total()
    }

    fn export_queue_dropped_total(&self) -> u64 {
        self.queue_dropped.load(Ordering::Relaxed)
    }

    fn export_writer_lost_total(&self) -> u64 {
        self.writer_lost.load(Ordering::Relaxed)
    }

    fn export_writer_dead(&self) -> bool {
        self.writer_dead.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemorySink, RotatingFileSink, SinkContext};
    use ferrum_ids::{PolicyId, RuleId};
    use std::time::Instant;

    fn sample(n: u32) -> EnforcementEvent {
        EnforcementEvent {
            policy: PolicyId::new("p"),
            rule: RuleId::new("no-shell"),
            action: "kill".into(),
            image_digest: None,
            pod: "web".into(),
            namespace: "prod".into(),
            comm: "sh".into(),
            syscall: "execve".into(),
            pid: n,
            tgid: n,
            executed: false,
            respond_error: None,
            waiver: None,
        }
    }

    /// Sink that takes its time, so the queue behind it fills up.
    struct SlowSink {
        inner: RotatingFileSink,
        delay: Duration,
    }

    impl EventSink for SlowSink {
        fn emit(&self, event: &EnforcementEvent) {
            std::thread::sleep(self.delay);
            self.inner.emit(event);
        }

        fn events_dropped_total(&self) -> u64 {
            self.inner.events_dropped_total()
        }
    }

    /// Writer that dies on the first event, the way a panicking sink would.
    struct PanicSink;

    impl EventSink for PanicSink {
        fn emit(&self, _event: &EnforcementEvent) {
            panic!("writer thread is gone");
        }
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrum-export-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        dir
    }

    #[test]
    fn full_queue_drops_instead_of_blocking_and_flushes_the_rest() {
        let dir = temp_dir("queue");
        let sink = QueueSink::new(
            SlowSink {
                inner: RotatingFileSink::new(
                    dir.clone(),
                    64 * 1024 * 1024,
                    2,
                    SinkContext::new("node-a", "respond"),
                ),
                delay: Duration::from_millis(20),
            },
            4,
        );
        let sent: u32 = 200;
        let start = Instant::now();
        for i in 0..sent {
            sink.emit(&sample(i));
        }
        let elapsed = start.elapsed();
        // Blocking would need sent * delay = 4s; the queue must not hold the
        // decision path hostage for anything close to that.
        assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
        let dropped = sink.export_queue_dropped_total();
        assert!(dropped > 0, "queue never filled");
        // A full queue is a burst, not a dead writer.
        assert_eq!(sink.export_writer_lost_total(), 0);
        assert!(!sink.export_writer_dead());

        let inner = sink.shutdown();
        assert_eq!(inner.events_dropped_total(), 0);
        let written = std::fs::read_to_string(dir.join("events.jsonl")).expect("events.jsonl");
        let lines = written.lines().filter(|l| !l.is_empty()).count();
        assert_eq!(lines as u64, sent as u64 - dropped);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_queue_loses_nothing() {
        let dir = temp_dir("queue-small");
        let sink = QueueSink::new(
            RotatingFileSink::new(
                dir.clone(),
                64 * 1024 * 1024,
                2,
                SinkContext::new("node-a", "observe"),
            ),
            256,
        );
        for i in 0..64 {
            sink.emit(&sample(i));
        }
        assert_eq!(sink.export_queue_dropped_total(), 0);
        sink.shutdown();
        let written = std::fs::read_to_string(dir.join("events.jsonl")).expect("events.jsonl");
        assert_eq!(written.lines().filter(|l| !l.is_empty()).count(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A dead writer means export is over; a full queue does not. Counting the
    /// two together hides the permanent failure behind the transient one.
    #[test]
    fn a_dead_writer_is_counted_apart_from_a_full_queue() {
        let sink = QueueSink::new(PanicSink, 1);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !sink.export_writer_dead() && Instant::now() < deadline {
            sink.emit(&sample(1));
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(sink.export_writer_dead(), "writer death never surfaced");
        assert!(sink.export_writer_lost_total() > 0);
        // Everything after the death is a lost writer, never a full queue.
        let dropped = sink.export_queue_dropped_total();
        let lost = sink.export_writer_lost_total();
        for i in 0..8 {
            sink.emit(&sample(i));
        }
        assert_eq!(sink.export_queue_dropped_total(), dropped);
        assert_eq!(sink.export_writer_lost_total(), lost + 8);
    }

    /// SIGTERM path: `close` through a shared handle flushes what was accepted.
    #[test]
    fn close_through_an_arc_flushes_accepted_events() {
        let sink = Arc::new(QueueSink::new(MemorySink::new(), 1024));
        for i in 0..128 {
            sink.emit(&sample(i));
        }
        let handle = Arc::clone(&sink);
        handle.close();
        assert_eq!(sink.inner().events().len(), 128);
        // Idempotent: a second close (shutdown at exit) must not hang.
        sink.close();
    }
}
