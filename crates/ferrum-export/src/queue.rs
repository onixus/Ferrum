//! Bounded hand-off between the decision path and a blocking sink.
//!
//! The decision path must never wait on a disk write: `emit` does a
//! `try_send` on a bounded channel and, when the queue is full, counts the
//! event as an export drop and returns. Enforcement itself is unaffected —
//! only telemetry is lost, and the loss is visible in
//! `export_queue_dropped_total`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;

use ferrum_proto::EnforcementEvent;

use crate::EventSink;

pub struct QueueSink<S: EventSink + Send + Sync + 'static> {
    tx: SyncSender<EnforcementEvent>,
    worker: JoinHandle<()>,
    inner: Arc<S>,
    queue_dropped: Arc<AtomicU64>,
}

impl<S: EventSink + Send + Sync + 'static> QueueSink<S> {
    /// Wrap `sink` in a writer thread fed by a queue of `cap` events.
    pub fn new(sink: S, cap: usize) -> Self {
        let inner = Arc::new(sink);
        let (tx, rx) = sync_channel::<EnforcementEvent>(cap.max(1));
        let worker_sink = Arc::clone(&inner);
        let worker = std::thread::spawn(move || {
            for event in rx {
                worker_sink.emit(&event);
            }
        });
        Self {
            tx,
            worker,
            inner,
            queue_dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Close the queue and wait for the writer to flush what it accepted.
    /// Explicit, so a caller (and a test) can be sure the file is complete.
    /// Returns the wrapped sink, still usable for counters.
    pub fn shutdown(self) -> Arc<S> {
        let Self {
            tx, worker, inner, ..
        } = self;
        drop(tx);
        let _ = worker.join();
        inner
    }
}

impl<S: EventSink + Send + Sync + 'static> EventSink for QueueSink<S> {
    fn emit(&self, event: &EnforcementEvent) {
        match self.tx.try_send(event.clone()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.queue_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn events_dropped_total(&self) -> u64 {
        self.inner.events_dropped_total()
    }

    fn export_queue_dropped_total(&self) -> u64 {
        self.queue_dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RotatingFileSink, SinkContext};
    use ferrum_ids::{PolicyId, RuleId};
    use std::time::{Duration, Instant};

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
}
