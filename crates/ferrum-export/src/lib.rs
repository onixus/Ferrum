//! Off-cluster enforcement events. Not a CRD; not written to etcd.

#![deny(unsafe_code)]

mod file;
mod queue;

pub use file::{EnvelopeWriterSink, RotatingFileSink, SinkContext};
pub use queue::QueueSink;

use ferrum_proto::EnforcementEvent;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub trait EventSink {
    fn emit(&self, event: &EnforcementEvent);

    fn events_dropped_total(&self) -> u64 {
        0
    }

    /// Events lost because the export queue was full. Distinct from
    /// `events_dropped_total` (a failed write) and from the in-kernel ring
    /// counter: this one means the export path could not keep up.
    fn export_queue_dropped_total(&self) -> u64 {
        0
    }
}

/// Lets a caller pick a sink at runtime (file vs stdout) and still hand one
/// concrete type to `QueueSink`.
impl EventSink for Box<dyn EventSink + Send + Sync> {
    fn emit(&self, event: &EnforcementEvent) {
        (**self).emit(event)
    }

    fn events_dropped_total(&self) -> u64 {
        (**self).events_dropped_total()
    }

    fn export_queue_dropped_total(&self) -> u64 {
        (**self).export_queue_dropped_total()
    }
}

pub struct WriterSink<W> {
    writer: Mutex<W>,
    dropped: AtomicU64,
}

impl<W> WriterSink<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
            dropped: AtomicU64::new(0),
        }
    }

    fn lock_writer(&self) -> std::sync::MutexGuard<'_, W> {
        self.writer.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<W: Write> EventSink for WriterSink<W> {
    fn emit(&self, event: &EnforcementEvent) {
        let payload = match serde_json::to_vec(event) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let mut w = self.lock_writer();
        let wrote = w.write_all(&payload).and_then(|_| w.write_all(b"\n"));
        if wrote.is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn events_dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

pub type StdoutSink = WriterSink<io::Stdout>;

impl StdoutSink {
    pub fn stdout() -> Self {
        Self::new(io::stdout())
    }
}

pub struct MemorySink {
    events: Mutex<Vec<EnforcementEvent>>,
    dropped: AtomicU64,
}

impl Default for MemorySink {
    fn default() -> Self {
        Self::new()
    }
}

impl MemorySink {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn events(&self) -> Vec<EnforcementEvent> {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn record_drop(&self, n: u64) {
        self.dropped.fetch_add(n, Ordering::Relaxed);
    }
}

impl EventSink for MemorySink {
    fn emit(&self, event: &EnforcementEvent) {
        self.events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(event.clone());
    }

    fn events_dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_ids::{PolicyId, RuleId};

    fn sample() -> EnforcementEvent {
        EnforcementEvent {
            policy: PolicyId::new("p"),
            rule: RuleId::new("no-shell"),
            action: "kill".into(),
            image_digest: None,
            pod: "web".into(),
            namespace: "prod".into(),
            comm: "sh".into(),
            syscall: "execve".into(),
            pid: 0,
            tgid: 0,
            executed: false,
            respond_error: None,
            waiver: None,
        }
    }

    #[test]
    fn memory_sink_keeps_events() {
        let sink = MemorySink::new();
        sink.emit(&sample());
        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].rule.to_string(), "no-shell");
        assert_eq!(events[0].action, "kill");
        assert_eq!(sink.events_dropped_total(), 0);
    }

    #[test]
    fn writer_sink_json_line() {
        let sink = WriterSink::new(Vec::new());
        sink.emit(&sample());
        let bytes = sink.lock_writer().clone();
        let line = std::str::from_utf8(&bytes).expect("utf8");
        assert!(line.contains("\"rule\":\"no-shell\""));
        assert!(line.contains("\"action\":\"kill\""));
        assert!(line.ends_with('\n'));
        assert_eq!(sink.events_dropped_total(), 0);
    }

    #[test]
    fn drops_are_counted() {
        let sink = MemorySink::new();
        sink.record_drop(4);
        assert_eq!(sink.events_dropped_total(), 4);
    }
}
