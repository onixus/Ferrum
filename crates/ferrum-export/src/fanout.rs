//! One event, several destinations, one record.
//!
//! Not a new capability of this crate and deliberately not one: there is no
//! socket here, no format and no dependency. It is the combinator over the
//! trait this crate owns, and it exists to make one thing true that separate
//! sinks cannot make true on their own — the envelope is stamped **once** and
//! every destination gets the same bytes. Two sinks each calling
//! `SinkContext::envelope` would give one enforcement decision two timestamps,
//! and an investigation correlating a SIEM alert against `events.jsonl` would
//! be joining on a field that does not join.
//!
//! Where it sits matters as much as what it does: the agent puts it *inside*
//! `QueueSink`, so the decision path still does one `try_send` and the fan-out
//! happens on the export writer thread. A slow destination costs queue depth
//! and is counted in `export_queue_dropped_total`; it does not cost the
//! datapath.
//!
//! Counters are summed across destinations. That is honest — an enforcement
//! event that failed to reach one of the two systems that were supposed to
//! hold it *is* a lost record, whatever else it also reached — and it is
//! lossy in one direction, which is written down rather than discovered: the
//! sum does not say which destination failed. Each destination says so itself,
//! once per transition, on stderr. A second per-destination counter was
//! refused on purpose: this tree has already paid for twenty-two counters
//! nobody read, and the fix for that was not a twenty-third.

use ferrum_proto::{EnforcementEvent, EventEnvelope};

use crate::{EventSink, SinkContext};

pub struct FanoutSink {
    ctx: SinkContext,
    sinks: Vec<Box<dyn EventSink + Send + Sync>>,
}

impl FanoutSink {
    /// `ctx` is the one that stamps; the destinations receive what it stamped.
    pub fn new(ctx: SinkContext, sinks: Vec<Box<dyn EventSink + Send + Sync>>) -> FanoutSink {
        FanoutSink { ctx, sinks }
    }

    pub fn context(&self) -> &SinkContext {
        &self.ctx
    }

    pub fn destinations(&self) -> usize {
        self.sinks.len()
    }

    fn sum(&self, read: impl Fn(&(dyn EventSink + Send + Sync)) -> u64) -> u64 {
        self.sinks
            .iter()
            .map(|sink| read(sink.as_ref()))
            .fold(0u64, u64::saturating_add)
    }
}

impl EventSink for FanoutSink {
    fn emit(&self, event: &EnforcementEvent) {
        self.emit_envelope(&self.ctx.envelope(event))
    }

    fn emit_envelope(&self, envelope: &EventEnvelope) {
        for sink in &self.sinks {
            sink.emit_envelope(envelope);
        }
    }

    fn export_write_failed_total(&self) -> u64 {
        self.sum(|sink| sink.export_write_failed_total())
    }

    fn export_queue_dropped_total(&self) -> u64 {
        self.sum(|sink| sink.export_queue_dropped_total())
    }

    fn export_writer_lost_total(&self) -> u64 {
        self.sum(|sink| sink.export_writer_lost_total())
    }

    /// Any destination being dead is the agent being unable to record what it
    /// enforced. `any`, not `all`: a node that still writes its local file
    /// while the SIEM the SOC watches gets nothing is not a healthy node.
    fn export_writer_dead(&self) -> bool {
        self.sinks.iter().any(|sink| sink.export_writer_dead())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemorySink;
    use ferrum_ids::{PolicyId, RuleId};
    use std::sync::atomic::{AtomicU64, Ordering};

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
            pid: 1,
            tgid: 1,
            executed: false,
            labels_unknown: false,
            path_unknown: false,
            container_unknown: false,
            respond_error: None,
            waiver: None,
        }
    }

    /// Records the envelope it was handed, so the test can compare what two
    /// destinations received rather than what each of them built.
    #[derive(Default)]
    struct RecordingSink {
        seen: std::sync::Mutex<Vec<EventEnvelope>>,
        failed: AtomicU64,
    }

    impl EventSink for RecordingSink {
        fn emit(&self, _event: &EnforcementEvent) {
            unreachable!("the fanout always stamps first")
        }

        fn emit_envelope(&self, envelope: &EventEnvelope) {
            self.seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(envelope.clone());
        }

        fn export_write_failed_total(&self) -> u64 {
            self.failed.load(Ordering::Relaxed)
        }
    }

    /// The reason this type exists: one decision is one record everywhere.
    #[test]
    fn every_destination_receives_the_same_stamped_envelope() {
        let ctx = SinkContext::new("node-a", "respond");
        let first = std::sync::Arc::new(RecordingSink::default());
        let second = std::sync::Arc::new(RecordingSink::default());
        let fanout = FanoutSink::new(
            ctx,
            vec![
                Box::new(std::sync::Arc::clone(&first)),
                Box::new(std::sync::Arc::clone(&second)),
            ],
        );
        fanout.emit(&sample());
        let a = first.seen.lock().unwrap().clone();
        let b = second.seen.lock().unwrap().clone();
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_eq!(
            a[0].ts, b[0].ts,
            "two destinations were given two timestamps for one enforcement decision"
        );
        assert_eq!(a[0].node, b[0].node);
    }

    /// A destination that loses records makes the node lossy, even when the
    /// other one is fine.
    #[test]
    fn a_loss_at_one_destination_is_a_loss_for_the_node() {
        let ctx = SinkContext::new("node-a", "observe");
        let lossy = std::sync::Arc::new(RecordingSink::default());
        lossy.failed.store(7, Ordering::Relaxed);
        let fanout = FanoutSink::new(
            ctx,
            vec![
                Box::new(MemorySink::new()),
                Box::new(std::sync::Arc::clone(&lossy)),
            ],
        );
        fanout.emit(&sample());
        assert_eq!(
            fanout.export_write_failed_total(),
            7,
            "the healthy destination hid the failing one"
        );
    }
}
