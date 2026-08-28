//! Scheduling for the kernel ring-reader thread: when to sleep, and when to
//! read the in-kernel drop counter.
//!
//! The drop poll is on a wall-clock schedule, not on the idle path. Ring
//! drops happen precisely when the ring is full, i.e. when every `drain`
//! returns records and the reader never idles; a poll driven by accumulated
//! idle time would therefore never run in the one scenario the counter exists
//! for, and `events_dropped_total` would stay unread under flood.

use ferrum_common::Result;
use std::time::{Duration, Instant};

/// Backoff bounds for an empty ring. Latency between a kernel record and its
/// verdict is bounded by `IDLE_MAX`: there is no epoll on this path.
const IDLE_MIN: Duration = Duration::from_millis(1);
const IDLE_MAX: Duration = Duration::from_millis(10);

/// What one pass over the ring produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RingTick {
    /// Records handed to the drain callback this pass.
    pub records: usize,
    /// How long the caller should sleep before the next pass; `None` means
    /// the ring still had records, so come straight back.
    pub sleep: Option<Duration>,
    /// New in-kernel drops since the last poll. Zero when the poll was not
    /// due, when the counter did not move, or when reading it failed.
    pub drop_delta: u64,
    /// The drop counter was due and could not be read.
    pub drop_check_failed: bool,
}

/// Drain/poll scheduler for one ring reader.
#[derive(Debug)]
pub struct RingLoop {
    drop_interval: Duration,
    next_drop_check: Instant,
    idle: Duration,
    seen_drops: u64,
}

impl RingLoop {
    pub fn new(drop_interval: Duration, now: Instant) -> Self {
        Self {
            drop_interval,
            next_drop_check: now + drop_interval,
            idle: IDLE_MIN,
            seen_drops: 0,
        }
    }

    /// One pass: drain the ring, then poll the drop counter if the schedule
    /// says so. `dropped_total` is only called when the poll is due, and is
    /// called whatever `drain` returned.
    pub fn tick(
        &mut self,
        now: Instant,
        drain: impl FnOnce() -> usize,
        dropped_total: impl FnOnce() -> Result<u64>,
    ) -> RingTick {
        let records = drain();
        let sleep = if records == 0 {
            let sleep = self.idle;
            self.idle = (self.idle * 2).min(IDLE_MAX);
            Some(sleep)
        } else {
            self.idle = IDLE_MIN;
            None
        };
        let mut tick = RingTick {
            records,
            sleep,
            ..RingTick::default()
        };
        if now >= self.next_drop_check {
            // Anchored on `now`, not on the previous deadline: a late pass
            // must not queue a burst of immediately-due polls.
            self.next_drop_check = now + self.drop_interval;
            match dropped_total() {
                Ok(total) => {
                    tick.drop_delta = total.saturating_sub(self.seen_drops);
                    self.seen_drops = total;
                }
                Err(_) => tick.drop_check_failed = true,
            }
        }
        tick
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Agent, AgentConfig};
    use ferrum_common::FerrumError;
    use std::cell::Cell;

    /// The regression this module exists for: under an uninterrupted stream
    /// the reader never idles, and the drop counter must still be polled on
    /// schedule. A poll driven by idle time is silent exactly under flood.
    #[test]
    fn drops_are_polled_under_a_continuous_stream() {
        let agent = Agent::new(AgentConfig::default());
        let interval = Duration::from_millis(1000);
        let start = Instant::now();
        let mut ring = RingLoop::new(interval, start);
        let kernel_drops = Cell::new(0u64);
        let polls = Cell::new(0u32);

        let mut now = start;
        for step in 0..=3000u64 {
            now = start + Duration::from_millis(step);
            // Ring full: every pass returns records, so the loop never sleeps.
            let tick = ring.tick(
                now,
                || 64,
                || {
                    polls.set(polls.get() + 1);
                    kernel_drops.set(kernel_drops.get() + 7);
                    Ok(kernel_drops.get())
                },
            );
            assert_eq!(tick.records, 64);
            assert_eq!(tick.sleep, None, "a non-empty ring must not sleep");
            agent.record_drop_at(tick.drop_delta, now);
        }

        assert_eq!(polls.get(), 3, "one poll per interval");
        assert_eq!(agent.events_dropped_total(), 21);
        assert!(
            agent.is_degraded(),
            "ring drops under flood must surface as Degraded"
        );
        assert!(agent.ring_drops_recent_at(now));
    }

    #[test]
    fn an_idle_ring_backs_off_and_still_polls() {
        let interval = Duration::from_millis(50);
        let start = Instant::now();
        let mut ring = RingLoop::new(interval, start);
        let mut slept = Vec::new();
        let mut polls = 0u32;
        for step in 0..100u64 {
            let tick = ring.tick(
                start + Duration::from_millis(step),
                || 0,
                || {
                    polls += 1;
                    Ok(0)
                },
            );
            slept.push(tick.sleep.expect("empty ring sleeps"));
            assert_eq!(tick.drop_delta, 0);
        }
        assert_eq!(slept[0], IDLE_MIN);
        assert_eq!(*slept.last().expect("ticks"), IDLE_MAX);
        assert_eq!(polls, 1, "100ms of ticks covers one 50ms deadline");
    }

    /// A counter that only ever grows: the agent must see each increment once
    /// and must not re-report the same total.
    #[test]
    fn only_the_delta_is_reported() {
        let start = Instant::now();
        let interval = Duration::from_millis(10);
        let mut ring = RingLoop::new(interval, start);
        let first = ring.tick(start + interval, || 1, || Ok(5));
        assert_eq!(first.drop_delta, 5);
        let same = ring.tick(start + interval * 2, || 1, || Ok(5));
        assert_eq!(same.drop_delta, 0);
        let more = ring.tick(start + interval * 3, || 1, || Ok(9));
        assert_eq!(more.drop_delta, 4);
        // A counter reset (map replaced) must not underflow into a huge delta.
        let reset = ring.tick(start + interval * 4, || 1, || Ok(1));
        assert_eq!(reset.drop_delta, 0);
    }

    #[test]
    fn an_unreadable_counter_is_reported_not_counted() {
        let start = Instant::now();
        let interval = Duration::from_millis(10);
        let mut ring = RingLoop::new(interval, start);
        let tick = ring.tick(
            start + interval,
            || 1,
            || Err(FerrumError::Degraded("no map".into())),
        );
        assert!(tick.drop_check_failed);
        assert_eq!(tick.drop_delta, 0);
        // The failed read did not move `seen_drops`, so the next poll still
        // reports the full total.
        let next = ring.tick(start + interval * 2, || 1, || Ok(3));
        assert_eq!(next.drop_delta, 3);
    }
}
