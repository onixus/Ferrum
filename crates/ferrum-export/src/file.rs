//! Envelope-wrapping sinks: durable JSONL file with size rotation, plus a
//! generic writer variant so stdout and file output share one format.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use chrono::Utc;
use ferrum_ids::Digest;
use ferrum_proto::{EnforcementEvent, EventEnvelope};

use crate::EventSink;

/// Node-local context stamped onto every exported envelope. Cheap to clone;
/// clones share the mutable degraded/digest state, so the agent can flip
/// `Degraded=true` or swap the bundle digest without rebuilding sinks.
#[derive(Clone)]
pub struct SinkContext {
    inner: Arc<ContextInner>,
}

struct ContextInner {
    node: String,
    agent_role: String,
    degraded: AtomicBool,
    bundle_digest: RwLock<Option<Digest>>,
}

impl SinkContext {
    pub fn new(node: impl Into<String>, agent_role: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(ContextInner {
                node: node.into(),
                agent_role: agent_role.into(),
                degraded: AtomicBool::new(false),
                bundle_digest: RwLock::new(None),
            }),
        }
    }

    pub fn set_degraded(&self, degraded: bool) {
        self.inner.degraded.store(degraded, Ordering::Relaxed);
    }

    pub fn set_bundle_digest(&self, digest: Option<Digest>) {
        *self
            .inner
            .bundle_digest
            .write()
            .unwrap_or_else(|e| e.into_inner()) = digest;
    }

    pub fn envelope(&self, event: &EnforcementEvent) -> EventEnvelope {
        EventEnvelope {
            ts: Utc::now(),
            node: self.inner.node.clone(),
            bundle_digest: self
                .inner
                .bundle_digest
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            agent_role: self.inner.agent_role.clone(),
            degraded: self.inner.degraded.load(Ordering::Relaxed),
            event: event.clone(),
        }
    }
}

/// JSONL sink writing `events.jsonl` in `dir`, rotating to
/// `events.jsonl.1..keep_files` when a write would push the active file past
/// `max_bytes`. Construction never touches the filesystem; every failure on
/// the emit path drops the event and bumps the counter instead of
/// propagating.
pub struct RotatingFileSink {
    dir: PathBuf,
    max_bytes: u64,
    keep_files: usize,
    ctx: SinkContext,
    state: Mutex<Option<OpenFile>>,
    dropped: AtomicU64,
}

struct OpenFile {
    file: File,
    len: u64,
}

const ACTIVE_NAME: &str = "events.jsonl";

impl RotatingFileSink {
    pub fn new(
        dir: impl Into<PathBuf>,
        max_bytes: u64,
        keep_files: usize,
        ctx: SinkContext,
    ) -> Self {
        Self {
            dir: dir.into(),
            max_bytes: max_bytes.max(1),
            keep_files,
            ctx,
            state: Mutex::new(None),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn context(&self) -> &SinkContext {
        &self.ctx
    }

    pub fn set_degraded(&self, degraded: bool) {
        self.ctx.set_degraded(degraded);
    }

    pub fn set_bundle_digest(&self, digest: Option<Digest>) {
        self.ctx.set_bundle_digest(digest);
    }

    fn active_path(&self) -> PathBuf {
        self.dir.join(ACTIVE_NAME)
    }

    fn rotated_path(&self, n: usize) -> PathBuf {
        self.dir.join(format!("{ACTIVE_NAME}.{n}"))
    }

    fn open_active(&self) -> std::io::Result<OpenFile> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.active_path())?;
        let len = file.metadata()?.len();
        Ok(OpenFile { file, len })
    }

    /// Shift events.jsonl.(N-1)→.N … events.jsonl→.1. The active file is
    /// closed by the caller before this runs; a full line is only ever
    /// written to a single file, so rotation cannot split a record.
    fn rotate(&self) -> std::io::Result<()> {
        if self.keep_files == 0 {
            std::fs::remove_file(self.active_path())?;
            return Ok(());
        }
        let last = self.rotated_path(self.keep_files);
        if last.exists() {
            std::fs::remove_file(&last)?;
        }
        for n in (1..self.keep_files).rev() {
            let from = self.rotated_path(n);
            if from.exists() {
                std::fs::rename(&from, self.rotated_path(n + 1))?;
            }
        }
        std::fs::rename(self.active_path(), self.rotated_path(1))
    }

    fn try_emit(&self, line: &[u8]) -> std::io::Result<()> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = Some(self.open_active()?);
        }
        let needs_rotation = match guard.as_ref() {
            Some(open) => open.len > 0 && open.len + line.len() as u64 > self.max_bytes,
            None => false,
        };
        if needs_rotation {
            *guard = None;
            self.rotate()?;
            *guard = Some(self.open_active()?);
        }
        let open = guard.as_mut().expect("opened above");
        match open.file.write_all(line).and_then(|_| open.file.flush()) {
            Ok(()) => {
                open.len += line.len() as u64;
                Ok(())
            }
            Err(e) => {
                // The file may hold a partial line; drop the handle so the
                // next emit reopens and re-measures instead of appending to
                // an unknown offset.
                *guard = None;
                Err(e)
            }
        }
    }
}

impl EventSink for RotatingFileSink {
    fn emit(&self, event: &EnforcementEvent) {
        let envelope = self.ctx.envelope(event);
        let mut line = match serde_json::to_vec(&envelope) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        line.push(b'\n');
        if self.try_emit(&line).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn events_dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Envelope counterpart of [`crate::WriterSink`]: same JSONL record shape as
/// [`RotatingFileSink`], any `Write` destination (stdout in the agent).
pub struct EnvelopeWriterSink<W> {
    writer: Mutex<W>,
    ctx: SinkContext,
    dropped: AtomicU64,
}

impl<W> EnvelopeWriterSink<W> {
    pub fn new(writer: W, ctx: SinkContext) -> Self {
        Self {
            writer: Mutex::new(writer),
            ctx,
            dropped: AtomicU64::new(0),
        }
    }

    pub fn context(&self) -> &SinkContext {
        &self.ctx
    }

    fn lock_writer(&self) -> std::sync::MutexGuard<'_, W> {
        self.writer.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl EnvelopeWriterSink<std::io::Stdout> {
    pub fn stdout(ctx: SinkContext) -> Self {
        Self::new(std::io::stdout(), ctx)
    }
}

impl<W: Write> EventSink for EnvelopeWriterSink<W> {
    fn emit(&self, event: &EnforcementEvent) {
        let envelope = self.ctx.envelope(event);
        let payload = match serde_json::to_vec(&envelope) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_ids::{PolicyId, RuleId};
    use ferrum_proto::EventEnvelope;
    use std::path::{Path, PathBuf};

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
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferrum-export-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ctx() -> SinkContext {
        let ctx = SinkContext::new("node-a", "observe");
        ctx.set_bundle_digest(Some(Digest::new("sha256:abc")));
        ctx
    }

    fn parse_lines(path: &Path) -> Vec<EventEnvelope> {
        let data = std::fs::read_to_string(path).unwrap();
        data.lines()
            .map(|l| serde_json::from_str(l).expect("full JSON line"))
            .collect()
    }

    #[test]
    fn envelope_writer_matches_file_format() {
        let sink = EnvelopeWriterSink::new(Vec::new(), ctx());
        sink.context().set_degraded(true);
        sink.emit(&sample());
        let bytes = sink.lock_writer().clone();
        let line = std::str::from_utf8(&bytes).unwrap();
        assert!(line.ends_with('\n'));
        let env: EventEnvelope = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(env.node, "node-a");
        assert_eq!(env.agent_role, "observe");
        assert!(env.degraded);
        assert_eq!(env.bundle_digest.unwrap().to_string(), "sha256:abc");
        assert_eq!(env.event.rule.to_string(), "no-shell");
        assert_eq!(sink.events_dropped_total(), 0);
    }

    #[test]
    fn rotates_by_size_without_partial_lines() {
        let dir = temp_dir("rotate");
        let max_bytes = 700;
        let sink = RotatingFileSink::new(&dir, max_bytes, 3, ctx());
        for _ in 0..20 {
            sink.emit(&sample());
        }
        assert_eq!(sink.events_dropped_total(), 0);
        let mut total = 0;
        let mut rotated = 0;
        for name in [
            "events.jsonl",
            "events.jsonl.1",
            "events.jsonl.2",
            "events.jsonl.3",
        ] {
            let path = dir.join(name);
            if !path.exists() {
                continue;
            }
            let lines = parse_lines(&path);
            if name != "events.jsonl" {
                rotated += 1;
                // A file exceeds max_bytes only when a single record does.
                let len = std::fs::metadata(&path).unwrap().len();
                assert!(len <= max_bytes || lines.len() == 1);
            }
            total += lines.len();
        }
        assert!(rotated >= 1, "small max_bytes must force rotation");
        assert!(!dir.join("events.jsonl.4").exists(), "keep_files=3");
        assert!(total <= 20);
        assert!(total >= 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oversized_line_still_lands_whole() {
        let dir = temp_dir("oversized");
        let sink = RotatingFileSink::new(&dir, 8, 2, ctx());
        sink.emit(&sample());
        sink.emit(&sample());
        assert_eq!(sink.events_dropped_total(), 0);
        let mut total = 0;
        for name in ["events.jsonl", "events.jsonl.1", "events.jsonl.2"] {
            let path = dir.join(name);
            if path.exists() {
                total += parse_lines(&path).len();
            }
        }
        assert_eq!(total, 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unwritable_dir_counts_drops_without_panic() {
        let missing = std::env::temp_dir()
            .join("ferrum-export-missing")
            .join("no-such-subdir");
        let sink = RotatingFileSink::new(missing, 1024, 2, ctx());
        for _ in 0..3 {
            sink.emit(&sample());
        }
        assert_eq!(sink.events_dropped_total(), 3);
    }

    #[test]
    fn degraded_and_digest_update_without_rebuilding_sink() {
        let dir = temp_dir("update");
        let sink = RotatingFileSink::new(&dir, 1 << 20, 2, ctx());
        sink.emit(&sample());
        sink.set_degraded(true);
        sink.set_bundle_digest(Some(Digest::new("sha256:def")));
        sink.emit(&sample());
        let lines = parse_lines(&dir.join("events.jsonl"));
        assert_eq!(lines.len(), 2);
        assert!(!lines[0].degraded);
        assert!(lines[1].degraded);
        assert_eq!(
            lines[1].bundle_digest.clone().unwrap().to_string(),
            "sha256:def"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
