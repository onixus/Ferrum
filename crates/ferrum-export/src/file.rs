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

    /// The node this agent runs on, as stamped on every envelope. Read by the
    /// node status file so the file and the envelopes name the same node.
    pub fn node(&self) -> &str {
        &self.inner.node
    }

    pub fn agent_role(&self) -> &str {
        &self.inner.agent_role
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
            schema: ferrum_proto::SchemaId,
            schema_version: ferrum_proto::EVENT_SCHEMA_VERSION,
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
    /// A failed write may leave a partial line in the file; the next write
    /// must terminate it first so records never glue together.
    torn: AtomicBool,
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
            torn: AtomicBool::new(false),
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
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Events carry pod/namespace/comm; nothing on the node but the
            // agent (and root) should read them. Applies on create only.
            opts.mode(0o600);
        }
        let file = opts.open(self.active_path())?;
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
        if self.torn.load(Ordering::Relaxed) {
            let open = guard.as_mut().expect("opened above");
            if open.len > 0 {
                // Terminate the partial line a failed write left behind so the
                // next record does not glue to it (one lost event stays one).
                if let Err(e) = open.file.write_all(b"\n").and_then(|_| open.file.flush()) {
                    *guard = None;
                    return Err(e);
                }
                open.len += 1;
            }
            self.torn.store(false, Ordering::Relaxed);
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
                // an unknown offset, and remember to terminate the stub.
                *guard = None;
                self.torn.store(true, Ordering::Relaxed);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
impl RotatingFileSink {
    /// Reproduce the state a failed `write_all` leaves behind: closed handle,
    /// torn flag set, partial line already in the file (written by the test).
    fn simulate_failed_write(&self) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.torn.store(true, Ordering::Relaxed);
    }
}

impl EventSink for RotatingFileSink {
    fn emit(&self, event: &EnforcementEvent) {
        self.emit_envelope(&self.ctx.envelope(event))
    }

    fn emit_envelope(&self, envelope: &EventEnvelope) {
        let mut line = match serde_json::to_vec(envelope) {
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

    fn export_write_failed_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Envelope counterpart of [`crate::WriterSink`]: same JSONL record shape as
/// [`RotatingFileSink`], any `Write` destination (stdout in the agent).
pub struct EnvelopeWriterSink<W> {
    writer: Mutex<W>,
    ctx: SinkContext,
    /// A failed write may leave a partial line on the stream; the next write
    /// terminates it first so records never glue together.
    torn: AtomicBool,
    dropped: AtomicU64,
}

impl<W> EnvelopeWriterSink<W> {
    pub fn new(writer: W, ctx: SinkContext) -> Self {
        Self {
            writer: Mutex::new(writer),
            ctx,
            torn: AtomicBool::new(false),
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
        self.emit_envelope(&self.ctx.envelope(event))
    }

    fn emit_envelope(&self, envelope: &EventEnvelope) {
        let mut line = match serde_json::to_vec(envelope) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        line.push(b'\n');
        if self.torn.load(Ordering::Relaxed) {
            line.insert(0, b'\n');
        }
        let mut w = self.lock_writer();
        match w.write_all(&line) {
            Ok(()) => self.torn.store(false, Ordering::Relaxed),
            Err(_) => {
                self.torn.store(true, Ordering::Relaxed);
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn export_write_failed_total(&self) -> u64 {
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
            pid: 0,
            tgid: 0,
            executed: false,
            labels_unknown: false,
            path_unknown: false,
            container_unknown: false,
            respond_error: None,
            waiver: None,
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
        assert_eq!(sink.export_write_failed_total(), 0);
    }

    #[test]
    fn rotates_by_size_without_partial_lines() {
        let dir = temp_dir("rotate");
        let max_bytes = 700;
        let sink = RotatingFileSink::new(&dir, max_bytes, 3, ctx());
        for _ in 0..20 {
            sink.emit(&sample());
        }
        assert_eq!(sink.export_write_failed_total(), 0);
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
        assert_eq!(sink.export_write_failed_total(), 0);
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
        assert_eq!(sink.export_write_failed_total(), 3);
    }

    #[test]
    fn torn_file_line_is_terminated_before_next_record() {
        let dir = temp_dir("torn");
        let sink = RotatingFileSink::new(&dir, 1 << 20, 2, ctx());
        sink.emit(&sample());
        // A failed write_all left half a record in the file.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(dir.join("events.jsonl"))
                .unwrap();
            f.write_all(b"{\"policy\":\"p\",\"rul").unwrap();
        }
        sink.simulate_failed_write();
        sink.emit(&sample());
        let data = std::fs::read_to_string(dir.join("events.jsonl")).unwrap();
        let lines: Vec<&str> = data.lines().collect();
        assert_eq!(lines.len(), 3, "{data:?}");
        serde_json::from_str::<EventEnvelope>(lines[0]).expect("first record intact");
        assert!(serde_json::from_str::<EventEnvelope>(lines[1]).is_err());
        serde_json::from_str::<EventEnvelope>(lines[2]).expect("record after torn line intact");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn active_file_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        let sink = RotatingFileSink::new(&dir, 1 << 20, 2, ctx());
        sink.emit(&sample());
        let mode = std::fs::metadata(dir.join("events.jsonl"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// First `write_all` call fails after writing a prefix; later calls succeed.
    struct FlakyWriter {
        buf: Vec<u8>,
        fail_next_after: Option<usize>,
    }

    impl Write for FlakyWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            match self.fail_next_after.take() {
                Some(n) => {
                    let n = n.min(data.len());
                    self.buf.extend_from_slice(&data[..n]);
                    Err(std::io::Error::other("flaky"))
                }
                None => {
                    self.buf.extend_from_slice(data);
                    Ok(data.len())
                }
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn torn_writer_line_is_terminated_before_next_record() {
        let sink = EnvelopeWriterSink::new(
            FlakyWriter {
                buf: Vec::new(),
                fail_next_after: Some(17),
            },
            ctx(),
        );
        sink.emit(&sample());
        assert_eq!(sink.export_write_failed_total(), 1);
        sink.emit(&sample());
        assert_eq!(sink.export_write_failed_total(), 1);
        let buf = sink.lock_writer().buf.clone();
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text:?}");
        assert!(serde_json::from_str::<EventEnvelope>(lines[0]).is_err());
        serde_json::from_str::<EventEnvelope>(lines[1]).expect("record after torn line intact");
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
