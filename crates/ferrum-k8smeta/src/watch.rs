//! Pod watch: parsing (always compiled, offline-testable) plus a thin network
//! wrapper behind the `apiserver` feature.
//!
//! No kube client: it would pull tokio into a crate that sits on the decision
//! path. The stream is plain HTTP/1.1 over rustls, same shape as
//! `ferrum-admission::server`.

use crate::labels::{LabelObject, LabelWatchEvent};
use crate::source::{normalize_runtime_id, ContainerRecord, PodCache, PodRecord};
use ferrum_common::{FerrumError, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodWatchEvent {
    Added(PodRecord),
    Modified(PodRecord),
    Deleted(PodRecord),
    /// `allowWatchBookmarks`: resourceVersion only, no object change.
    Bookmark(String),
    /// `410 Gone` in-band: the caller must relist, not resume.
    Gone(String),
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchOutcome {
    Applied,
    Removed,
    /// Object was for another node, or unusable. Cache untouched.
    Ignored,
    /// Caller must relist from scratch.
    MustRelist,
}

/// Parse `GET /api/v1/pods` (a `PodList`) into (resourceVersion, pods).
pub fn parse_pod_list(bytes: &[u8]) -> Result<(String, Vec<PodRecord>)> {
    let root: Value = serde_json::from_slice(bytes)
        .map_err(|e| FerrumError::Degraded(format!("pod list json: {e}")))?;
    let kind = root.get("kind").and_then(Value::as_str).unwrap_or_default();
    if kind != "PodList" {
        return Err(FerrumError::Degraded(format!(
            "expected PodList from apiserver, got {kind:?}"
        )));
    }
    let rv = root
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let pods = root
        .get("items")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(parse_pod).collect())
        .unwrap_or_default();
    Ok((rv, pods))
}

/// Parse one line of a `watch=1` stream. Pure: no I/O, no cache.
pub fn parse_watch_event(line: &[u8]) -> Result<PodWatchEvent> {
    let root: Value = serde_json::from_slice(line)
        .map_err(|e| FerrumError::Degraded(format!("watch json: {e}")))?;
    let kind = root.get("type").and_then(Value::as_str).unwrap_or_default();
    let object = root.get("object").unwrap_or(&Value::Null);
    match kind {
        "ADDED" | "MODIFIED" | "DELETED" => {
            let pod = parse_pod(object).ok_or_else(|| {
                FerrumError::Degraded(format!("watch {kind} object is not a usable Pod"))
            })?;
            Ok(match kind {
                "ADDED" => PodWatchEvent::Added(pod),
                "MODIFIED" => PodWatchEvent::Modified(pod),
                _ => PodWatchEvent::Deleted(pod),
            })
        }
        "BOOKMARK" => Ok(PodWatchEvent::Bookmark(
            object
                .pointer("/metadata/resourceVersion")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        )),
        "ERROR" => {
            let (gone, message) = watch_error(object);
            if gone {
                Ok(PodWatchEvent::Gone(message))
            } else {
                Ok(PodWatchEvent::Error(message))
            }
        }
        other => Err(FerrumError::Degraded(format!("unknown watch type {other}"))),
    }
}

/// Fold one event into the cache. DELETE removes by UID, so every cgroup of
/// that pod disappears from the next resolver refresh.
pub fn apply_watch_event(cache: &mut PodCache, event: PodWatchEvent) -> WatchOutcome {
    // Every frame the apiserver produced is proof the watch is alive, so a
    // bookmark on a quiet cluster and a 410 both count. An ERROR frame does
    // not: a stream that only rejects us delivers no pod state. Liveness is
    // not completeness: the 410 below also raises the relist obligation.
    if !matches!(event, PodWatchEvent::Error(_)) {
        cache.mark_applied_at(Instant::now());
    }
    match event {
        PodWatchEvent::Added(pod) | PodWatchEvent::Modified(pod) => {
            if cache.upsert(pod) {
                WatchOutcome::Applied
            } else {
                WatchOutcome::Ignored
            }
        }
        PodWatchEvent::Deleted(pod) => {
            cache.remove(&pod.uid);
            WatchOutcome::Removed
        }
        PodWatchEvent::Bookmark(rv) => {
            cache.set_resource_version(rv);
            WatchOutcome::Ignored
        }
        PodWatchEvent::Gone(_) => {
            cache.raise_relist_pending();
            WatchOutcome::MustRelist
        }
        PodWatchEvent::Error(_) => WatchOutcome::Ignored,
    }
}

/// Feed a whole recorded stream (one JSON object per line). Stops at the first
/// event demanding a relist and reports it.
pub fn apply_watch_stream(cache: &mut PodCache, body: &[u8]) -> Result<WatchOutcome> {
    let mut outcome = WatchOutcome::Ignored;
    for line in body.split(|b| *b == b'\n') {
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let event = parse_watch_event(line)?;
        if let Some(rv) = event_resource_version(&event) {
            cache.set_resource_version(rv);
        }
        outcome = apply_watch_event(cache, event);
        if outcome == WatchOutcome::MustRelist {
            return Ok(outcome);
        }
    }
    Ok(outcome)
}

/// The relist obligation, raised and discharged the same way on either cache.
///
/// Both watch streams meet the same two facts — `410 Gone`, and a frame this
/// build cannot read — and both must answer them identically. One trait so the
/// answer is written once.
pub trait RelistDebt {
    fn relist_pending(&self) -> bool;
    fn raise_relist_pending_at(&mut self, at: Instant);
    /// The debt has stood past [`crate::labels::RELIST_DEBT_HOLDDOWN`] and the
    /// stream should end so the relist can run.
    fn relist_due_at(&self, now: Instant) -> bool;
}

impl RelistDebt for PodCache {
    fn relist_pending(&self) -> bool {
        PodCache::relist_pending(self)
    }

    fn raise_relist_pending_at(&mut self, at: Instant) {
        PodCache::raise_relist_pending_at(self, at)
    }

    fn relist_due_at(&self, now: Instant) -> bool {
        PodCache::relist_due_at(self, now)
    }
}

impl RelistDebt for crate::labels::LabelCache {
    fn relist_pending(&self) -> bool {
        crate::labels::LabelCache::relist_pending(self)
    }

    fn raise_relist_pending_at(&mut self, at: Instant) {
        crate::labels::LabelCache::raise_relist_pending_at(self, at)
    }

    fn relist_due_at(&self, now: Instant) -> bool {
        crate::labels::LabelCache::relist_due_at(self, now)
    }
}

/// A frame the parser cannot read is a change that happened and was not
/// applied: exactly the fact `410 Gone` carries, and it reaches the cache the
/// same way. Skipping it and reading on leaves the cache `listed`, fresh and
/// owing nothing while a namespace it never saw answers a selector as
/// unlabelled — an unobserved label reported as an absent one, which is the
/// fail-open this project refused in cycle 6.
///
/// Deliberately not an `Err` that ends the stream on the frame itself. A frame
/// this build rejects may be one a newer apiserver invented — a `type:` added
/// in an upgrade — and reconnecting on each of them turns a rolling
/// control-plane upgrade into a reconnect storm against the apiserver,
/// authored by the component that is supposed to protect it.
///
/// So the debt is raised here and the stream reads on. Discharging it is not
/// this function's job and deliberately not this function's frame:
/// [`relist_if_due`] runs on *every* frame, so [`RELIST_DEBT_HOLDDOWN`] after
/// the debt was raised the next frame of any kind ends the stream with
/// [`WatchOutcome::MustRelist`] and the cycle's own relist discharges it.
/// Checking it here instead — which is what cycle 11 did — means the debt is
/// only ever looked at again by a *second* unreadable frame: one bad frame on a
/// stream that then stays healthy leaves the cache unwarm for the life of the
/// connection, denying every selected Pod cluster-wide, which is the fault the
/// hold-down exists to bound. Bounded in both directions: at most one reconnect
/// per hold-down however many unreadable frames arrive, and at most one
/// hold-down of failing closed per burst.
///
/// [`RELIST_DEBT_HOLDDOWN`]: crate::labels::RELIST_DEBT_HOLDDOWN
fn note_unreadable_frame<C: RelistDebt + ?Sized>(
    cache: &mut C,
    resource: &str,
    err: &FerrumError,
    now: Instant,
) -> WatchOutcome {
    // Once per debt, not once per frame: the burst that raises it is exactly
    // the burst that would fill the log.
    let first = !cache.relist_pending();
    cache.raise_relist_pending_at(now);
    if first {
        eprintln!(
            "ferrum-k8smeta: unreadable {resource} watch frame, relist pending within {:?};              the stream keeps reading and the cache is not warm until it lands: {err}",
            crate::labels::RELIST_DEBT_HOLDDOWN
        );
    }
    WatchOutcome::Ignored
}

/// The standing debt, checked on every frame rather than only on the ones the
/// parser rejects. A debt raised by an unreadable frame is discharged by a
/// relist, and nothing on a healthy stream asks for one: `Applied` and
/// `Ignored` are not outcomes `cycle()` relists on, so a debt only this frame's
/// successor-in-failure could see is a debt that stands until the connection
/// does — the cache unwarm, admission denying every selected Pod, and
/// `PodCache::snapshot()` naming no cgroups, for hours.
///
/// It stays cheap in the other direction because the answer is still the
/// hold-down and not the frame: inside [`RELIST_DEBT_HOLDDOWN`] this returns
/// `None` however many frames arrive, so a burst of unreadable frames costs one
/// reconnect per hold-down, not one per frame.
///
/// [`RELIST_DEBT_HOLDDOWN`]: crate::labels::RELIST_DEBT_HOLDDOWN
fn relist_if_due<C: RelistDebt + ?Sized>(
    cache: &C,
    resource: &str,
    now: Instant,
) -> Option<WatchOutcome> {
    if !cache.relist_due_at(now) {
        return None;
    }
    eprintln!(
        "ferrum-k8smeta: {resource} relist debt stood past {:?}; ending the stream to relist",
        crate::labels::RELIST_DEBT_HOLDDOWN
    );
    Some(WatchOutcome::MustRelist)
}

/// One line of a pod `watch=1` stream, folded in. The single place a pod frame
/// is turned into cache state, so the network loop cannot answer an unreadable
/// frame differently from a replayed one.
pub fn apply_watch_line(cache: &mut PodCache, line: &[u8]) -> WatchOutcome {
    apply_watch_line_at(cache, line, Instant::now())
}

/// Same, at an explicit instant, so the relist hold-down can be exercised
/// without sleeping through it.
pub fn apply_watch_line_at(cache: &mut PodCache, line: &[u8], now: Instant) -> WatchOutcome {
    if let Some(outcome) = relist_if_due(cache, "pods", now) {
        return outcome;
    }
    let event = match parse_watch_event(line) {
        Ok(event) => event,
        Err(err) => return note_unreadable_frame(cache, "pods", &err, now),
    };
    if let Some(rv) = event_resource_version(&event) {
        cache.set_resource_version(rv);
    }
    apply_watch_event(cache, event)
}

/// Same for one line of a namespaces/serviceaccounts stream. `Err` is reserved
/// for an object the cache refuses to hold, which does end the stream: an
/// unbounded map is how one apiserver OOMs the node.
pub fn apply_labels_line(
    cache: &mut crate::labels::LabelCache,
    resource: &str,
    line: &[u8],
) -> Result<WatchOutcome> {
    apply_labels_line_at(cache, resource, line, Instant::now())
}

/// Same, at an explicit instant, so the relist hold-down can be exercised
/// without sleeping through it.
pub fn apply_labels_line_at(
    cache: &mut crate::labels::LabelCache,
    resource: &str,
    line: &[u8],
    now: Instant,
) -> Result<WatchOutcome> {
    if let Some(outcome) = relist_if_due(cache, resource, now) {
        return Ok(outcome);
    }
    let event = match parse_labels_watch_event(line) {
        Ok(event) => event,
        Err(err) => return Ok(note_unreadable_frame(cache, resource, &err, now)),
    };
    if let Some(rv) = crate::labels::label_event_resource_version(&event) {
        cache.set_resource_version(rv);
    }
    crate::labels::try_apply_labels_event(cache, event)
}

fn event_resource_version(event: &PodWatchEvent) -> Option<String> {
    match event {
        PodWatchEvent::Bookmark(rv) => Some(rv.clone()),
        PodWatchEvent::Added(p) | PodWatchEvent::Modified(p) | PodWatchEvent::Deleted(p) => {
            Some(p.resource_version.clone()).filter(|s| !s.is_empty())
        }
        _ => None,
    }
}

/// Parse a `NamespaceList` or `ServiceAccountList` into (resourceVersion,
/// objects). Only `metadata.name`, `metadata.namespace` and `metadata.labels`
/// are read: nothing else in those objects is a policy input, and a selector
/// must not start depending on secrets or annotations by accident.
pub fn parse_labels_list(kind: &str, bytes: &[u8]) -> Result<(String, Vec<LabelObject>)> {
    let root: Value = serde_json::from_slice(bytes)
        .map_err(|e| FerrumError::Degraded(format!("{kind} json: {e}")))?;
    let got = root.get("kind").and_then(Value::as_str).unwrap_or_default();
    if got != kind {
        return Err(FerrumError::Degraded(format!(
            "expected {kind} from apiserver, got {got:?}"
        )));
    }
    let rv = root
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let objects = root
        .get("items")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(parse_label_object).collect())
        .unwrap_or_default();
    Ok((rv, objects))
}

/// Parse one line of a namespaces/serviceaccounts `watch=1` stream. Pure.
pub fn parse_labels_watch_event(line: &[u8]) -> Result<LabelWatchEvent> {
    let root: Value = serde_json::from_slice(line)
        .map_err(|e| FerrumError::Degraded(format!("watch json: {e}")))?;
    let kind = root.get("type").and_then(Value::as_str).unwrap_or_default();
    let object = root.get("object").unwrap_or(&Value::Null);
    match kind {
        "ADDED" | "MODIFIED" | "DELETED" => {
            let parsed = parse_label_object(object).ok_or_else(|| {
                FerrumError::Degraded(format!("watch {kind} object has no metadata.name"))
            })?;
            Ok(match kind {
                "ADDED" => LabelWatchEvent::Added(parsed),
                "MODIFIED" => LabelWatchEvent::Modified(parsed),
                _ => LabelWatchEvent::Deleted(parsed),
            })
        }
        "BOOKMARK" => Ok(LabelWatchEvent::Bookmark(
            object
                .pointer("/metadata/resourceVersion")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        )),
        "ERROR" => {
            let (gone, message) = watch_error(object);
            if gone {
                Ok(LabelWatchEvent::Gone(message))
            } else {
                Ok(LabelWatchEvent::Error(message))
            }
        }
        other => Err(FerrumError::Degraded(format!("unknown watch type {other}"))),
    }
}

/// `410 Gone` / `Expired` means the resourceVersion is unusable and resuming
/// would skip changes silently.
fn watch_error(object: &Value) -> (bool, String) {
    let code = object.get("code").and_then(Value::as_i64).unwrap_or(0);
    let message = object
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("watch error")
        .to_string();
    let gone = code == 410 || object.get("reason").and_then(Value::as_str) == Some("Expired");
    (gone, message)
}

fn parse_label_object(object: &Value) -> Option<LabelObject> {
    let meta = object.get("metadata")?;
    let name = meta.get("name").and_then(Value::as_str)?.to_string();
    if name.is_empty() {
        return None;
    }
    Some(LabelObject {
        namespace: meta
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        name,
        labels: string_map(meta.get("labels")),
        resource_version: meta
            .get("resourceVersion")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    })
}

/// A Pod object without a UID or a name is unusable; returning None keeps it
/// out of the cache instead of producing an identity with empty fields.
pub fn parse_pod(object: &Value) -> Option<PodRecord> {
    let meta = object.get("metadata")?;
    let uid = meta.get("uid").and_then(Value::as_str)?.to_string();
    let name = meta.get("name").and_then(Value::as_str)?.to_string();
    let namespace = meta
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if uid.is_empty() || name.is_empty() || namespace.is_empty() {
        return None;
    }
    let spec = object.get("spec");
    let node_name = spec
        .and_then(|s| s.get("nodeName"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let service_account = spec
        .and_then(|s| {
            s.get("serviceAccountName")
                .or_else(|| s.get("serviceAccount"))
        })
        .and_then(Value::as_str)
        .unwrap_or("default")
        .to_string();

    let mut images: BTreeMap<String, (String, String, String)> = BTreeMap::new();
    if let Some(list) = object
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
    {
        for status in list {
            let cname = status
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let id = status
                .get("containerID")
                .and_then(Value::as_str)
                .map(normalize_runtime_id)
                .unwrap_or_default();
            let image = status
                .get("image")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let digest = status
                .get("imageID")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if !cname.is_empty() && !id.is_empty() {
                images.insert(cname, (id, image, image_digest(&digest)));
            }
        }
    }

    let containers = images
        .into_iter()
        .map(|(name, (id, image, image_digest))| ContainerRecord {
            name,
            id,
            image,
            image_digest,
        })
        .collect::<Vec<_>>();

    Some(PodRecord {
        uid,
        namespace,
        name,
        node_name,
        service_account,
        resource_version: meta
            .get("resourceVersion")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        labels: string_map(meta.get("labels")),
        // Namespace/ServiceAccount labels are not on the Pod object; the label
        // caches fill them in on the way out of PodCache::snapshot.
        namespace_labels: BTreeMap::new(),
        service_account_labels: BTreeMap::new(),
        containers,
    })
}

/// `imageID` is `<repo>@sha256:...` or a bare digest depending on runtime.
/// Anything else is reported as no digest rather than as a made-up one.
fn image_digest(image_id: &str) -> String {
    image_id
        .rsplit_once('@')
        .map(|(_, d)| d.to_string())
        .unwrap_or_else(|| {
            if image_id.starts_with("sha256:") {
                image_id.to_string()
            } else {
                String::new()
            }
        })
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod freshness_tests {
    use super::*;
    use crate::labels::{LabelCache, RELIST_DEBT_HOLDDOWN};
    use crate::source::{PodMetadataSource, POD_WATCH_BUDGET};
    use std::time::Duration;

    fn stale_cache() -> Option<PodCache> {
        let mut cache = PodCache::new("node-a");
        cache.upsert(PodRecord {
            uid: "u1".into(),
            namespace: "prod".into(),
            name: "web-0".into(),
            node_name: "node-a".into(),
            ..Default::default()
        });
        cache.mark_applied_at(Instant::now().checked_sub(POD_WATCH_BUDGET * 2)?);
        Some(cache)
    }

    #[test]
    fn a_bookmark_refreshes_even_though_it_changes_nothing() {
        let Some(mut cache) = stale_cache() else {
            return;
        };
        assert!(cache.snapshot().is_err(), "stale before the bookmark");
        let event = parse_watch_event(
            br#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"42"}}}"#,
        )
        .expect("bookmark");
        assert_eq!(apply_watch_event(&mut cache, event), WatchOutcome::Ignored);
        assert!(
            cache.applied_age().expect("stamped") < Duration::from_secs(1),
            "an Ignored outcome still proves the stream is alive"
        );
        cache.snapshot().expect("a bookmarked cache resolves");
    }

    const GONE: &[u8] = br#"{"type":"ERROR","object":{"kind":"Status","reason":"Expired","message":"too old resource version: 2 (9)","code":410}}"#;

    #[test]
    fn a_410_is_liveness_but_never_freshness() {
        let Some(mut cache) = stale_cache() else {
            return;
        };
        let event = parse_watch_event(GONE).expect("gone");
        assert_eq!(
            apply_watch_event(&mut cache, event),
            WatchOutcome::MustRelist
        );
        // The stamp lands: the apiserver did answer us.
        assert!(cache.applied_age().expect("stamped") < Duration::from_secs(1));
        assert!(cache.is_fresh_at(Instant::now()), "the watch is alive");
        // The cache is still refused: liveness is not completeness.
        assert!(cache.relist_pending());
        match cache.snapshot() {
            Err(FerrumError::Degraded(msg)) => {
                assert!(msg.contains("relist"), "{msg}");
                assert!(msg.contains("410"), "{msg}");
                assert!(msg.contains("behind"), "{msg}");
            }
            other => panic!("a cache owing a relist must be Degraded, got {other:?}"),
        }
        // Not an eviction: the pods from before the gap are still there for
        // whoever completes the relist.
        assert_eq!(cache.len(), 1);
    }

    /// A watch frame this build cannot parse is a change that happened and was
    /// not applied. Skipping it and reading on left the cache listed, fresh and
    /// owing nothing — warm, with a hole in it — so every consumer that gates on
    /// warmth proceeded off pods it had never been told about.
    #[test]
    fn a_frame_this_build_cannot_read_leaves_the_cache_owing_a_relist() {
        let mut cache = PodCache::new("node-a");
        cache.replace_all(vec![PodRecord {
            uid: "u1".into(),
            namespace: "prod".into(),
            name: "web-0".into(),
            node_name: "node-a".into(),
            ..Default::default()
        }]);
        cache.mark_applied_at(Instant::now());
        cache.snapshot().expect("a listed cache resolves");

        // A `type:` a newer apiserver invented, mid rolling upgrade.
        assert_eq!(
            apply_watch_line(
                &mut cache,
                br#"{"type":"PATCHED","object":{"metadata":{}}}"#
            ),
            WatchOutcome::Ignored
        );
        // The stream keeps running: the very next frame still applies.
        assert_eq!(
            apply_watch_line(
                &mut cache,
                br#"{"type":"ADDED","object":{"metadata":{"uid":"u2","name":"web-1","namespace":"prod","resourceVersion":"9"},"spec":{"nodeName":"node-a"}}}"#
            ),
            WatchOutcome::Applied
        );
        assert_eq!(cache.len(), 2, "the frames we can read are still applied");
        assert!(cache.is_fresh_at(Instant::now()), "the watch is alive");
        // And the cache says what it is: behind, not complete.
        assert!(cache.relist_pending());
        assert!(
            cache.snapshot().is_err(),
            "a cache with a hole in it does not name cgroups"
        );
        cache.replace_all(Vec::new());
        assert!(!cache.relist_pending(), "a relist discharges the debt");
    }

    /// The debt cycle 11 raised had nothing behind it: `Ignored` is not one of
    /// the outcomes `cycle()` relists on, so a watch connection that stays up —
    /// the healthy case — kept the cache unwarm for the life of the process and
    /// `containerOnly` rules stopped firing for good. The hold-down is the
    /// missing relist: the frames keep being read, and once the debt has stood
    /// long enough the stream ends so the cycle's own relist can discharge it.
    #[test]
    fn an_unreadable_pod_frame_ends_the_stream_once_its_debt_stands() {
        let start = Instant::now();
        let mut cache = PodCache::new("node-a");
        cache.replace_all(Vec::new());
        cache.mark_applied_at(start);

        let unknown = br#"{"type":"PATCHED","object":{"metadata":{}}}"#;
        assert_eq!(
            apply_watch_line_at(&mut cache, unknown, start),
            WatchOutcome::Ignored,
            "the frame that raises the debt does not cost a reconnect"
        );
        assert!(cache.relist_pending());
        assert!(
            cache.snapshot().is_err(),
            "a cache with a hole in it denies"
        );
        // Still inside the hold-down: the stream reads on.
        assert_eq!(
            apply_watch_line_at(&mut cache, unknown, start + RELIST_DEBT_HOLDDOWN / 2),
            WatchOutcome::Ignored
        );
        // Past it, and the next frame ends the stream so the relist can run.
        assert_eq!(
            apply_watch_line_at(&mut cache, unknown, start + RELIST_DEBT_HOLDDOWN),
            WatchOutcome::MustRelist,
            "nothing else in cycle() would ever relist"
        );
        // Which is what `cycle()` does with `MustRelist`, and it discharges.
        cache.replace_all(Vec::new());
        cache.mark_applied_at(start + RELIST_DEBT_HOLDDOWN);
        assert!(!cache.relist_pending());
        assert!(cache.snapshot().is_ok(), "the cache is warm again");
    }

    /// The hold-down only ever ran on a *second* unreadable frame: the due
    /// check lived in the `Err` arm of the parser, so a single bad frame on a
    /// stream that then stays healthy raised a debt nothing would ever look at
    /// again. The cache stayed unwarm for the life of the connection, which is
    /// `review.rs` denying every Pod under a namespaceSelector and
    /// `PodCache::snapshot()` refusing to name a cgroup — the very fault the
    /// hold-down was written to bound. So the debt is checked where a frame is
    /// folded in, not where it fails to parse: any frame past the hold-down
    /// ends the stream.
    #[test]
    fn one_unreadable_frame_on_an_otherwise_healthy_stream_still_relists() {
        let start = Instant::now();
        let mut cache = PodCache::new("node-a");
        cache.replace_all(Vec::new());
        cache.mark_applied_at(start);

        assert_eq!(
            apply_watch_line_at(
                &mut cache,
                br#"{"type":"PATCHED","object":{"metadata":{}}}"#,
                start
            ),
            WatchOutcome::Ignored,
            "one bad frame still costs no reconnect of its own"
        );
        assert!(cache.relist_pending());

        // From here the stream is healthy: readable frames and bookmarks, the
        // case that used to leave the debt standing forever.
        let added = br#"{"type":"ADDED","object":{"metadata":{"uid":"u1","name":"web-0","namespace":"prod","resourceVersion":"11"},"spec":{"nodeName":"node-a"}}}"#;
        let bookmark = br#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"12"}}}"#;
        assert_eq!(
            apply_watch_line_at(&mut cache, added, start + RELIST_DEBT_HOLDDOWN / 4),
            WatchOutcome::Applied,
            "inside the hold-down the stream reads on"
        );
        assert_eq!(
            apply_watch_line_at(&mut cache, bookmark, start + RELIST_DEBT_HOLDDOWN / 2),
            WatchOutcome::Ignored
        );
        assert!(
            cache.snapshot().is_err(),
            "and while the debt stands the cache still denies"
        );

        // Past the hold-down, and the next healthy frame ends the stream.
        assert_eq!(
            apply_watch_line_at(&mut cache, added, start + RELIST_DEBT_HOLDDOWN),
            WatchOutcome::MustRelist,
            "a healthy frame past the hold-down must relist, not read on forever"
        );
        cache.replace_all(Vec::new());
        cache.mark_applied_at(start + RELIST_DEBT_HOLDDOWN);
        assert!(!cache.relist_pending());
        assert!(cache.snapshot().is_ok(), "the cache is warm again");

        // The label stream, whose unwarm cache is what denies Pods in
        // admission, answers the same way on the same shape of stream.
        let mut labels = LabelCache::new();
        labels.try_replace_all(Vec::new()).expect("list fits");
        assert_eq!(
            apply_labels_line_at(
                &mut labels,
                "namespaces",
                br#"{"type":"PATCHED","object":{"metadata":{"name":"prod"}}}"#,
                start
            )
            .expect("an unreadable frame is not a stream error"),
            WatchOutcome::Ignored
        );
        let healthy = br#"{"type":"MODIFIED","object":{"metadata":{"name":"prod","resourceVersion":"77"},"labels":{}}}"#;
        assert_ne!(
            apply_labels_line_at(
                &mut labels,
                "namespaces",
                healthy,
                start + RELIST_DEBT_HOLDDOWN / 2
            )
            .expect("healthy frame"),
            WatchOutcome::MustRelist,
            "inside the hold-down a healthy frame is not a reconnect"
        );
        assert!(!labels.is_warm_at(start + RELIST_DEBT_HOLDDOWN / 2));
        assert_eq!(
            apply_labels_line_at(
                &mut labels,
                "namespaces",
                healthy,
                start + RELIST_DEBT_HOLDDOWN
            )
            .expect("healthy frame"),
            WatchOutcome::MustRelist,
            "otherwise is_warm stays false for the life of the connection"
        );
        labels.try_replace_all(Vec::new()).expect("relist fits");
        assert!(labels.is_warm_at(start + RELIST_DEBT_HOLDDOWN));
    }

    /// The other direction, which the fix must not break: a rolling
    /// control-plane upgrade emitting a `type:` this build does not know on
    /// every frame must not become one reconnect per frame against the
    /// apiserver the whole cluster depends on.
    #[test]
    fn a_rolling_stream_of_unknown_frames_is_not_a_reconnect_per_frame() {
        let start = Instant::now();
        let mut cache = LabelCache::new();
        cache.try_replace_all(Vec::new()).expect("list fits");

        let unknown = br#"{"type":"PATCHED","object":{"metadata":{"name":"prod"}}}"#;
        let span = RELIST_DEBT_HOLDDOWN * 4;
        let frames = 400u32;
        let step = span / frames;
        let mut relists = 0u32;
        let mut now = start;
        for _ in 0..frames {
            let outcome = apply_labels_line_at(&mut cache, "namespaces", unknown, now)
                .expect("an unreadable frame is not a stream error");
            if outcome == WatchOutcome::MustRelist {
                relists += 1;
                // What the cycle does next: reconnect and list.
                cache.try_replace_all(Vec::new()).expect("relist fits");
            }
            now += step;
        }
        assert!(
            relists <= 5,
            "{frames} unreadable frames over {span:?} cost {relists} reconnects; the \
             hold-down bounds that at one per {RELIST_DEBT_HOLDDOWN:?}"
        );
        assert!(
            relists >= 3,
            "and the debt is still discharged, repeatedly: {relists}"
        );
    }

    #[test]
    fn only_a_completed_relist_clears_the_debt() {
        let Some(mut cache) = stale_cache() else {
            return;
        };
        assert_eq!(
            apply_watch_stream(&mut cache, GONE).expect("apply"),
            WatchOutcome::MustRelist
        );
        assert!(cache.snapshot().is_err());

        // A later event proves the new stream is alive, and that is all: the
        // gap the 410 left is only closed by a full list.
        let event = parse_watch_event(
            br#"{"type":"MODIFIED","object":{"metadata":{"uid":"u1","name":"web-0","namespace":"prod","resourceVersion":"99"},"spec":{"nodeName":"node-a"}}}"#,
        )
        .expect("modified");
        assert_eq!(apply_watch_event(&mut cache, event), WatchOutcome::Applied);
        assert!(cache.relist_pending(), "an event is not a list");
        assert!(cache.snapshot().is_err());

        let (_, pods) = parse_pod_list(
            br#"{"kind":"PodList","metadata":{"resourceVersion":"1200"},"items":[
                 {"metadata":{"uid":"u1","name":"web-0","namespace":"prod"},
                  "spec":{"nodeName":"node-a"}}]}"#,
        )
        .expect("list");
        cache.replace_all(pods);
        cache.mark_applied_at(Instant::now());
        assert!(!cache.relist_pending());
        assert_eq!(cache.snapshot().expect("relisted").len(), 1);
    }

    #[test]
    fn a_bare_error_frame_is_not_liveness() {
        let Some(mut cache) = stale_cache() else {
            return;
        };
        let event = parse_watch_event(
            br#"{"type":"ERROR","object":{"kind":"Status","message":"boom","code":500}}"#,
        )
        .expect("error");
        assert_eq!(apply_watch_event(&mut cache, event), WatchOutcome::Ignored);
        assert!(
            cache.snapshot().is_err(),
            "a stream that only errors delivers no pod state"
        );
    }

    #[test]
    fn an_applied_stream_leaves_the_cache_usable() {
        let Some(mut cache) = stale_cache() else {
            return;
        };
        let stream = br#"{"type":"MODIFIED","object":{"metadata":{"uid":"u1","name":"web-0","namespace":"prod","resourceVersion":"77"},"spec":{"nodeName":"node-a"}}}"#;
        assert_eq!(
            apply_watch_stream(&mut cache, stream).expect("apply"),
            WatchOutcome::Applied
        );
        assert_eq!(cache.snapshot().expect("fresh").len(), 1);
    }
}

#[cfg(test)]
mod label_parse_tests {
    use super::*;
    use crate::labels::{apply_labels_event, apply_labels_stream, LabelCache};

    const NS_LIST: &[u8] = br#"{
        "kind": "NamespaceList",
        "metadata": {"resourceVersion": "2001"},
        "items": [
          {"metadata": {"name": "prod", "resourceVersion": "1900",
                        "labels": {"ferrum.io/zone": "pci"}}},
          {"metadata": {"name": "dev", "resourceVersion": "1901", "labels": {}}},
          {"metadata": {"resourceVersion": "1902"}}
        ]
    }"#;

    #[test]
    fn namespace_list_keeps_only_name_and_labels() {
        let (rv, objects) = parse_labels_list("NamespaceList", NS_LIST).expect("list");
        assert_eq!(rv, "2001");
        // The nameless item is dropped, not stored under an empty key.
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].name, "prod");
        assert!(objects[0].namespace.is_empty());
        assert_eq!(
            objects[0].labels.get("ferrum.io/zone").map(String::as_str),
            Some("pci")
        );
        assert!(objects[1].labels.is_empty());
    }

    #[test]
    fn wrong_kind_is_degraded_not_an_empty_list() {
        let err = parse_labels_list("ServiceAccountList", NS_LIST).expect_err("kind mismatch");
        assert!(err.to_string().contains("ServiceAccountList"), "{err}");
    }

    #[test]
    fn service_account_list_carries_its_namespace() {
        let raw = br#"{
            "kind": "ServiceAccountList",
            "metadata": {"resourceVersion": "3001"},
            "items": [
              {"metadata": {"name": "default", "namespace": "prod",
                            "labels": {"tier": "front"}}},
              {"metadata": {"name": "default", "namespace": "dev",
                            "labels": {"tier": "sandbox"}}}
            ]
        }"#;
        let (_, objects) = parse_labels_list("ServiceAccountList", raw).expect("list");
        let mut cache = LabelCache::new();
        cache.try_replace_all(objects).expect("list fits");
        assert_eq!(
            cache.labels_or_empty("prod", "default").get("tier"),
            Some(&"front".to_string())
        );
        assert_eq!(
            cache.labels_or_empty("dev", "default").get("tier"),
            Some(&"sandbox".to_string())
        );
    }

    #[test]
    fn watch_events_add_modify_delete_and_bookmark() {
        let mut cache = LabelCache::new();
        cache.try_replace_all(Vec::new()).expect("list fits");
        let added = parse_labels_watch_event(
            br#"{"type":"ADDED","object":{"metadata":{"name":"prod","resourceVersion":"5",
                 "labels":{"ferrum.io/zone":"pci"}}}}"#,
        )
        .expect("added");
        assert_eq!(apply_labels_event(&mut cache, added), WatchOutcome::Applied);
        assert_eq!(
            cache.labels_or_empty("", "prod").get("ferrum.io/zone"),
            Some(&"pci".to_string())
        );

        let modified = parse_labels_watch_event(
            br#"{"type":"MODIFIED","object":{"metadata":{"name":"prod","resourceVersion":"6",
                 "labels":{"ferrum.io/zone":"public"}}}}"#,
        )
        .expect("modified");
        apply_labels_event(&mut cache, modified);
        assert_eq!(
            cache.labels_or_empty("", "prod").get("ferrum.io/zone"),
            Some(&"public".to_string())
        );

        let bookmark = parse_labels_watch_event(
            br#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"7"}}}"#,
        )
        .expect("bookmark");
        apply_labels_event(&mut cache, bookmark);
        assert_eq!(cache.resource_version(), "7");

        let deleted = parse_labels_watch_event(
            br#"{"type":"DELETED","object":{"metadata":{"name":"prod","resourceVersion":"8"}}}"#,
        )
        .expect("deleted");
        assert_eq!(
            apply_labels_event(&mut cache, deleted),
            WatchOutcome::Removed
        );
        assert!(cache.labels_of("", "prod").is_none());
    }

    #[test]
    fn expired_resource_version_demands_a_relist() {
        let line = br#"{"type":"ERROR","object":{"kind":"Status","reason":"Expired","message":"too old resource version: 2 (9)","code":410}}"#;
        match parse_labels_watch_event(line).expect("parse") {
            LabelWatchEvent::Gone(msg) => {
                assert!(msg.contains("too old resource version"), "{msg}")
            }
            other => panic!("410 must be Gone, got {other:?}"),
        }
        let mut cache = LabelCache::new();
        cache
            .try_replace_all(parse_labels_list("NamespaceList", NS_LIST).expect("list").1)
            .expect("list fits");
        assert!(cache.is_warm());
        let outcome = apply_labels_stream(&mut cache, line).expect("apply");
        assert_eq!(outcome, WatchOutcome::MustRelist);
        // A relist demand must not empty the cache we already have.
        assert_eq!(cache.len(), 2);
        // But the labels in it are known to have moved on without us: a
        // selector must not be decided off them until a list lands.
        assert!(cache.relist_pending());
        assert!(!cache.is_warm(), "410 is liveness, not warmth");
        cache
            .try_replace_all(parse_labels_list("NamespaceList", NS_LIST).expect("list").1)
            .expect("list fits");
        assert!(!cache.relist_pending());
        assert!(cache.is_warm(), "a completed relist clears the debt");
    }

    /// The same fact on the label caches, where it is a fail-open: the
    /// namespace whose ADDED frame was eaten has labels, the cache does not
    /// have them, and `labels_or_empty` cannot tell that apart from a namespace
    /// that carries none. An unobserved label is not a non-match, so the cache
    /// must stop calling itself warm the moment it misses a frame.
    #[test]
    fn an_eaten_namespace_frame_is_not_a_namespace_without_labels() {
        let mut cache = LabelCache::new();
        cache.try_replace_all(Vec::new()).expect("empty list fits");
        assert!(cache.is_warm(), "a completed list of zero objects is warm");

        // prod is created with the label a namespaceSelector matches on, and
        // the frame that carries it is one this parser refuses.
        let eaten = br#"{"type":"ADDED","object":{"metadata":{"labels":{"ferrum.io/zone":"prod"},"resourceVersion":"4"}}}"#;
        assert!(
            parse_labels_watch_event(eaten).is_err(),
            "the frame is unreadable"
        );
        assert_eq!(
            apply_labels_line(&mut cache, "namespaces", eaten)
                .expect("a skipped frame is not a stream error"),
            WatchOutcome::Ignored
        );
        // A well-formed frame right after it, and the stream is still running.
        assert_eq!(
            apply_labels_line(
                &mut cache,
                "namespaces",
                br#"{"type":"ADDED","object":{"metadata":{"name":"dev","resourceVersion":"5"}}}"#
            )
            .expect("applied"),
            WatchOutcome::Applied
        );
        assert_eq!(cache.resource_version(), "5");
        // The hole is real: prod answers as unlabelled.
        assert!(cache.labels_or_empty("", "prod").is_empty());
        // So the cache must not be warm, which is the gate every consumer of
        // these labels fails closed on.
        assert!(cache.relist_pending());
        assert!(!cache.is_warm(), "a cache that missed a frame is not warm");
        cache.try_replace_all(Vec::new()).expect("relist fits");
        assert!(cache.is_warm(), "a completed relist clears the debt");
    }

    #[test]
    fn non_410_watch_error_is_not_a_relist() {
        let line = br#"{"type":"ERROR","object":{"kind":"Status","message":"boom","code":500}}"#;
        match parse_labels_watch_event(line).expect("parse") {
            LabelWatchEvent::Error(msg) => assert_eq!(msg, "boom"),
            other => panic!("500 must stay Error, got {other:?}"),
        }
    }
}

#[cfg(feature = "apiserver")]
pub use client::{ApiserverConfig, ApiserverWatcher, LabelWatcher, SERVICE_ACCOUNT_DIR};

#[cfg(feature = "apiserver")]
mod client {
    use super::{apply_labels_line, apply_watch_line, parse_labels_list, parse_pod_list};
    use crate::labels::LabelCache;
    use crate::source::{PodCache, POD_WATCH_BUDGET};
    use crate::watch::WatchOutcome;
    use ferrum_common::{FerrumError, Result};
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, Instant};

    pub const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
    /// The apiserver certificate carries this SAN; the Service IP we dial does
    /// not have to be in it, so verification uses the name, not the address.
    const DEFAULT_SERVER_NAME: &str = "kubernetes.default.svc";
    const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;
    /// A header line longer than this, or more than [`MAX_HEADER_LINES`] of
    /// them, is an unhealthy or hostile apiserver trying to grow our heap:
    /// refuse instead of buffering.
    const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;
    const MAX_HEADER_LINES: usize = 100;
    /// Relist body ceiling. A node's PodList is orders of magnitude smaller;
    /// anything past this is not a list we are willing to hold in memory.
    const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
    const RECONNECT_BACKOFF: Duration = Duration::from_secs(2);
    const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);
    /// A cycle that streamed at least this long was a healthy connection, so
    /// the next reconnect starts from the base delay again.
    const HEALTHY_STREAM: Duration = Duration::from_secs(60);
    /// A blackholed connection blocks in `read()` forever, and a watch thread
    /// parked there never reconnects while the cache silently ages out. Half
    /// the freshness budget: the timeout fires, the cycle reconnects and
    /// relists, all before `PodCache::snapshot` starts refusing. Long enough
    /// that ordinary bookmark gaps on a quiet cluster do not trip it.
    const IO_TIMEOUT: Duration = Duration::from_secs(POD_WATCH_BUDGET.as_secs() / 2);
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    #[derive(Debug, Clone)]
    pub struct ApiserverConfig {
        pub host: String,
        pub port: u16,
        pub server_name: String,
        pub node_name: String,
        pub token_path: PathBuf,
        pub ca_path: PathBuf,
    }

    impl ApiserverConfig {
        /// In-cluster config for a cluster-wide watch. No node name: the
        /// namespaces/serviceaccounts watches carry no fieldSelector, so there
        /// is nothing to scope them to.
        pub fn cluster_wide() -> Result<Self> {
            Self::in_cluster(String::new())
        }

        /// In-cluster config: Service env vars plus the projected SA volume.
        pub fn from_service_account(node_name: impl Into<String>) -> Result<Self> {
            let node_name = node_name.into();
            if node_name.is_empty() {
                return Err(FerrumError::Degraded(
                    "node name required: an unscoped pod watch is a cluster-wide read".into(),
                ));
            }
            Self::in_cluster(node_name)
        }

        fn in_cluster(node_name: String) -> Result<Self> {
            let host = std::env::var("KUBERNETES_SERVICE_HOST")
                .map_err(|_| FerrumError::Degraded("KUBERNETES_SERVICE_HOST unset".into()))?;
            let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
                .or_else(|_| std::env::var("KUBERNETES_SERVICE_PORT"))
                .unwrap_or_else(|_| "443".into())
                .parse::<u16>()
                .map_err(|e| FerrumError::Degraded(format!("KUBERNETES_SERVICE_PORT: {e}")))?;
            Self::from_sa_dir(node_name, host, port, Path::new(SERVICE_ACCOUNT_DIR))
        }

        /// The half of `in_cluster` that does not read the environment, so
        /// the token check below is reachable from a test without a projected
        /// volume and without touching process-global env vars.
        fn from_sa_dir(node_name: String, host: String, port: u16, dir: &Path) -> Result<Self> {
            let token_path = dir.join("token");
            // Checked at construction, not left to the first connect.
            // `automountServiceAccountToken: false` on the pod spec or the
            // ServiceAccount projects no token at all, and that is the shipped
            // install defect cycle 10 slice A fixed in the manifests: without
            // this check the config is built, the watch thread spawns, every
            // connect authenticates with nothing, and the only symptom is an
            // endless backoff on a cache that never warms. A failure here
            // names the file that is missing, at startup, where the operator
            // is looking. The token is still re-read on every connect —
            // projected tokens rotate — so this is an existence check and not
            // a value the config holds.
            if !token_path.exists() {
                return Err(FerrumError::Degraded(format!(
                    "{} does not exist: no ServiceAccount token is projected into this pod, so \
                     every apiserver request would authenticate as nobody. Check \
                     automountServiceAccountToken on the pod spec and on the ServiceAccount.",
                    token_path.display()
                )));
            }
            Ok(Self {
                host,
                port,
                server_name: DEFAULT_SERVER_NAME.to_string(),
                node_name,
                token_path,
                ca_path: dir.join("ca.crt"),
            })
        }

        /// Re-read every connect: projected tokens rotate.
        fn token(&self) -> Result<String> {
            let raw = std::fs::read_to_string(&self.token_path).map_err(|e| {
                FerrumError::Degraded(format!(
                    "service account token {}: {e}",
                    self.token_path.display()
                ))
            })?;
            Ok(raw.trim().to_string())
        }

        fn connect(&self) -> Result<TlsStream> {
            let cfg = self.tls_config()?;
            let name = rustls::ServerName::try_from(self.server_name.as_str())
                .map_err(|e| FerrumError::Degraded(format!("apiserver server name: {e}")))?;
            let conn = rustls::ClientConnection::new(cfg, name)
                .map_err(|e| FerrumError::Degraded(format!("tls client: {e}")))?;
            let tcp = self.dial()?;
            Ok(rustls::StreamOwned::new(conn, tcp))
        }

        /// Connect with every deadline set before the socket is used once.
        fn dial(&self) -> Result<TcpStream> {
            let addrs = (self.host.as_str(), self.port)
                .to_socket_addrs()
                .map_err(|e| FerrumError::Degraded(format!("apiserver resolve: {e}")))?;
            let mut last: Option<io::Error> = None;
            for addr in addrs {
                match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                    Ok(tcp) => {
                        let _ = tcp.set_nodelay(true);
                        // Not best-effort: a socket with no read deadline is
                        // exactly the hang these timeouts exist to break, so
                        // failing to set them fails the connect.
                        tcp.set_read_timeout(Some(IO_TIMEOUT))
                            .and_then(|_| tcp.set_write_timeout(Some(IO_TIMEOUT)))
                            .map_err(|e| {
                                FerrumError::Degraded(format!("apiserver socket timeout: {e}"))
                            })?;
                        return Ok(tcp);
                    }
                    Err(e) => last = Some(e),
                }
            }
            Err(FerrumError::Degraded(match last {
                Some(e) => format!("apiserver connect: {e}"),
                None => format!(
                    "apiserver {}:{} resolved to no address",
                    self.host, self.port
                ),
            }))
        }

        fn request(&self, stream: &mut TlsStream, path: &str) -> Result<()> {
            let token = self.token()?;
            let mut req = String::new();
            req.push_str(&format!("GET {path} HTTP/1.1\r\n"));
            req.push_str(&format!("Host: {}\r\n", self.server_name));
            req.push_str(&format!("Authorization: Bearer {token}\r\n"));
            req.push_str("Accept: application/json\r\n");
            req.push_str("User-Agent: ferrum-k8smeta\r\n");
            req.push_str("Connection: close\r\n\r\n");
            stream
                .write_all(req.as_bytes())
                .and_then(|_| stream.flush())
                .map_err(|e| FerrumError::Degraded(format!("apiserver request: {e}")))
        }

        fn tls_config(&self) -> Result<Arc<rustls::ClientConfig>> {
            let pem = std::fs::read(&self.ca_path).map_err(|e| {
                FerrumError::Degraded(format!("cluster CA {}: {e}", self.ca_path.display()))
            })?;
            let mut reader = io::Cursor::new(pem);
            let certs = rustls_pemfile::certs(&mut reader)
                .map_err(|e| FerrumError::Degraded(format!("cluster CA parse: {e}")))?;
            if certs.is_empty() {
                return Err(FerrumError::Degraded(
                    "cluster CA has no certificate".into(),
                ));
            }
            let mut roots = rustls::RootCertStore::empty();
            for cert in certs {
                roots
                    .add(&rustls::Certificate(cert))
                    .map_err(|e| FerrumError::Degraded(format!("cluster CA rejected: {e}")))?;
            }
            // Cluster CA only: no system roots, no fallback to webpki defaults.
            Ok(Arc::new(
                rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ))
        }
    }

    type TlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

    /// Live pod cache fed by a watch. Owns no threads of its own; the caller
    /// decides where `run` spins.
    pub struct ApiserverWatcher {
        config: ApiserverConfig,
        cache: Arc<RwLock<PodCache>>,
    }

    impl ApiserverWatcher {
        pub fn new(config: ApiserverConfig) -> Self {
            let cache = PodCache::new(config.node_name.clone());
            Self {
                config,
                cache: Arc::new(RwLock::new(cache)),
            }
        }

        pub fn cache(&self) -> Arc<RwLock<PodCache>> {
            Arc::clone(&self.cache)
        }

        fn with_cache<T>(&self, f: impl FnOnce(&mut PodCache) -> T) -> T {
            let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
            f(&mut guard)
        }

        fn list_path(&self) -> String {
            format!(
                "/api/v1/pods?fieldSelector={}&resourceVersion=0",
                percent_encode(&format!("spec.nodeName={}", self.config.node_name))
            )
        }

        fn watch_path(&self, rv: &str) -> String {
            format!(
                "/api/v1/pods?fieldSelector={}&watch=1&allowWatchBookmarks=true&resourceVersion={}",
                percent_encode(&format!("spec.nodeName={}", self.config.node_name)),
                percent_encode(rv)
            )
        }

        /// Full list; replaces the cache. Returns the resourceVersion to watch from.
        pub fn relist(&self) -> Result<String> {
            let mut stream = self.config.connect()?;
            let path = self.list_path();
            self.config.request(&mut stream, &path)?;
            let mut reader = BufReader::new(stream);
            let head = read_head(&mut reader)?;
            if head.status != 200 {
                return Err(FerrumError::Degraded(format!(
                    "apiserver list returned {}",
                    head.status
                )));
            }
            let mut body = Vec::new();
            read_body(&mut reader, &head, &mut body)?;
            let (rv, pods) = parse_pod_list(&body)?;
            self.with_cache(|c| {
                c.replace_all(pods);
                c.set_resource_version(rv.clone());
                c.mark_applied_at(Instant::now());
            });
            Ok(rv)
        }

        /// Stream events until the connection ends. `Ok(MustRelist)` means the
        /// resourceVersion expired (410) and resuming would silently skip
        /// changes; the caller must relist.
        pub fn watch_once(&self, rv: &str) -> Result<WatchOutcome> {
            let mut stream = self.config.connect()?;
            let path = self.watch_path(rv);
            self.config.request(&mut stream, &path)?;
            let mut reader = BufReader::new(stream);
            let head = read_head(&mut reader)?;
            match head.status {
                200 => {}
                // Same fact as an in-band 410, only delivered as a status.
                410 => {
                    self.with_cache(|c| c.raise_relist_pending());
                    return Ok(WatchOutcome::MustRelist);
                }
                other => {
                    return Err(FerrumError::Degraded(format!(
                        "apiserver watch returned {other}"
                    )))
                }
            }
            let mut body = BodyReader::new(&mut reader, &head);
            loop {
                let mut line = Vec::new();
                match read_line(&mut body, &mut line) {
                    Ok(0) => return Ok(WatchOutcome::Applied),
                    Ok(_) => {}
                    Err(e) => return Err(FerrumError::Degraded(format!("watch stream: {e}"))),
                }
                if line.iter().all(|b| b.is_ascii_whitespace()) {
                    continue;
                }
                let outcome = self.with_cache(|c| apply_watch_line(c, &line));
                if outcome == WatchOutcome::MustRelist {
                    return Ok(outcome);
                }
            }
        }

        /// One relist plus watch streams until the connection ends or the
        /// resourceVersion expires. Returning is normal; the caller backs off.
        fn cycle(&self) -> Result<()> {
            let mut rv = self.relist()?;
            loop {
                match self.watch_once(&rv)? {
                    WatchOutcome::MustRelist => return Ok(()),
                    _ => {
                        rv = self
                            .cache
                            .read()
                            .unwrap_or_else(|e| e.into_inner())
                            .resource_version()
                            .to_string();
                        if rv.is_empty() {
                            return Ok(());
                        }
                    }
                }
            }
        }

        /// List, watch, reconnect forever. 410 relists instead of resuming.
        /// Namespace and ServiceAccount labels ride along on their own threads:
        /// they feed the same `PodCache`, so no caller has to ask for them.
        pub fn run(&self) -> ! {
            for service_accounts in [false, true] {
                let stream = LabelStream {
                    config: self.config.clone(),
                    kind: if service_accounts {
                        SERVICE_ACCOUNTS
                    } else {
                        NAMESPACES
                    },
                    sink: Box::new(PodCacheLabels {
                        cache: self.cache(),
                        service_accounts,
                    }),
                };
                std::thread::spawn(move || stream.run());
            }
            watch_loop(|| self.cycle(), std::thread::sleep, None);
            unreachable!("watch_loop without a budget never returns")
        }
    }

    const NAMESPACES: LabelKind = LabelKind {
        list_kind: "NamespaceList",
        resource: "namespaces",
    };
    const SERVICE_ACCOUNTS: LabelKind = LabelKind {
        list_kind: "ServiceAccountList",
        resource: "serviceaccounts",
    };

    #[derive(Debug, Clone, Copy)]
    struct LabelKind {
        list_kind: &'static str,
        resource: &'static str,
    }

    /// Where a label stream writes. The two label caches of a `PodCache` live
    /// inside it, behind the same lock as the pods, so they cannot be handed
    /// out as separate `Arc`s.
    trait LabelSink: Send + Sync {
        fn with(&self, f: &mut dyn FnMut(&mut LabelCache));
    }

    struct SharedLabels(Arc<RwLock<LabelCache>>);

    impl LabelSink for SharedLabels {
        fn with(&self, f: &mut dyn FnMut(&mut LabelCache)) {
            f(&mut self.0.write().unwrap_or_else(|e| e.into_inner()));
        }
    }

    struct PodCacheLabels {
        cache: Arc<RwLock<PodCache>>,
        service_accounts: bool,
    }

    impl LabelSink for PodCacheLabels {
        fn with(&self, f: &mut dyn FnMut(&mut LabelCache)) {
            let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
            if self.service_accounts {
                f(guard.service_accounts_mut());
            } else {
                f(guard.namespaces_mut());
            }
        }
    }

    /// One cluster-wide list+watch of a label-bearing kind.
    struct LabelStream {
        config: ApiserverConfig,
        kind: LabelKind,
        sink: Box<dyn LabelSink>,
    }

    impl LabelStream {
        fn relist(&self) -> Result<String> {
            let mut stream = self.config.connect()?;
            let path = format!("/api/v1/{}?resourceVersion=0", self.kind.resource);
            self.config.request(&mut stream, &path)?;
            let mut reader = BufReader::new(stream);
            let head = read_head(&mut reader)?;
            if head.status != 200 {
                return Err(FerrumError::Degraded(format!(
                    "apiserver {} list returned {}",
                    self.kind.resource, head.status
                )));
            }
            let mut body = Vec::new();
            read_body(&mut reader, &head, &mut body)?;
            let (rv, objects) = parse_labels_list(self.kind.list_kind, &body)?;
            let mut objects = Some(objects);
            let listed_rv = rv.clone();
            let mut stored: Result<()> = Ok(());
            self.sink.with(&mut |cache| {
                stored = cache.try_replace_all(objects.take().unwrap_or_default());
                if stored.is_ok() {
                    cache.set_resource_version(listed_rv.clone());
                }
            });
            // A list past the cache ceilings leaves it cold; relisting on the
            // next cycle is the only honest answer.
            stored?;
            Ok(rv)
        }

        fn watch_once(&self, rv: &str) -> Result<WatchOutcome> {
            let mut stream = self.config.connect()?;
            let path = format!(
                "/api/v1/{}?watch=1&allowWatchBookmarks=true&resourceVersion={}",
                self.kind.resource,
                percent_encode(rv)
            );
            self.config.request(&mut stream, &path)?;
            let mut reader = BufReader::new(stream);
            let head = read_head(&mut reader)?;
            match head.status {
                200 => {}
                // Same fact as an in-band 410, only delivered as a status.
                410 => {
                    self.sink.with(&mut |cache| cache.raise_relist_pending());
                    return Ok(WatchOutcome::MustRelist);
                }
                other => {
                    return Err(FerrumError::Degraded(format!(
                        "apiserver {} watch returned {other}",
                        self.kind.resource
                    )))
                }
            }
            let mut body = BodyReader::new(&mut reader, &head);
            loop {
                let mut line = Vec::new();
                match read_line(&mut body, &mut line) {
                    Ok(0) => return Ok(WatchOutcome::Applied),
                    Ok(_) => {}
                    Err(e) => return Err(FerrumError::Degraded(format!("watch stream: {e}"))),
                }
                if line.iter().all(|b| b.is_ascii_whitespace()) {
                    continue;
                }
                let mut applied: Result<WatchOutcome> = Ok(WatchOutcome::Ignored);
                self.sink.with(&mut |cache| {
                    applied = apply_labels_line(cache, self.kind.resource, &line);
                });
                // An object the cache refuses to hold ends the stream: growing
                // the map without a ceiling is how one apiserver OOMs us.
                let outcome = applied?;
                if outcome == WatchOutcome::MustRelist {
                    return Ok(outcome);
                }
            }
        }

        fn cycle(&self) -> Result<()> {
            let mut rv = self.relist()?;
            loop {
                match self.watch_once(&rv)? {
                    WatchOutcome::MustRelist => return Ok(()),
                    _ => {
                        let mut current = String::new();
                        self.sink
                            .with(&mut |cache| current = cache.resource_version().to_string());
                        if current.is_empty() {
                            return Ok(());
                        }
                        rv = current;
                    }
                }
            }
        }

        fn run(self) -> ! {
            watch_loop(|| self.cycle(), std::thread::sleep, None);
            unreachable!("watch_loop without a budget never returns")
        }
    }

    /// Cluster-wide Namespace and ServiceAccount label caches. This is the
    /// admission-side entry point: it never reads Pods, so the webhook's RBAC
    /// stays get/list/watch on those two kinds.
    pub struct LabelWatcher {
        config: ApiserverConfig,
        namespaces: Arc<RwLock<LabelCache>>,
        service_accounts: Arc<RwLock<LabelCache>>,
    }

    impl LabelWatcher {
        pub fn new(config: ApiserverConfig) -> Self {
            Self {
                config,
                namespaces: Arc::new(RwLock::new(LabelCache::new())),
                service_accounts: Arc::new(RwLock::new(LabelCache::new())),
            }
        }

        pub fn namespaces(&self) -> Arc<RwLock<LabelCache>> {
            Arc::clone(&self.namespaces)
        }

        pub fn service_accounts(&self) -> Arc<RwLock<LabelCache>> {
            Arc::clone(&self.service_accounts)
        }

        /// Both streams on their own threads. Returns immediately: the caller
        /// keeps serving while the caches are still cold.
        pub fn spawn(&self) {
            for (sink, kind) in [
                (
                    Box::new(SharedLabels(self.namespaces())) as Box<dyn LabelSink>,
                    NAMESPACES,
                ),
                (
                    Box::new(SharedLabels(self.service_accounts())) as Box<dyn LabelSink>,
                    SERVICE_ACCOUNTS,
                ),
            ] {
                let stream = LabelStream {
                    config: self.config.clone(),
                    kind,
                    sink,
                };
                std::thread::spawn(move || stream.run());
            }
        }
    }

    /// Reconnect delay: doubles up to [`MAX_RECONNECT_BACKOFF`] so an apiserver
    /// that closes every connection at once cannot turn us into a busy loop.
    struct Backoff {
        next: Duration,
    }

    impl Backoff {
        fn new() -> Self {
            Self {
                next: RECONNECT_BACKOFF,
            }
        }

        fn take(&mut self) -> Duration {
            let now = self.next;
            self.next = (now * 2).min(MAX_RECONNECT_BACKOFF);
            now
        }

        fn reset(&mut self) {
            self.next = RECONNECT_BACKOFF;
        }
    }

    /// Drives `cycle`, sleeping between every iteration — including the ones
    /// that returned `Ok`, because an apiserver that answers with an immediate
    /// EOF would otherwise spin here. `budget` bounds the iteration count for
    /// tests; production passes `None` and never returns.
    fn watch_loop<C, S>(mut cycle: C, mut sleep: S, budget: Option<usize>)
    where
        C: FnMut() -> Result<()>,
        S: FnMut(Duration),
    {
        let mut backoff = Backoff::new();
        let mut left = budget;
        loop {
            let started = Instant::now();
            if let Err(err) = cycle() {
                eprintln!("ferrum-k8smeta: pod watch cycle failed: {err}");
            }
            // A connection that streamed for a while was healthy, whatever
            // ended it; only repeated short cycles are worth backing off from.
            if started.elapsed() >= HEALTHY_STREAM {
                backoff.reset();
            }
            sleep(backoff.take());
            if let Some(left) = left.as_mut() {
                *left -= 1;
                if *left == 0 {
                    return;
                }
            }
        }
    }

    #[derive(Debug)]
    struct Head {
        status: u16,
        chunked: bool,
        content_length: Option<usize>,
    }

    fn read_head<R: BufRead>(reader: &mut R) -> Result<Head> {
        let mut status = 0u16;
        let mut chunked = false;
        let mut content_length = None;
        let mut first = true;
        let mut seen = 0usize;
        loop {
            seen += 1;
            if seen > MAX_HEADER_LINES {
                return Err(FerrumError::Degraded(format!(
                    "apiserver sent more than {MAX_HEADER_LINES} header lines"
                )));
            }
            let mut line = String::new();
            let n = read_text_line(reader, &mut line)
                .map_err(|e| FerrumError::Degraded(format!("apiserver response: {e}")))?;
            if n == 0 {
                return Err(FerrumError::Degraded(
                    "apiserver closed before headers".into(),
                ));
            }
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            if first {
                status = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| FerrumError::Degraded(format!("bad status line {line:?}")))?;
                first = false;
                continue;
            }
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let value = value.trim();
                if name.eq_ignore_ascii_case("transfer-encoding")
                    && value.to_ascii_lowercase().contains("chunked")
                {
                    chunked = true;
                } else if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse::<usize>().ok();
                }
            }
        }
        Ok(Head {
            status,
            chunked,
            content_length,
        })
    }

    enum BodyReader<'a, R: BufRead> {
        Chunked { inner: &'a mut R, remaining: usize },
        Plain { inner: &'a mut R, remaining: usize },
    }

    impl<'a, R: BufRead> BodyReader<'a, R> {
        fn new(inner: &'a mut R, head: &Head) -> Self {
            if head.chunked {
                BodyReader::Chunked {
                    inner,
                    remaining: 0,
                }
            } else {
                BodyReader::Plain {
                    inner,
                    remaining: head.content_length.unwrap_or(usize::MAX),
                }
            }
        }
    }

    impl<R: BufRead> Read for BodyReader<'_, R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self {
                BodyReader::Plain { inner, remaining } => {
                    if *remaining == 0 {
                        return Ok(0);
                    }
                    let cap = buf.len().min(*remaining);
                    let n = inner.read(&mut buf[..cap])?;
                    *remaining -= n;
                    Ok(n)
                }
                BodyReader::Chunked { inner, remaining } => {
                    if *remaining == 0 {
                        let mut size_line = String::new();
                        if read_text_line(*inner, &mut size_line)? == 0 {
                            return Ok(0);
                        }
                        let size_text = size_line
                            .trim_end_matches(['\r', '\n'])
                            .split(';')
                            .next()
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if size_text.is_empty() {
                            return Ok(0);
                        }
                        let size = usize::from_str_radix(&size_text, 16).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, format!("chunk size: {e}"))
                        })?;
                        if size == 0 {
                            return Ok(0);
                        }
                        *remaining = size;
                    }
                    let cap = buf.len().min(*remaining);
                    let n = inner.read(&mut buf[..cap])?;
                    *remaining -= n;
                    if *remaining == 0 {
                        // Consume the CRLF that terminates the chunk.
                        let mut trailer = String::new();
                        let _ = read_text_line(*inner, &mut trailer);
                    }
                    Ok(n)
                }
            }
        }
    }

    fn read_body<R: BufRead>(reader: &mut R, head: &Head, out: &mut Vec<u8>) -> Result<()> {
        if head.content_length.is_some_and(|len| len > MAX_BODY_BYTES) {
            return Err(body_too_large());
        }
        let mut body = BodyReader::new(reader, head);
        let mut buf = [0u8; 8192];
        loop {
            let n = body
                .read(&mut buf)
                .map_err(|e| FerrumError::Degraded(format!("apiserver body: {e}")))?;
            if n == 0 {
                return Ok(());
            }
            if out.len() + n > MAX_BODY_BYTES {
                return Err(body_too_large());
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    fn body_too_large() -> FerrumError {
        FerrumError::Degraded(format!(
            "apiserver body exceeds {MAX_BODY_BYTES} bytes; refusing to buffer it"
        ))
    }

    /// Bounded `read_until`. Used for status/header lines and for chunk-size
    /// lines: all of them are short by construction, and an unbounded read here
    /// lets the peer choose our allocation size.
    fn read_text_line<R: BufRead>(reader: &mut R, out: &mut String) -> io::Result<usize> {
        let mut raw = Vec::new();
        let limit = MAX_HEADER_LINE_BYTES as u64 + 1;
        let n = reader.take(limit).read_until(b'\n', &mut raw)?;
        if n > MAX_HEADER_LINE_BYTES || (n > 0 && raw.last() != Some(&b'\n')) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("header line exceeds {MAX_HEADER_LINE_BYTES} bytes"),
            ));
        }
        out.push_str(&String::from_utf8_lossy(&raw));
        Ok(n)
    }

    /// Line reader over a body stream that is not `BufRead`.
    fn read_line<R: Read>(reader: &mut R, out: &mut Vec<u8>) -> io::Result<usize> {
        let mut byte = [0u8; 1];
        loop {
            match reader.read(&mut byte)? {
                0 => return Ok(out.len()),
                _ => {
                    if byte[0] == b'\n' {
                        return Ok(out.len() + 1);
                    }
                    out.push(byte[0]);
                    if out.len() > MAX_LINE_BYTES {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "watch frame too large",
                        ));
                    }
                }
            }
        }
    }

    fn percent_encode(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        for b in raw.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::cell::RefCell;

        fn head_of(raw: &[u8]) -> Result<Head> {
            read_head(&mut io::Cursor::new(raw.to_vec()))
        }

        fn degraded_text(err: FerrumError) -> String {
            match err {
                FerrumError::Degraded(msg) => msg,
                other => panic!("expected Degraded, got {other:?}"),
            }
        }

        /// A pod with `automountServiceAccountToken: false` projects no token,
        /// and construction used to succeed anyway: the watcher spawned, every
        /// connect authenticated as nobody, and the whole install failure
        /// showed up only as an endless backoff on a cache that never warmed.
        /// The error must name the file.
        #[test]
        fn a_config_without_a_projected_token_is_an_error_that_names_the_file() {
            let dir = std::env::temp_dir().join(format!(
                "ferrum-sa-missing-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).expect("temp dir");
            let err = ApiserverConfig::from_sa_dir("node-a".into(), "10.0.0.1".into(), 443, &dir)
                .expect_err("a directory with no token is not a usable config");
            let msg = degraded_text(err);
            assert!(
                msg.contains(&dir.join("token").display().to_string()),
                "{msg}"
            );
            assert!(msg.contains("automountServiceAccountToken"), "{msg}");

            // And the same directory once the token is there: a config, with
            // the path kept for the per-connect re-read.
            std::fs::write(dir.join("token"), b"tok").expect("write token");
            let config =
                ApiserverConfig::from_sa_dir("node-a".into(), "10.0.0.1".into(), 443, &dir)
                    .expect("a projected token is a usable config");
            assert_eq!(config.token_path, dir.join("token"));
            assert_eq!(config.node_name, "node-a");
            std::fs::remove_dir_all(&dir).ok();
        }

        #[test]
        fn ordinary_head_still_parses() {
            let head = head_of(
                b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .expect("head");
            assert_eq!(head.status, 200);
            assert_eq!(head.content_length, Some(7));
            assert!(head.chunked);
        }

        #[test]
        fn giant_header_line_is_degraded_not_buffered() {
            let mut raw = b"HTTP/1.1 200 OK\r\nX-Flood: ".to_vec();
            raw.extend(std::iter::repeat(b'A').take(MAX_HEADER_LINE_BYTES * 4));
            raw.extend_from_slice(b"\r\n\r\n");
            let msg = degraded_text(head_of(&raw).expect_err("must refuse"));
            assert!(msg.contains("header line exceeds"), "{msg}");
        }

        #[test]
        fn giant_status_line_is_degraded() {
            let mut raw = b"HTTP/1.1 200 ".to_vec();
            raw.extend(std::iter::repeat(b'X').take(MAX_HEADER_LINE_BYTES + 1));
            raw.extend_from_slice(b"\r\n\r\n");
            let msg = degraded_text(head_of(&raw).expect_err("must refuse"));
            assert!(msg.contains("header line exceeds"), "{msg}");
        }

        #[test]
        fn endless_header_count_is_degraded() {
            let mut raw = b"HTTP/1.1 200 OK\r\n".to_vec();
            for i in 0..MAX_HEADER_LINES * 2 {
                raw.extend_from_slice(format!("X-Pad-{i}: v\r\n").as_bytes());
            }
            raw.extend_from_slice(b"\r\n");
            let msg = degraded_text(head_of(&raw).expect_err("must refuse"));
            assert!(msg.contains("header lines"), "{msg}");
        }

        #[test]
        fn body_past_the_ceiling_is_degraded() {
            // Chunked, so the peer never has to declare the total up front.
            let chunk = vec![b'x'; 1 << 20];
            let mut raw = Vec::new();
            for _ in 0..(MAX_BODY_BYTES / chunk.len()) + 2 {
                raw.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                raw.extend_from_slice(&chunk);
                raw.extend_from_slice(b"\r\n");
            }
            let head = Head {
                status: 200,
                chunked: true,
                content_length: None,
            };
            let mut out = Vec::new();
            let err =
                read_body(&mut io::Cursor::new(raw), &head, &mut out).expect_err("must refuse");
            assert!(
                degraded_text(err).contains("exceeds"),
                "message names the cap"
            );
            assert!(out.len() <= MAX_BODY_BYTES, "buffer stayed under the cap");
        }

        #[test]
        fn declared_content_length_past_the_ceiling_is_refused_before_reading() {
            let head = Head {
                status: 200,
                chunked: false,
                content_length: Some(MAX_BODY_BYTES + 1),
            };
            let mut out = Vec::new();
            let err = read_body(&mut io::Cursor::new(Vec::new()), &head, &mut out)
                .expect_err("must refuse");
            assert!(degraded_text(err).contains("exceeds"));
            assert!(out.is_empty());
        }

        #[test]
        fn small_body_still_reads() {
            let head = Head {
                status: 200,
                chunked: false,
                content_length: Some(5),
            };
            let mut out = Vec::new();
            read_body(&mut io::Cursor::new(b"hello".to_vec()), &head, &mut out).expect("body");
            assert_eq!(out, b"hello");
        }

        #[test]
        fn immediate_eof_still_sleeps_between_cycles() {
            let slept: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
            // Every cycle returns Ok instantly, the EOF-on-connect case.
            watch_loop(|| Ok(()), |d| slept.borrow_mut().push(d), Some(4));
            let slept = slept.into_inner();
            assert_eq!(slept.len(), 4, "one sleep per iteration, Ok included");
            assert!(slept.iter().all(|d| *d >= RECONNECT_BACKOFF));
        }

        #[test]
        fn backoff_grows_and_is_capped() {
            let slept: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
            watch_loop(
                || Err(FerrumError::Degraded("connect refused".into())),
                |d| slept.borrow_mut().push(d),
                Some(8),
            );
            let slept = slept.into_inner();
            assert_eq!(slept[0], RECONNECT_BACKOFF);
            assert_eq!(slept[1], RECONNECT_BACKOFF * 2);
            assert_eq!(slept[2], RECONNECT_BACKOFF * 4);
            assert!(
                slept.windows(2).all(|w| w[1] >= w[0]),
                "delay never shrinks while cycles keep failing"
            );
            assert_eq!(*slept.last().expect("delays"), MAX_RECONNECT_BACKOFF);
            assert!(slept.iter().all(|d| *d <= MAX_RECONNECT_BACKOFF));
        }

        fn silent_config() -> (std::net::TcpListener, ApiserverConfig) {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listener");
            let port = listener.local_addr().expect("addr").port();
            let config = ApiserverConfig {
                host: "127.0.0.1".into(),
                port,
                server_name: "kubernetes.default.svc".into(),
                node_name: "node-a".into(),
                token_path: PathBuf::from("/nonexistent/token"),
                ca_path: PathBuf::from("/nonexistent/ca.crt"),
            };
            (listener, config)
        }

        #[test]
        fn every_dialed_socket_carries_both_deadlines() {
            let (_listener, config) = silent_config();
            let tcp = config.dial().expect("dial");
            assert_eq!(tcp.read_timeout().expect("read"), Some(IO_TIMEOUT));
            assert_eq!(tcp.write_timeout().expect("write"), Some(IO_TIMEOUT));
        }

        #[test]
        fn a_peer_that_never_answers_ends_in_an_error_not_a_hang() {
            let (_listener, config) = silent_config();
            let mut tcp = config.dial().expect("dial");
            // Same mechanism as IO_TIMEOUT, shortened so the test is not the
            // one waiting out the budget.
            tcp.set_read_timeout(Some(Duration::from_millis(50)))
                .expect("timeout");
            let mut buf = [0u8; 1];
            let err = tcp.read(&mut buf).expect_err("read must not block forever");
            assert!(
                matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "{err:?}"
            );
        }

        #[test]
        fn io_timeout_expires_well_inside_the_freshness_budget() {
            // The reconnect and relist have to happen while the cache is still
            // fresh; a timeout at or past the budget would let it go stale.
            assert!(IO_TIMEOUT < POD_WATCH_BUDGET);
            assert!(IO_TIMEOUT + CONNECT_TIMEOUT < POD_WATCH_BUDGET);
            assert!(
                IO_TIMEOUT > HEALTHY_STREAM,
                "bookmark gaps on a quiet cluster must not trip it"
            );
        }

        #[test]
        fn a_long_healthy_cycle_resets_the_backoff() {
            let mut backoff = Backoff::new();
            assert_eq!(backoff.take(), RECONNECT_BACKOFF);
            assert_eq!(backoff.take(), RECONNECT_BACKOFF * 2);
            backoff.reset();
            assert_eq!(backoff.take(), RECONNECT_BACKOFF);
            assert!(HEALTHY_STREAM > MAX_RECONNECT_BACKOFF);
        }
    }
}
