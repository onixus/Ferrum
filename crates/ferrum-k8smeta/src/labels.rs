//! Namespace and ServiceAccount labels: the half of a policy selector that is
//! not on the admitted object.
//!
//! A miss here is an empty label map, never another object's labels: the
//! ServiceAccount key carries its namespace, so `default` in `prod` and
//! `default` in `dev` are different entries.

use crate::watch::WatchOutcome;
use ferrum_common::{FerrumError, Result};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

/// Entry ceiling for one cache. The Namespaces and ServiceAccounts of a real
/// cluster stay far below this; a stream that keeps inventing names is broken
/// or hostile, and this crate does not hold an unbounded map for it.
pub const MAX_LABEL_ENTRIES: usize = 20_000;
/// Label bytes (keys plus values) of a single object. Kubernetes caps a label
/// value at 63 characters and a key at 317, so even a heavily labelled object
/// stays in the low kilobytes.
pub const MAX_OBJECT_LABEL_BYTES: usize = 8 * 1024;
/// Label bytes held by one cache. The entry and per-object ceilings alone
/// multiply out well past the webhook's memory limit, so the total is what
/// actually bounds the heap.
pub const MAX_TOTAL_LABEL_BYTES: usize = 16 * 1024 * 1024;
/// How long a listed cache may go without a list, bookmark or event before it
/// stops calling itself warm. Same budget AGENTS.md allows for a control plane
/// that is down: past it the consumer degrades instead of deciding on labels
/// of unknown age.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(2 * 60 * 60);

fn label_bytes(labels: &BTreeMap<String, String>) -> usize {
    labels.iter().map(|(k, v)| k.len() + v.len()).sum()
}

/// One `Namespace` or `ServiceAccount` reduced to what a selector needs.
/// `namespace` is empty for cluster-scoped kinds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LabelObject {
    pub namespace: String,
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub resource_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelWatchEvent {
    Added(LabelObject),
    Modified(LabelObject),
    Deleted(LabelObject),
    Bookmark(String),
    /// `410 Gone` in-band: the caller must relist, not resume.
    Gone(String),
    Error(String),
}

/// Cache key. Namespaced objects are keyed by both parts so a name cannot leak
/// across namespaces.
pub fn label_key(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}/{name}")
    }
}

#[derive(Debug, Clone)]
pub struct LabelCache {
    by_name: HashMap<String, BTreeMap<String, String>>,
    resource_version: String,
    /// False until a list completed. A cold cache is not "no labels", it is
    /// "not known yet", and the consumer decides what that costs.
    listed: bool,
    /// Last evidence the stream was alive: a list, a bookmark, or an event.
    /// Without it a latched `listed` reports warm through an outage of any
    /// length.
    fresh_at: Option<Instant>,
    max_age: Duration,
    label_bytes: usize,
    /// Why the last write was refused, kept so a caller that only sees the
    /// cache can tell a refusal from an empty result.
    overflow: Option<String>,
    /// A relist the watch demanded and nobody has completed yet. Liveness and
    /// completeness are different facts: `410 Gone` proves the stream is alive
    /// *and* that objects changed unseen, so the labels held may already
    /// answer a selector wrongly.
    relist_pending: bool,
}

impl Default for LabelCache {
    fn default() -> Self {
        Self {
            by_name: HashMap::new(),
            resource_version: String::new(),
            listed: false,
            fresh_at: None,
            max_age: DEFAULT_MAX_AGE,
            label_bytes: 0,
            overflow: None,
            relist_pending: false,
        }
    }
}

impl LabelCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Warm means listed, refreshed within [`LabelCache::max_age`] *and* not
    /// owing a relist: a cache nobody has managed to refresh, and a cache told
    /// it missed events, are both not warm.
    pub fn is_warm(&self) -> bool {
        self.is_warm_at(Instant::now())
    }

    pub fn is_warm_at(&self, now: Instant) -> bool {
        self.listed
            && !self.relist_pending
            && self.age_at(now).is_some_and(|age| age <= self.max_age)
    }

    /// The watch owes a relist that has not completed — `410 Gone`, or a frame
    /// the parser could not read. Until it does, the cache is not warm however
    /// recently the stream spoke.
    pub fn relist_pending(&self) -> bool {
        self.relist_pending
    }

    /// Raise the obligation. There is deliberately no public way to lower it:
    /// only a completed [`LabelCache::try_replace_all`] discharges it.
    pub fn raise_relist_pending(&mut self) {
        self.relist_pending = true;
    }

    /// Time since the last list, bookmark or event. `None` while cold.
    pub fn age(&self) -> Option<Duration> {
        self.age_at(Instant::now())
    }

    pub fn age_at(&self, now: Instant) -> Option<Duration> {
        self.fresh_at.map(|at| now.saturating_duration_since(at))
    }

    /// Listed once, but past its budget: the labels are of unknown age.
    pub fn is_stale(&self) -> bool {
        self.is_stale_at(Instant::now())
    }

    pub fn is_stale_at(&self, now: Instant) -> bool {
        self.listed && !self.is_warm_at(now)
    }

    pub fn max_age(&self) -> Duration {
        self.max_age
    }

    pub fn set_max_age(&mut self, max_age: Duration) {
        self.max_age = max_age;
    }

    /// Place the last refresh at an explicit instant, so a caller (or a test)
    /// can age a cache without waiting for it.
    pub fn mark_fresh_at(&mut self, at: Instant) {
        self.fresh_at = Some(at);
    }

    pub fn label_bytes(&self) -> usize {
        self.label_bytes
    }

    /// Reason the last write was refused, if any.
    pub fn overflow(&self) -> Option<&str> {
        self.overflow.as_deref()
    }

    pub fn take_overflow(&mut self) -> Option<String> {
        self.overflow.take()
    }

    pub fn resource_version(&self) -> &str {
        &self.resource_version
    }

    pub fn set_resource_version(&mut self, rv: impl Into<String>) {
        let rv = rv.into();
        if !rv.is_empty() {
            self.resource_version = rv;
            // An advancing resourceVersion is the stream saying it is alive.
            self.fresh_at = Some(Instant::now());
        }
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    pub fn labels_of(&self, namespace: &str, name: &str) -> Option<&BTreeMap<String, String>> {
        self.by_name.get(&label_key(namespace, name))
    }

    /// Labels or an empty map. The caller cannot tell a miss from an unlabelled
    /// object here; use [`LabelCache::labels_of`] when that matters.
    pub fn labels_or_empty(&self, namespace: &str, name: &str) -> BTreeMap<String, String> {
        self.labels_of(namespace, name).cloned().unwrap_or_default()
    }

    /// Insert or replace. False when the object is unusable or does not fit
    /// the ceilings; [`LabelCache::overflow`] then carries the reason.
    pub fn upsert(&mut self, object: LabelObject) -> bool {
        self.try_upsert(object).unwrap_or(false)
    }

    /// Same, but a breached ceiling is `Degraded` instead of a quiet `false`:
    /// the stream that caused it has to be dropped and relisted, and a
    /// truncated map would answer selectors as if the labels did not exist.
    pub fn try_upsert(&mut self, object: LabelObject) -> Result<bool> {
        if object.name.is_empty() {
            return Ok(false);
        }
        let key = label_key(&object.namespace, &object.name);
        let incoming = label_bytes(&object.labels);
        if incoming > MAX_OBJECT_LABEL_BYTES {
            return Err(self.refuse(format!(
                "labels of {key} are {incoming} bytes, past the \
                 {MAX_OBJECT_LABEL_BYTES}-byte per-object ceiling"
            )));
        }
        let replaced = match self.by_name.get(&key) {
            Some(existing) => label_bytes(existing),
            None if self.by_name.len() >= MAX_LABEL_ENTRIES => {
                return Err(self.refuse(format!(
                    "cache already holds {MAX_LABEL_ENTRIES} objects; refusing to grow for {key}"
                )));
            }
            None => 0,
        };
        let total = self.label_bytes - replaced + incoming;
        if total > MAX_TOTAL_LABEL_BYTES {
            return Err(self.refuse(format!(
                "label bytes would reach {total} at {key}, past the \
                 {MAX_TOTAL_LABEL_BYTES}-byte ceiling"
            )));
        }
        self.by_name.insert(key, object.labels);
        self.label_bytes = total;
        Ok(true)
    }

    fn refuse(&mut self, reason: String) -> FerrumError {
        self.overflow = Some(reason.clone());
        FerrumError::Degraded(format!("label cache: {reason}"))
    }

    pub fn remove(&mut self, namespace: &str, name: &str) -> bool {
        match self.by_name.remove(&label_key(namespace, name)) {
            Some(labels) => {
                self.label_bytes = self.label_bytes.saturating_sub(label_bytes(&labels));
                true
            }
            None => false,
        }
    }

    /// A list that does not fit leaves the cache empty and cold rather than
    /// half applied: a partial map answers selectors with labels the object
    /// does not have, and cold is the state consumers already fail closed on.
    pub fn try_replace_all(&mut self, objects: Vec<LabelObject>) -> Result<()> {
        self.clear();
        for object in objects {
            if let Err(err) = self.try_upsert(object) {
                self.clear();
                return Err(err);
            }
        }
        self.listed = true;
        self.fresh_at = Some(Instant::now());
        // Only a completed list discharges the obligation; a refused one
        // above leaves it standing.
        self.relist_pending = false;
        Ok(())
    }

    fn clear(&mut self) {
        self.by_name.clear();
        self.label_bytes = 0;
        self.listed = false;
        self.fresh_at = None;
    }
}

/// Fold one event in. DELETE drops the entry rather than leaving stale labels
/// that would keep matching a selector after the object is gone.
pub fn apply_labels_event(cache: &mut LabelCache, event: LabelWatchEvent) -> WatchOutcome {
    try_apply_labels_event(cache, event).unwrap_or(WatchOutcome::Ignored)
}

/// Same, but an event the cache refuses to hold is `Degraded`: the stream feeding
/// it has to end and relist instead of quietly dropping objects on the floor.
pub fn try_apply_labels_event(
    cache: &mut LabelCache,
    event: LabelWatchEvent,
) -> Result<WatchOutcome> {
    Ok(match event {
        LabelWatchEvent::Added(o) | LabelWatchEvent::Modified(o) => {
            if cache.try_upsert(o)? {
                WatchOutcome::Applied
            } else {
                WatchOutcome::Ignored
            }
        }
        LabelWatchEvent::Deleted(o) => {
            cache.remove(&o.namespace, &o.name);
            WatchOutcome::Removed
        }
        LabelWatchEvent::Bookmark(rv) => {
            cache.set_resource_version(rv);
            WatchOutcome::Ignored
        }
        LabelWatchEvent::Gone(_) => {
            cache.raise_relist_pending();
            WatchOutcome::MustRelist
        }
        LabelWatchEvent::Error(_) => WatchOutcome::Ignored,
    })
}

/// Feed a recorded stream (one JSON object per line). Stops at the first event
/// demanding a relist and reports it.
pub fn apply_labels_stream(cache: &mut LabelCache, body: &[u8]) -> Result<WatchOutcome> {
    let mut outcome = WatchOutcome::Ignored;
    for line in body.split(|b| *b == b'\n') {
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let event = crate::watch::parse_labels_watch_event(line)?;
        if let Some(rv) = label_event_resource_version(&event) {
            cache.set_resource_version(rv);
        }
        outcome = try_apply_labels_event(cache, event)?;
        if outcome == WatchOutcome::MustRelist {
            return Ok(outcome);
        }
    }
    Ok(outcome)
}

pub(crate) fn label_event_resource_version(event: &LabelWatchEvent) -> Option<String> {
    match event {
        LabelWatchEvent::Bookmark(rv) => Some(rv.clone()),
        LabelWatchEvent::Added(o) | LabelWatchEvent::Modified(o) | LabelWatchEvent::Deleted(o) => {
            Some(o.resource_version.clone()).filter(|s| !s.is_empty())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(namespace: &str, name: &str, key: &str, value: &str) -> LabelObject {
        LabelObject {
            namespace: namespace.into(),
            name: name.into(),
            labels: [(key.to_string(), value.to_string())].into_iter().collect(),
            resource_version: "7".into(),
        }
    }

    #[test]
    fn cold_cache_is_not_an_empty_cluster() {
        let mut cache = LabelCache::new();
        assert!(!cache.is_warm());
        cache.try_replace_all(Vec::new()).expect("list fits");
        assert!(cache.is_warm(), "a completed list of zero objects is warm");
    }

    #[test]
    fn same_service_account_name_does_not_leak_across_namespaces() {
        let mut cache = LabelCache::new();
        cache
            .try_replace_all(vec![
                object("prod", "default", "zone", "pci"),
                object("dev", "default", "zone", "public"),
            ])
            .expect("list fits");
        assert_eq!(
            cache.labels_or_empty("prod", "default").get("zone"),
            Some(&"pci".to_string())
        );
        assert_eq!(
            cache.labels_or_empty("dev", "default").get("zone"),
            Some(&"public".to_string())
        );
        assert!(cache.labels_of("staging", "default").is_none());
    }

    #[test]
    fn delete_drops_labels_instead_of_keeping_stale_ones() {
        let mut cache = LabelCache::new();
        cache
            .try_replace_all(vec![object("", "prod", "zone", "pci")])
            .expect("list fits");
        let outcome = apply_labels_event(
            &mut cache,
            LabelWatchEvent::Deleted(object("", "prod", "zone", "pci")),
        );
        assert_eq!(outcome, WatchOutcome::Removed);
        assert!(cache.labels_of("", "prod").is_none());
        assert!(cache.labels_or_empty("", "prod").is_empty());
    }

    #[test]
    fn gone_demands_a_relist_and_keeps_the_cache() {
        let mut cache = LabelCache::new();
        cache
            .try_replace_all(vec![object("", "prod", "zone", "pci")])
            .expect("list fits");
        let outcome = apply_labels_event(
            &mut cache,
            LabelWatchEvent::Gone("too old resource version".into()),
        );
        assert_eq!(outcome, WatchOutcome::MustRelist);
        assert_eq!(cache.len(), 1);
        // Kept, but no longer warm: the stream said we missed changes, and
        // only a completed list can say what they were.
        assert!(cache.relist_pending());
        assert!(!cache.is_warm());
        assert!(cache.is_stale(), "listed once, of unknown correctness");
        cache
            .try_replace_all(vec![object("", "prod", "zone", "public")])
            .expect("list fits");
        assert!(!cache.relist_pending());
        assert!(cache.is_warm());
    }

    #[test]
    fn a_failed_relist_leaves_the_debt_standing() {
        let mut cache = LabelCache::new();
        cache
            .try_replace_all(vec![object("", "prod", "zone", "pci")])
            .expect("list fits");
        apply_labels_event(&mut cache, LabelWatchEvent::Gone("expired".into()));
        let mut fat = object("", "dev", "zone", "public");
        fat.labels
            .insert("bloat".into(), "x".repeat(MAX_OBJECT_LABEL_BYTES));
        cache.try_replace_all(vec![fat]).expect_err("must refuse");
        assert!(
            cache.relist_pending(),
            "a refused list did not close the gap"
        );
        assert!(!cache.is_warm());
    }

    fn degraded(err: ferrum_common::FerrumError) -> String {
        match err {
            FerrumError::Degraded(msg) => msg,
            other => panic!("expected Degraded, got {other:?}"),
        }
    }

    fn fill(cache: &mut LabelCache, count: usize) {
        let objects = (0..count)
            .map(|i| object("", &format!("ns-{i}"), "zone", "pci"))
            .collect();
        cache.try_replace_all(objects).expect("fits");
    }

    #[test]
    fn a_stream_past_the_entry_ceiling_is_degraded_not_unbounded_growth() {
        let mut cache = LabelCache::new();
        fill(&mut cache, MAX_LABEL_ENTRIES);
        let err = try_apply_labels_event(
            &mut cache,
            LabelWatchEvent::Added(object("", "one-too-many", "zone", "pci")),
        )
        .expect_err("must refuse");
        assert!(degraded(err).contains(&MAX_LABEL_ENTRIES.to_string()));
        assert_eq!(cache.len(), MAX_LABEL_ENTRIES, "the map did not grow");
        assert!(cache.labels_of("", "one-too-many").is_none());
        assert!(cache.overflow().is_some_and(|r| r.contains("one-too-many")));
        // A known object still updates in place: the ceiling is on growth.
        try_apply_labels_event(
            &mut cache,
            LabelWatchEvent::Modified(object("", "ns-0", "zone", "public")),
        )
        .expect("replacing an existing entry is not growth");
        assert_eq!(
            cache.labels_or_empty("", "ns-0").get("zone"),
            Some(&"public".to_string())
        );
    }

    #[test]
    fn one_object_past_the_label_byte_ceiling_is_degraded() {
        let mut cache = LabelCache::new();
        let mut fat = object("", "prod", "zone", "pci");
        fat.labels
            .insert("bloat".into(), "x".repeat(MAX_OBJECT_LABEL_BYTES));
        let err = try_apply_labels_event(&mut cache, LabelWatchEvent::Added(fat.clone()))
            .expect_err("must refuse");
        let msg = degraded(err);
        assert!(msg.contains("per-object"), "{msg}");
        assert!(cache.labels_of("", "prod").is_none());
        assert_eq!(cache.label_bytes(), 0);
        // The same object in a list leaves the cache cold, never half applied.
        let mut cache = LabelCache::new();
        cache
            .try_replace_all(vec![object("", "dev", "zone", "public"), fat])
            .expect_err("must refuse");
        assert!(!cache.is_warm(), "a refused list is cold, not partial");
        assert!(cache.is_empty());
    }

    #[test]
    fn label_bytes_shrink_again_on_replace_and_delete() {
        let mut cache = LabelCache::new();
        let mut wide = object("", "prod", "zone", "pci");
        wide.labels.insert("pad".into(), "y".repeat(1024));
        cache.try_replace_all(vec![wide]).expect("fits");
        assert!(cache.label_bytes() > 1024);
        cache
            .try_upsert(object("", "prod", "zone", "pci"))
            .expect("fits");
        assert_eq!(cache.label_bytes(), "zone".len() + "pci".len());
        cache.remove("", "prod");
        assert_eq!(cache.label_bytes(), 0);
    }

    #[test]
    fn a_cache_nobody_refreshed_stops_reporting_warm() {
        let mut cache = LabelCache::new();
        cache
            .try_replace_all(vec![object("", "prod", "zone", "pci")])
            .expect("list fits");
        assert!(cache.is_warm());
        assert!(cache.age().expect("listed") < Duration::from_secs(60));

        // Time is injected as the instant we ask about, so no test sleeps.
        let later = Instant::now() + cache.max_age() + Duration::from_secs(1);
        assert!(
            !cache.is_warm_at(later),
            "past the budget the cache is not warm"
        );
        assert!(cache.is_stale_at(later));
        assert!(cache.age_at(later).expect("listed") > cache.max_age());
        assert!(cache.is_warm_at(Instant::now() + Duration::from_secs(1)));
        // Stale is not empty: the labels stay for anyone willing to say so.
        assert_eq!(
            cache.labels_or_empty("", "prod").get("zone"),
            Some(&"pci".to_string())
        );

        // A bookmark at that moment refreshes it without a relist.
        cache.mark_fresh_at(later);
        assert!(cache.is_warm_at(later + Duration::from_secs(1)));
        assert!(!cache.is_stale_at(later + Duration::from_secs(1)));
    }

    #[test]
    fn a_bookmark_counts_as_liveness() {
        let mut cache = LabelCache::new();
        assert!(cache.age().is_none(), "nothing has proven the stream alive");
        cache.set_resource_version("42");
        assert!(cache.age().is_some(), "an advancing rv is liveness");
        assert!(!cache.is_warm(), "liveness alone is not a completed list");
    }

    #[test]
    fn the_freshness_budget_is_the_control_plane_down_budget() {
        let cache = LabelCache::new();
        assert_eq!(cache.max_age(), DEFAULT_MAX_AGE);
        assert_eq!(DEFAULT_MAX_AGE, Duration::from_secs(2 * 60 * 60));
        assert!(!cache.is_warm(), "cold cache has no age to compare");
        assert!(!cache.is_stale(), "cold is not stale, it is unknown");
    }

    #[test]
    fn a_shorter_budget_expires_sooner() {
        let mut cache = LabelCache::new();
        cache.set_max_age(Duration::from_secs(30));
        cache
            .try_replace_all(vec![object("", "prod", "zone", "pci")])
            .expect("list fits");
        let t0 = Instant::now();
        cache.mark_fresh_at(t0);
        assert!(cache.is_warm_at(t0 + Duration::from_secs(29)));
        assert!(!cache.is_warm_at(t0 + Duration::from_secs(31)));
    }
}
