//! Namespace and ServiceAccount labels: the half of a policy selector that is
//! not on the admitted object.
//!
//! A miss here is an empty label map, never another object's labels: the
//! ServiceAccount key carries its namespace, so `default` in `prod` and
//! `default` in `dev` are different entries.

use crate::watch::WatchOutcome;
use ferrum_common::Result;
use std::collections::{BTreeMap, HashMap};

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

#[derive(Debug, Clone, Default)]
pub struct LabelCache {
    by_name: HashMap<String, BTreeMap<String, String>>,
    resource_version: String,
    /// False until a list completed. A cold cache is not "no labels", it is
    /// "not known yet", and the consumer decides what that costs.
    listed: bool,
}

impl LabelCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_warm(&self) -> bool {
        self.listed
    }

    pub fn resource_version(&self) -> &str {
        &self.resource_version
    }

    pub fn set_resource_version(&mut self, rv: impl Into<String>) {
        let rv = rv.into();
        if !rv.is_empty() {
            self.resource_version = rv;
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

    pub fn upsert(&mut self, object: LabelObject) -> bool {
        if object.name.is_empty() {
            return false;
        }
        self.by_name
            .insert(label_key(&object.namespace, &object.name), object.labels);
        true
    }

    pub fn remove(&mut self, namespace: &str, name: &str) -> bool {
        self.by_name.remove(&label_key(namespace, name)).is_some()
    }

    /// Full list result. Replaces everything and marks the cache warm.
    pub fn replace_all(&mut self, objects: Vec<LabelObject>) {
        self.by_name.clear();
        for object in objects {
            self.upsert(object);
        }
        self.listed = true;
    }
}

/// Fold one event in. DELETE drops the entry rather than leaving stale labels
/// that would keep matching a selector after the object is gone.
pub fn apply_labels_event(cache: &mut LabelCache, event: LabelWatchEvent) -> WatchOutcome {
    match event {
        LabelWatchEvent::Added(o) | LabelWatchEvent::Modified(o) => {
            if cache.upsert(o) {
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
        LabelWatchEvent::Gone(_) => WatchOutcome::MustRelist,
        LabelWatchEvent::Error(_) => WatchOutcome::Ignored,
    }
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
        outcome = apply_labels_event(cache, event);
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
        cache.replace_all(Vec::new());
        assert!(cache.is_warm(), "a completed list of zero objects is warm");
    }

    #[test]
    fn same_service_account_name_does_not_leak_across_namespaces() {
        let mut cache = LabelCache::new();
        cache.replace_all(vec![
            object("prod", "default", "zone", "pci"),
            object("dev", "default", "zone", "public"),
        ]);
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
        cache.replace_all(vec![object("", "prod", "zone", "pci")]);
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
        cache.replace_all(vec![object("", "prod", "zone", "pci")]);
        let outcome = apply_labels_event(
            &mut cache,
            LabelWatchEvent::Gone("too old resource version".into()),
        );
        assert_eq!(outcome, WatchOutcome::MustRelist);
        assert_eq!(cache.len(), 1);
    }
}
