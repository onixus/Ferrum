//! Where namespace / ServiceAccount / cluster labels come from.
//!
//! None of them are on the admitted object, so the webhook has to be told.
//! A cold source is not "no labels": it is "not known yet", and a policy with
//! a namespace or ServiceAccount selector denies until the cache is warm.

use std::collections::BTreeMap;
use std::time::Duration;

/// Why a [`LabelSource`] is or is not usable, in the words the deny reply
/// carries.
///
/// `is_warm()` alone answers "may I decide on these labels", which is all the
/// admit path needs — but the deny reply is the only channel this process has,
/// and "not warm" has three causes that ask an operator for three different
/// things. A cache that has never listed warms up on its own; a cache that
/// listed and then went quiet has lost its watch; a cache told it missed
/// events needs a relist nobody has completed. Naming the first for all three
/// sends every reader to look at a process that started fine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LabelWarmth {
    /// No list has completed: the first seconds of a process, and a watch that
    /// has never managed to connect.
    #[default]
    Cold,
    /// Listed once, then nothing refreshed it inside the cache's budget. The
    /// labels held are of unknown age, so a selector answered from them may
    /// already be wrong.
    Stale {
        age: Duration,
    },
    /// Listed and recently alive, but the watch reported `410 Gone` and no
    /// relist has completed: objects changed unseen.
    RelistPending,
    Warm,
}

impl LabelWarmth {
    pub fn is_warm(&self) -> bool {
        matches!(self, Self::Warm)
    }

    /// The clause the deny message carries. Never "has not listed yet" unless
    /// that is what happened.
    pub fn reason(&self) -> String {
        match self {
            Self::Cold => "label cache has not listed yet".into(),
            Self::Stale { age } => format!(
                "label cache last refreshed {}s ago, past its freshness budget",
                age.as_secs()
            ),
            Self::RelistPending => {
                "label cache missed events (410 Gone) and has not relisted".into()
            }
            Self::Warm => "label cache is warm".into(),
        }
    }

    /// The worse of two answers, for a source backed by more than one cache:
    /// never-listed beats owes-a-relist beats stale beats warm, and of two
    /// stale caches the older is the one worth naming.
    pub fn worse_of(self, other: Self) -> Self {
        match (self.rank(), other.rank()) {
            (a, b) if a < b => self,
            (a, b) if a > b => other,
            _ => match (self, other) {
                (Self::Stale { age: a }, Self::Stale { age: b }) if b > a => other,
                _ => self,
            },
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Cold => 0,
            Self::RelistPending => 1,
            Self::Stale { .. } => 2,
            Self::Warm => 3,
        }
    }
}

/// Injected into [`crate::ReviewConfig`]. Implementations must be cheap: this
/// is called on the admit hot path, once per request.
pub trait LabelSource: std::fmt::Debug + Send + Sync {
    fn namespace_labels(&self, namespace: &str) -> BTreeMap<String, String>;
    fn service_account_labels(
        &self,
        namespace: &str,
        service_account: &str,
    ) -> BTreeMap<String, String>;
    fn cluster_labels(&self) -> BTreeMap<String, String>;
    /// Warmth and its cause, sampled once. Implementations answer this one and
    /// inherit `is_warm`, so the decision and the message it produces cannot
    /// disagree about which state the cache was in.
    fn warmth(&self) -> LabelWarmth;
    /// False until every backing list has completed at least once and is still
    /// fresh.
    fn is_warm(&self) -> bool {
        self.warmth().is_warm()
    }
}

/// Labels a caller states up front: the `--cluster-label` flags, and whatever
/// a test wants to pretend the apiserver said. Anything but `warm()` models a
/// webhook whose watch is not answering for labels.
#[derive(Debug, Clone, Default)]
pub struct StaticLabels {
    cluster: BTreeMap<String, String>,
    namespaces: BTreeMap<String, BTreeMap<String, String>>,
    service_accounts: BTreeMap<(String, String), BTreeMap<String, String>>,
    warmth: LabelWarmth,
}

impl StaticLabels {
    /// Cluster labels only. Never warm: a cluster label says nothing about
    /// whether namespace labels are known.
    pub fn cluster(cluster: BTreeMap<String, String>) -> Self {
        Self {
            cluster,
            ..Default::default()
        }
    }

    pub fn warm(mut self) -> Self {
        self.warmth = LabelWarmth::Warm;
        self
    }

    /// Listed, then left unrefreshed for `age`.
    pub fn stale(mut self, age: Duration) -> Self {
        self.warmth = LabelWarmth::Stale { age };
        self
    }

    /// Listed and alive, but owing a relist after `410 Gone`.
    pub fn relist_pending(mut self) -> Self {
        self.warmth = LabelWarmth::RelistPending;
        self
    }

    pub fn with_namespace(
        mut self,
        namespace: impl Into<String>,
        labels: BTreeMap<String, String>,
    ) -> Self {
        self.namespaces.insert(namespace.into(), labels);
        self
    }

    pub fn with_service_account(
        mut self,
        namespace: impl Into<String>,
        service_account: impl Into<String>,
        labels: BTreeMap<String, String>,
    ) -> Self {
        self.service_accounts
            .insert((namespace.into(), service_account.into()), labels);
        self
    }
}

impl LabelSource for StaticLabels {
    fn namespace_labels(&self, namespace: &str) -> BTreeMap<String, String> {
        self.namespaces.get(namespace).cloned().unwrap_or_default()
    }

    fn service_account_labels(
        &self,
        namespace: &str,
        service_account: &str,
    ) -> BTreeMap<String, String> {
        self.service_accounts
            .get(&(namespace.to_string(), service_account.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    fn cluster_labels(&self) -> BTreeMap<String, String> {
        self.cluster.clone()
    }

    fn warmth(&self) -> LabelWarmth {
        self.warmth
    }
}

/// The default: nothing is known, so any policy with a namespace or
/// ServiceAccount selector denies.
pub type ColdLabels = StaticLabels;

/// Live Namespace/ServiceAccount labels from a `ferrum-k8smeta` watch, plus
/// the static cluster labels. Warm only once both lists have completed.
#[cfg(feature = "apiserver")]
#[derive(Debug)]
pub struct WatchedLabels {
    namespaces: std::sync::Arc<std::sync::RwLock<ferrum_k8smeta::LabelCache>>,
    service_accounts: std::sync::Arc<std::sync::RwLock<ferrum_k8smeta::LabelCache>>,
    cluster: BTreeMap<String, String>,
}

/// Restate one cache's state as a cause. `is_warm_at`, `is_stale_at`,
/// `relist_pending` and `age_at` are asked at a single instant so the four
/// cannot describe different moments of the same request.
#[cfg(feature = "apiserver")]
fn cache_warmth(cache: &ferrum_k8smeta::LabelCache, now: std::time::Instant) -> LabelWarmth {
    if cache.is_warm_at(now) {
        LabelWarmth::Warm
    } else if !cache.is_stale_at(now) {
        // Stale is "listed and not warm", so not-warm and not-stale is
        // not-listed. There is no `listed()` accessor and this crate may not
        // add one.
        LabelWarmth::Cold
    } else if cache.relist_pending() {
        LabelWarmth::RelistPending
    } else {
        LabelWarmth::Stale {
            age: cache.age_at(now).unwrap_or_default(),
        }
    }
}

#[cfg(feature = "apiserver")]
impl WatchedLabels {
    pub fn new(
        namespaces: std::sync::Arc<std::sync::RwLock<ferrum_k8smeta::LabelCache>>,
        service_accounts: std::sync::Arc<std::sync::RwLock<ferrum_k8smeta::LabelCache>>,
        cluster: BTreeMap<String, String>,
    ) -> Self {
        Self {
            namespaces,
            service_accounts,
            cluster,
        }
    }
}

#[cfg(feature = "apiserver")]
impl LabelSource for WatchedLabels {
    fn namespace_labels(&self, namespace: &str) -> BTreeMap<String, String> {
        self.namespaces
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .labels_or_empty("", namespace)
    }

    fn service_account_labels(
        &self,
        namespace: &str,
        service_account: &str,
    ) -> BTreeMap<String, String> {
        self.service_accounts
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .labels_or_empty(namespace, service_account)
    }

    fn cluster_labels(&self) -> BTreeMap<String, String> {
        self.cluster.clone()
    }

    fn warmth(&self) -> LabelWarmth {
        let now = std::time::Instant::now();
        let namespaces = cache_warmth(
            &self.namespaces.read().unwrap_or_else(|e| e.into_inner()),
            now,
        );
        let service_accounts = cache_warmth(
            &self
                .service_accounts
                .read()
                .unwrap_or_else(|e| e.into_inner()),
            now,
        );
        namespaces.worse_of(service_accounts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_source_reports_no_labels_and_no_warmth() {
        let cold = ColdLabels::default();
        assert!(!cold.is_warm());
        assert_eq!(cold.warmth(), LabelWarmth::Cold);
        assert!(cold.namespace_labels("prod").is_empty());
        assert!(cold.service_account_labels("prod", "web-sa").is_empty());
    }

    #[test]
    fn cluster_labels_do_not_make_a_source_warm() {
        let labels = StaticLabels::cluster([("env".to_string(), "prod".to_string())].into());
        assert_eq!(labels.cluster_labels().len(), 1);
        assert!(
            !labels.is_warm(),
            "cluster flags say nothing about namespaces"
        );
    }

    #[test]
    fn every_not_warm_cause_reads_differently() {
        let cold = LabelWarmth::Cold.reason();
        let stale = LabelWarmth::Stale {
            age: Duration::from_secs(7_200),
        }
        .reason();
        let relist = LabelWarmth::RelistPending.reason();
        assert!(cold.contains("has not listed yet"), "{cold}");
        assert!(stale.contains("7200s"), "{stale}");
        assert!(relist.contains("410 Gone"), "{relist}");
        assert_ne!(cold, stale);
        assert_ne!(cold, relist);
        assert_ne!(stale, relist);
        // A stale cache must never be described as one that never listed.
        assert!(!stale.contains("has not listed yet"), "{stale}");
        assert!(!relist.contains("has not listed yet"), "{relist}");
    }

    #[test]
    fn worse_of_prefers_the_cause_that_needs_the_most_help() {
        use LabelWarmth::{Cold, RelistPending, Stale, Warm};
        let old = Stale {
            age: Duration::from_secs(9_000),
        };
        let older = Stale {
            age: Duration::from_secs(90_000),
        };
        assert_eq!(Cold.worse_of(Warm), Cold);
        assert_eq!(Warm.worse_of(Cold), Cold);
        assert_eq!(RelistPending.worse_of(old), RelistPending);
        assert_eq!(old.worse_of(Warm), old);
        assert_eq!(old.worse_of(older), older);
        assert_eq!(older.worse_of(old), older);
        assert_eq!(Warm.worse_of(Warm), Warm);
    }

    #[cfg(feature = "apiserver")]
    mod watched {
        use super::*;
        use ferrum_k8smeta::{LabelCache, LabelObject};
        use std::sync::{Arc, RwLock};
        use std::time::Instant;

        fn ns(name: &str, key: &str, value: &str) -> LabelObject {
            LabelObject {
                namespace: String::new(),
                name: name.to_string(),
                labels: [(key.to_string(), value.to_string())].into(),
                resource_version: "1".into(),
            }
        }

        fn listed() -> LabelCache {
            let mut cache = LabelCache::new();
            cache
                .try_replace_all(vec![ns("prod", "ferrum.io/zone", "pci")])
                .expect("list");
            cache
        }

        fn source(namespaces: LabelCache, service_accounts: LabelCache) -> WatchedLabels {
            WatchedLabels::new(
                Arc::new(RwLock::new(namespaces)),
                Arc::new(RwLock::new(service_accounts)),
                BTreeMap::new(),
            )
        }

        #[test]
        fn both_lists_must_complete_before_warm() {
            let half = source(listed(), LabelCache::new());
            assert!(!half.is_warm());
            assert_eq!(
                half.warmth(),
                LabelWarmth::Cold,
                "a ServiceAccount cache that never listed is cold, not stale"
            );
            let other_half = source(LabelCache::new(), listed());
            assert_eq!(other_half.warmth(), LabelWarmth::Cold);
            let both = source(listed(), listed());
            assert_eq!(both.warmth(), LabelWarmth::Warm);
            assert!(both.is_warm());
        }

        #[test]
        fn a_cache_past_its_budget_is_stale_with_an_age_not_cold() {
            let mut namespaces = listed();
            namespaces.set_max_age(std::time::Duration::from_secs(60));
            namespaces.mark_fresh_at(Instant::now() - std::time::Duration::from_secs(3_600));
            let source = source(namespaces, listed());
            assert!(!source.is_warm());
            match source.warmth() {
                LabelWarmth::Stale { age } => {
                    assert!(age.as_secs() >= 3_600, "age carried through: {age:?}");
                }
                other => panic!("expected Stale, got {other:?}"),
            }
        }

        #[test]
        fn a_cache_owing_a_relist_is_not_stale_by_age() {
            let mut namespaces = listed();
            namespaces.raise_relist_pending();
            let source = source(namespaces, listed());
            assert!(!source.is_warm());
            assert_eq!(
                source.warmth(),
                LabelWarmth::RelistPending,
                "410 Gone on a freshly listed cache is not an age problem"
            );
        }

        #[test]
        fn labels_do_not_cross_namespaces() {
            let mut service_accounts = LabelCache::new();
            service_accounts
                .try_replace_all(vec![
                    LabelObject {
                        namespace: "prod".into(),
                        name: "web-sa".into(),
                        labels: [("ferrum.io/tier".to_string(), "frontend".to_string())].into(),
                        resource_version: "1".into(),
                    },
                    LabelObject {
                        namespace: "dev".into(),
                        name: "web-sa".into(),
                        labels: [("ferrum.io/tier".to_string(), "sandbox".to_string())].into(),
                        resource_version: "1".into(),
                    },
                ])
                .expect("list");
            let source = source(listed(), service_accounts);
            assert_eq!(
                source.namespace_labels("prod").get("ferrum.io/zone"),
                Some(&"pci".to_string())
            );
            assert!(source.namespace_labels("dev").is_empty());
            assert_eq!(
                source
                    .service_account_labels("dev", "web-sa")
                    .get("ferrum.io/tier"),
                Some(&"sandbox".to_string())
            );
        }
    }
}
