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
    /// Listed and recently alive, but the watch owes a relist nobody has
    /// completed: objects changed unseen. Two producers, not one — `410 Gone`,
    /// and a frame the watch parser could not read — and the message names
    /// both, because an operator sent to look at watch expiry for a frame a
    /// rolling control-plane upgrade emitted finds nothing wrong there.
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
            Self::RelistPending => "label cache missed events (410 Gone, or a frame this build \
                 could not read) and has not relisted"
                .into(),
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
///
/// Every getter answers `Option`, and the distinction it carries is the whole
/// point: `None` is "this source never observed that object", `Some(map)` is
/// "it did, and these are the labels" — including `Some` of an empty map for
/// an object that carries none. Returning a bare map forced every caller to
/// re-derive the first from the second, and the only available derivation —
/// "empty means unobserved" — turned a namespace with no labels into an
/// integrity failure.
pub trait LabelSource: std::fmt::Debug + Send + Sync {
    fn namespace_labels(&self, namespace: &str) -> Option<BTreeMap<String, String>>;
    fn service_account_labels(
        &self,
        namespace: &str,
        service_account: &str,
    ) -> Option<BTreeMap<String, String>>;
    /// `None` until the operator states them. They come from `--cluster-label`,
    /// not from any watch, so there is no cache whose warmth could stand in for
    /// this: see [`ClusterLabels`].
    fn cluster_labels(&self) -> Option<BTreeMap<String, String>>;
    /// Warmth and its cause, sampled once. The only state question an
    /// implementor answers: `is_warm` is derived from it and is not a member of
    /// this trait, so the decision and the message it produces cannot disagree
    /// about which state the cache was in.
    fn warmth(&self) -> LabelWarmth;
}

/// `is_warm` for every [`LabelSource`], derived and not overridable.
///
/// As a provided method it was only a convention: an implementor could write
/// `fn is_warm(&self) -> bool { true }` beside a `warmth()` returning `Cold`
/// and the deny message would then describe a cache the decision had already
/// disagreed with. A blanket impl cannot be overridden — a second impl for a
/// concrete type overlaps and coherence rejects it — so the two are one fact.
pub trait LabelWarmthCheck {
    /// False until every backing list has completed at least once and is still
    /// fresh.
    fn is_warm(&self) -> bool;
}

impl<T: LabelSource + ?Sized> LabelWarmthCheck for T {
    fn is_warm(&self) -> bool {
        self.warmth().is_warm()
    }
}

/// Whether the operator stated cluster labels, and which.
///
/// This is the one label group with no cache behind it: MVP-1 has no cluster
/// object to read, so the labels are whatever `--cluster-label` carried and
/// their observedness is "the flag was passed". Nothing about the map itself
/// can say that — an operator who passes no flag and an operator who states a
/// cluster with no labels both leave an empty map — so it is a separate fact
/// here rather than a reading of `is_empty()`. Without it the cluster branch of
/// `require_labels_if_selected` keeps deciding by emptiness, which is exactly
/// the defect the namespace branch was fixed for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClusterLabels(Option<BTreeMap<String, String>>);

impl ClusterLabels {
    /// The flag was passed, and this is what it said — an empty map included.
    pub fn stated(labels: BTreeMap<String, String>) -> Self {
        Self(Some(labels))
    }

    /// No `--cluster-label`: a cluster selector cannot be answered, and a
    /// policy carrying one fails closed. There is deliberately no
    /// `From<BTreeMap>` beside these two: a caller holding only the parsed map
    /// would have to guess from emptiness, which is the defect this type
    /// exists to remove. Every caller knows whether the flag was there.
    pub fn unstated() -> Self {
        Self(None)
    }

    pub fn observed(&self) -> Option<&BTreeMap<String, String>> {
        self.0.as_ref()
    }
}

/// Labels a caller states up front: the `--cluster-label` flags, and whatever
/// a test wants to pretend the apiserver said. Anything but `warm()` models a
/// webhook whose watch is not answering for labels.
///
/// A namespace or ServiceAccount this was never given is `None`, not an empty
/// map: it models a cache that did not list the object, which is the fail-closed
/// case. `with_namespace(ns, BTreeMap::new())` is the other one — listed, and it
/// has no labels.
#[derive(Debug, Clone, Default)]
pub struct StaticLabels {
    cluster: ClusterLabels,
    namespaces: BTreeMap<String, BTreeMap<String, String>>,
    service_accounts: BTreeMap<(String, String), BTreeMap<String, String>>,
    warmth: LabelWarmth,
}

impl StaticLabels {
    /// Cluster labels only. Never warm: a cluster label says nothing about
    /// whether namespace labels are known.
    pub fn cluster(cluster: impl Into<ClusterLabels>) -> Self {
        Self {
            cluster: cluster.into(),
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
    fn namespace_labels(&self, namespace: &str) -> Option<BTreeMap<String, String>> {
        self.namespaces.get(namespace).cloned()
    }

    fn service_account_labels(
        &self,
        namespace: &str,
        service_account: &str,
    ) -> Option<BTreeMap<String, String>> {
        self.service_accounts
            .get(&(namespace.to_string(), service_account.to_string()))
            .cloned()
    }

    fn cluster_labels(&self) -> Option<BTreeMap<String, String>> {
        self.cluster.observed().cloned()
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
    cluster: ClusterLabels,
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
        cluster: impl Into<ClusterLabels>,
    ) -> Self {
        Self {
            namespaces,
            service_accounts,
            cluster: cluster.into(),
        }
    }
}

#[cfg(feature = "apiserver")]
impl LabelSource for WatchedLabels {
    /// `labels_of`, not `labels_or_empty`: the miss is the answer, and folding
    /// it into an empty map here is where it used to be lost.
    fn namespace_labels(&self, namespace: &str) -> Option<BTreeMap<String, String>> {
        self.namespaces
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .labels_of("", namespace)
            .cloned()
    }

    fn service_account_labels(
        &self,
        namespace: &str,
        service_account: &str,
    ) -> Option<BTreeMap<String, String>> {
        self.service_accounts
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .labels_of(namespace, service_account)
            .cloned()
    }

    fn cluster_labels(&self) -> Option<BTreeMap<String, String>> {
        self.cluster.observed().cloned()
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
        // `None`, not an empty map: this source never observed either object,
        // and a caller that cannot tell the two apart fails closed on both.
        assert_eq!(cold.namespace_labels("prod"), None);
        assert_eq!(cold.service_account_labels("prod", "web-sa"), None);
        assert_eq!(cold.cluster_labels(), None);
    }

    /// The one group with no cache behind it. Its observedness is the flag
    /// having been passed, which no map can carry, so it is stated separately —
    /// otherwise the cluster branch keeps deciding by emptiness.
    #[test]
    fn stated_cluster_labels_are_observed_even_when_there_are_none() {
        let stated = StaticLabels::cluster(ClusterLabels::stated(BTreeMap::new()));
        assert_eq!(
            stated.cluster_labels(),
            Some(BTreeMap::new()),
            "an operator who states a cluster with no labels has been heard"
        );
        let unstated = StaticLabels::cluster(ClusterLabels::unstated());
        assert_eq!(unstated.cluster_labels(), None);
    }

    #[test]
    fn cluster_labels_do_not_make_a_source_warm() {
        let labels = StaticLabels::cluster(ClusterLabels::stated(BTreeMap::from([(
            "env".to_string(),
            "prod".to_string(),
        )])));
        assert_eq!(labels.cluster_labels().expect("stated").len(), 1);
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

    /// B2: slice B gave `RelistPending` a second producer — a frame the watch
    /// parser refused — and left the message naming only the first. The deny
    /// reply is admission's only operator channel, so an operator reading it
    /// went to look at watch expiry and `--min-request-timeout` and found
    /// nothing wrong, while the actual fault's only trace was an `eprintln!`
    /// on the webhook Pod. The sibling message on `PodCache` was widened this
    /// cycle; this is the same sentence on the label side.
    #[test]
    fn relist_pending_names_both_of_the_causes_that_produce_it() {
        let message = LabelWarmth::RelistPending.reason();
        assert!(message.contains("410 Gone"), "{message}");
        assert!(
            message.contains("could not read"),
            "a frame the parser refused raises this too, and an operator sent to look at \
             resourceVersion expiry for it finds nothing: {message}"
        );
    }

    /// M4: as a provided method `is_warm` could be overridden beside a
    /// `warmth()` that disagrees with it — the invariant was a convention. It
    /// is not a member of `LabelSource` any more; the blanket impl below is the
    /// only definition there can be, and coherence is what seals it.
    #[test]
    fn warmth_is_the_only_state_answer_an_implementor_gives() {
        #[derive(Debug)]
        struct Lying;
        // The whole trait: there is no `is_warm` here to override.
        impl LabelSource for Lying {
            fn namespace_labels(&self, _: &str) -> Option<BTreeMap<String, String>> {
                None
            }
            fn service_account_labels(&self, _: &str, _: &str) -> Option<BTreeMap<String, String>> {
                None
            }
            fn cluster_labels(&self) -> Option<BTreeMap<String, String>> {
                None
            }
            fn warmth(&self) -> LabelWarmth {
                LabelWarmth::Cold
            }
        }
        let source: &dyn LabelSource = &Lying;
        assert!(!source.is_warm());
        assert_eq!(source.warmth(), LabelWarmth::Cold);
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
                source
                    .namespace_labels("prod")
                    .expect("listed")
                    .get("ferrum.io/zone"),
                Some(&"pci".to_string())
            );
            // `dev` is not in this namespace cache at all, which is a different
            // answer from a `dev` that was listed and carries no labels.
            assert_eq!(source.namespace_labels("dev"), None);
            assert_eq!(
                source
                    .service_account_labels("dev", "web-sa")
                    .expect("listed")
                    .get("ferrum.io/tier"),
                Some(&"sandbox".to_string())
            );
        }

        /// The reading that was lost: a namespace the list named without labels
        /// comes back as `Some` of an empty map, and only a namespace the list
        /// never named comes back as `None`.
        #[test]
        fn a_listed_namespace_without_labels_is_not_a_miss() {
            let mut namespaces = LabelCache::new();
            namespaces
                .try_replace_all(vec![LabelObject {
                    namespace: String::new(),
                    name: "plain".into(),
                    labels: BTreeMap::new(),
                    resource_version: "1".into(),
                }])
                .expect("list");
            let source = source(namespaces, listed());
            assert_eq!(source.namespace_labels("plain"), Some(BTreeMap::new()));
            assert_eq!(source.namespace_labels("never-listed"), None);
        }
    }
}
