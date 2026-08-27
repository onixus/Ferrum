//! Where namespace / ServiceAccount / cluster labels come from.
//!
//! None of them are on the admitted object, so the webhook has to be told.
//! A cold source is not "no labels": it is "not known yet", and a policy with
//! a namespace or ServiceAccount selector denies until the cache is warm.

use std::collections::BTreeMap;

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
    /// False until every backing list has completed at least once.
    fn is_warm(&self) -> bool;
}

/// Labels a caller states up front: the `--cluster-label` flags, and whatever
/// a test wants to pretend the apiserver said. `warm = false` models a webhook
/// that has not finished its first list.
#[derive(Debug, Clone, Default)]
pub struct StaticLabels {
    cluster: BTreeMap<String, String>,
    namespaces: BTreeMap<String, BTreeMap<String, String>>,
    service_accounts: BTreeMap<(String, String), BTreeMap<String, String>>,
    warm: bool,
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
        self.warm = true;
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

    fn is_warm(&self) -> bool {
        self.warm
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

    fn is_warm(&self) -> bool {
        self.namespaces
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_warm()
            && self
                .service_accounts
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .is_warm()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_source_reports_no_labels_and_no_warmth() {
        let cold = ColdLabels::default();
        assert!(!cold.is_warm());
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
}
