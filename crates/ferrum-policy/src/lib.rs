//! Валидация инвариантов. Не интерпретатор datapath и не клиент Kubernetes.
//!
//! Запрещено добавлять: kube, reqwest, tokio, aya.

use chrono::{Duration, Utc};
use ferrum_api::{
    AdmitSpec, ClusterSecurityPolicySpec, FailurePolicy, PolicyExceptionSpec, PolicyMode,
    RuntimeAction, RuntimeSpec, SecurityPolicySpec,
};
use ferrum_common::{FerrumError, Result};

pub fn validate_cluster_policy(spec: &ClusterSecurityPolicySpec) -> Result<()> {
    validate_admit(&spec.admit)?;
    validate_runtime(&spec.runtime)?;
    if spec.disabled && spec.mode == PolicyMode::Enforce {
        return Err(FerrumError::Validation(
            "disabled=true вместе с mode=enforce: выключите политику или не притворяйтесь".into(),
        ));
    }
    Ok(())
}

pub fn validate_namespaced_policy(spec: &SecurityPolicySpec) -> Result<()> {
    validate_admit(&spec.admit)?;
    validate_runtime(&spec.runtime)?;
    if spec.admit.failure_policy == FailurePolicy::Ignore {
        return Err(FerrumError::Validation(
            "namespaced SecurityPolicy не может ставить failurePolicy=Ignore — это break-glass уровня ИБ"
                .into(),
        ));
    }
    Ok(())
}

pub fn validate_exception(spec: &PolicyExceptionSpec) -> Result<()> {
    if spec.ticket.trim().is_empty() {
        return Err(FerrumError::Validation("PolicyException.ticket пуст".into()));
    }
    if spec.reason.trim().len() < 8 {
        return Err(FerrumError::Validation(
            "reason короче восьми символов — это не обоснование, это статус в Slack".into(),
        ));
    }
    if spec.four_eyes && spec.approved_by.trim().is_empty() {
        return Err(FerrumError::Validation(
            "fourEyes=true без approvedBy".into(),
        ));
    }
    if spec.expires_at <= Utc::now() {
        return Err(FerrumError::Validation(
            "expiresAt уже в прошлом. Исключение родилось мёртвым".into(),
        ));
    }
    if spec.expires_at > Utc::now() + Duration::days(90) {
        return Err(FerrumError::Validation(
            "waiver длиннее 90 дней. Это уже не исключение, а новая политика без комитета".into(),
        ));
    }
    Ok(())
}

fn validate_admit(admit: &AdmitSpec) -> Result<()> {
    if admit.failure_policy == FailurePolicy::Ignore {
        // cluster-level Ignore валиден синтаксически; аннотацию break-glass проверяет admission.
    }
    Ok(())
}

fn validate_runtime(runtime: &RuntimeSpec) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    for rule in &runtime.rules {
        if rule.id.trim().is_empty() {
            return Err(FerrumError::Validation("runtime rule без id".into()));
        }
        if !ids.insert(rule.id.clone()) {
            return Err(FerrumError::Validation(format!(
                "дубль runtime rule id '{}'",
                rule.id
            )));
        }
        if matches!(rule.action, RuntimeAction::Kill | RuntimeAction::Isolate)
            && rule.match_on.comm_in.is_empty()
            && rule.match_on.path_prefix.is_empty()
            && rule.match_on.path_suffix.is_empty()
            && rule.syscalls.is_empty()
        {
            return Err(FerrumError::Validation(format!(
                "rule '{}' с action={:?} без match — это kill-all, не политика",
                rule.id, rule.action
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ferrum_api::{ExceptionTarget, RuntimeMatch, RuntimeRule};

    #[test]
    fn exception_requires_future_expiry() {
        let spec = PolicyExceptionSpec {
            ticket: "JIRA-1".into(),
            requested_by: "sre".into(),
            approved_by: "ib".into(),
            reason: "debug sidecar after incident".into(),
            expires_at: Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap(),
            mode: PolicyMode::Audit,
            four_eyes: true,
            target: ExceptionTarget::default(),
        };
        assert!(validate_exception(&spec).is_err());
    }

    #[test]
    fn kill_all_rejected() {
        let spec = ClusterSecurityPolicySpec {
            runtime: RuntimeSpec {
                rules: vec![RuntimeRule {
                    id: "oops".into(),
                    syscalls: vec![],
                    match_on: RuntimeMatch::default(),
                    action: RuntimeAction::Kill,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_cluster_policy(&spec).is_err());
    }
}
