//! Валидация инвариантов. Не интерпретатор datapath и не клиент Kubernetes.
//!
//! Запрещено добавлять: kube, reqwest, tokio, aya.

mod eval;

use chrono::{Days, Utc};
use ferrum_api::{
    AdmitSpec, ClusterSecurityPolicySpec, FailurePolicy, PolicyExceptionSpec, PolicyMode,
    RuntimeAction, RuntimeSpec, SecurityPolicySpec, SupplySpec,
};
use ferrum_common::{FerrumError, Result};

pub use eval::{evaluate, exception_applies, RuleHit};

pub(crate) const MIN_REASON_LEN: usize = 8;
pub(crate) const MAX_EXCEPTION_DAYS: u64 = 90;

pub fn validate_cluster_policy(spec: &ClusterSecurityPolicySpec) -> Result<()> {
    validate_common(
        spec.mode,
        spec.disabled,
        &spec.supply,
        &spec.admit,
        &spec.runtime,
    )
}

pub fn validate_namespaced_policy(spec: &SecurityPolicySpec) -> Result<()> {
    validate_common(
        spec.mode,
        spec.disabled,
        &spec.supply,
        &spec.admit,
        &spec.runtime,
    )?;
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
        return Err(FerrumError::Validation(
            "PolicyException.ticket пуст".into(),
        ));
    }
    if spec.reason.trim().len() < MIN_REASON_LEN {
        return Err(FerrumError::Validation(
            "reason короче восьми символов — это не обоснование, это статус в Slack".into(),
        ));
    }
    if spec.four_eyes && spec.approved_by.trim().is_empty() {
        return Err(FerrumError::Validation(
            "fourEyes=true без approvedBy".into(),
        ));
    }
    let now = Utc::now();
    if spec.expires_at <= now {
        return Err(FerrumError::Validation(
            "expiresAt уже в прошлом. Исключение родилось мёртвым".into(),
        ));
    }
    if spec.expires_at > now + Days::new(MAX_EXCEPTION_DAYS) {
        return Err(FerrumError::Validation(
            "waiver длиннее 90 дней. Это уже не исключение, а новая политика без комитета".into(),
        ));
    }
    if spec.target.policies.is_empty() || spec.target.policies.iter().any(|p| p.trim().is_empty()) {
        return Err(FerrumError::Validation(
            "PolicyException.target.policies пуст — пустой target это не scope, это global waiver"
                .into(),
        ));
    }
    if spec.target.rules.is_empty() || spec.target.rules.iter().any(|r| r.trim().is_empty()) {
        return Err(FerrumError::Validation(
            "PolicyException.target.rules пуст — исключение без rule id не бьёт deny".into(),
        ));
    }
    Ok(())
}

fn validate_common(
    mode: PolicyMode,
    disabled: bool,
    supply: &SupplySpec,
    admit: &AdmitSpec,
    runtime: &RuntimeSpec,
) -> Result<()> {
    if disabled && mode == PolicyMode::Enforce {
        return Err(FerrumError::Validation(
            "disabled=true вместе с mode=enforce: выключите политику или не притворяйтесь".into(),
        ));
    }
    validate_supply(supply)?;
    validate_admit(admit)?;
    validate_runtime(runtime)?;
    Ok(())
}

const ED25519_PUBLIC_KEY_HEX_LEN: usize = 64;

fn is_ed25519_public_key_hex(s: &str) -> bool {
    s.len() == ED25519_PUBLIC_KEY_HEX_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn validate_supply(supply: &SupplySpec) -> Result<()> {
    if (supply.require_signed || supply.deny_unsigned) && supply.trust_roots.is_empty() {
        return Err(FerrumError::Validation(
            "requireSigned/denyUnsigned без trustRoots: корни доверия едут в bundle, admission не ходит в Rekor на каждый Pod"
                .into(),
        ));
    }
    let mut has_verifying_key = false;
    for root in &supply.trust_roots {
        if root.name.trim().is_empty() {
            return Err(FerrumError::Validation("trustRoot.name пуст".into()));
        }
        for key in &root.public_keys {
            if !is_ed25519_public_key_hex(key) {
                return Err(FerrumError::Validation(format!(
                    "trustRoot '{}': publicKey должен быть 64 hex-символа (Ed25519)",
                    root.name
                )));
            }
            has_verifying_key = true;
        }
    }
    if (supply.require_signed || supply.deny_unsigned) && !has_verifying_key {
        return Err(FerrumError::Validation(
            "requireSigned/denyUnsigned без publicKeys: keyless issuer не корень в bundle, admission не ходит в Rekor"
                .into(),
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
    if matches!(
        runtime.default_action,
        RuntimeAction::Kill | RuntimeAction::Isolate
    ) {
        return Err(FerrumError::Validation(
            "runtime.defaultAction Kill/Isolate — это kill-all, не политика".into(),
        ));
    }
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
    use ferrum_api::{
        ClusterSecurityPolicy, ExceptionTarget, PolicyException, RuntimeMatch, RuntimeRule,
        TrustRoot,
    };

    const FIXTURE_ED25519_PK: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn live_exception(
        namespace: &str,
        policies: &[&str],
        rules: &[&str],
        expires_at: chrono::DateTime<Utc>,
    ) -> PolicyExceptionSpec {
        PolicyExceptionSpec {
            ticket: "JIRA-18421".into(),
            requested_by: "sre".into(),
            approved_by: "ib".into(),
            reason: "temporary debug sidecar after incident".into(),
            expires_at,
            mode: PolicyMode::Audit,
            four_eyes: true,
            target: ExceptionTarget {
                namespace: namespace.into(),
                policies: policies.iter().map(|s| (*s).to_string()).collect(),
                rules: rules.iter().map(|s| (*s).to_string()).collect(),
            },
        }
    }

    fn hit(policy: &str, rule: &str, action: RuntimeAction) -> RuleHit {
        RuleHit::new("", policy, rule, action)
    }

    fn ns_hit(namespace: &str, policy: &str, rule: &str, action: RuntimeAction) -> RuleHit {
        RuleHit::new(namespace, policy, rule, action)
    }

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
    fn exception_empty_ticket_short_reason_four_eyes_fail() {
        let spec = PolicyExceptionSpec {
            ticket: "  ".into(),
            requested_by: "sre".into(),
            approved_by: "".into(),
            reason: "asap".into(),
            expires_at: Utc::now() + Days::new(7),
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

    #[test]
    fn isolate_without_match_rejected() {
        let spec = ClusterSecurityPolicySpec {
            runtime: RuntimeSpec {
                rules: vec![RuntimeRule {
                    id: "oops".into(),
                    syscalls: vec![],
                    match_on: RuntimeMatch::default(),
                    action: RuntimeAction::Isolate,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_cluster_policy(&spec).is_err());
    }

    #[test]
    fn namespaced_ignore_is_validation_error() {
        let spec = SecurityPolicySpec {
            admit: AdmitSpec {
                failure_policy: FailurePolicy::Ignore,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_namespaced_policy(&spec).is_err());
    }

    #[test]
    fn namespaced_disabled_enforce_rejected() {
        let spec = SecurityPolicySpec {
            mode: PolicyMode::Enforce,
            disabled: true,
            ..Default::default()
        };
        assert!(validate_namespaced_policy(&spec).is_err());
    }

    #[test]
    fn unsigned_without_trust_roots_rejected() {
        let cases = [
            SupplySpec {
                require_signed: true,
                ..Default::default()
            },
            SupplySpec {
                deny_unsigned: true,
                ..Default::default()
            },
        ];
        for supply in cases {
            let spec = ClusterSecurityPolicySpec {
                supply,
                ..Default::default()
            };
            assert!(validate_cluster_policy(&spec).is_err());
        }
    }

    #[test]
    fn signed_with_trust_roots_ok() {
        let spec = ClusterSecurityPolicySpec {
            supply: SupplySpec {
                require_signed: true,
                deny_unsigned: true,
                trust_roots: vec![TrustRoot {
                    name: "org-cosign".into(),
                    public_keys: vec![FIXTURE_ED25519_PK.into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_cluster_policy(&spec).is_ok());
    }

    #[test]
    fn signed_keyless_only_rejected() {
        let spec = ClusterSecurityPolicySpec {
            supply: SupplySpec {
                require_signed: true,
                deny_unsigned: true,
                trust_roots: vec![TrustRoot {
                    name: "org-cosign".into(),
                    keyless_issuer_allow: vec!["https://token.actions.githubusercontent.com".into()],
                    public_keys: vec![],
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_cluster_policy(&spec).is_err());
    }

    #[test]
    fn malformed_public_key_rejected() {
        let short = "0".repeat(63);
        let not_hex = format!("{}g", "0".repeat(63));
        for key in ["not-hex", "aa", short.as_str(), not_hex.as_str()] {
            let spec = ClusterSecurityPolicySpec {
                supply: SupplySpec {
                    require_signed: true,
                    trust_roots: vec![TrustRoot {
                        name: "org-cosign".into(),
                        public_keys: vec![key.into()],
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(validate_cluster_policy(&spec).is_err(), "accepted {key:?}");
        }
    }

    #[test]
    fn default_action_kill_or_isolate_rejected() {
        for default_action in [RuntimeAction::Kill, RuntimeAction::Isolate] {
            let spec = ClusterSecurityPolicySpec {
                runtime: RuntimeSpec {
                    default_action,
                    ..Default::default()
                },
                ..Default::default()
            };
            assert!(validate_cluster_policy(&spec).is_err());
        }
    }

    #[test]
    fn empty_exception_target_is_validation_error() {
        let spec = live_exception(
            "",
            &["prod-restricted"],
            &["no-shell"],
            Utc::now() + Days::new(7),
        );
        let mut empty = spec.clone();
        empty.target = ExceptionTarget::default();
        assert!(validate_exception(&empty).is_err());
        empty.target.policies = vec!["prod-restricted".into()];
        assert!(validate_exception(&empty).is_err());
    }

    #[test]
    fn blank_trust_root_name_rejected() {
        let spec = ClusterSecurityPolicySpec {
            supply: SupplySpec {
                require_signed: true,
                trust_roots: vec![TrustRoot {
                    name: "  ".into(),
                    public_keys: vec![FIXTURE_ED25519_PK.into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(validate_cluster_policy(&spec).is_err());
    }

    #[test]
    fn evaluate_table() {
        let now = Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap();
        let live = now + Days::new(7);
        let expired = now - Days::new(1);
        let too_long = now + Days::new(MAX_EXCEPTION_DAYS + 1);

        struct Case {
            name: &'static str,
            hits: Vec<RuleHit>,
            default_action: RuntimeAction,
            exceptions: Vec<PolicyExceptionSpec>,
            want: RuntimeAction,
        }

        let cases = [
            Case {
                name: "deny beats allow",
                hits: vec![
                    hit("prod-restricted", "allow-metrics", RuntimeAction::Allow),
                    hit("prod-restricted", "no-shell", RuntimeAction::Deny),
                ],
                default_action: RuntimeAction::Audit,
                exceptions: vec![],
                want: RuntimeAction::Deny,
            },
            Case {
                name: "in-scope live exception beats deny",
                hits: vec![hit("prod-restricted", "no-shell", RuntimeAction::Deny)],
                default_action: RuntimeAction::Allow,
                exceptions: vec![live_exception(
                    "",
                    &["prod-restricted"],
                    &["no-shell"],
                    live,
                )],
                want: RuntimeAction::Allow,
            },
            Case {
                name: "in-scope live exception waives kill to default",
                hits: vec![hit("prod-restricted", "no-shell", RuntimeAction::Kill)],
                default_action: RuntimeAction::Audit,
                exceptions: vec![live_exception(
                    "",
                    &["prod-restricted"],
                    &["no-shell"],
                    live,
                )],
                want: RuntimeAction::Audit,
            },
            Case {
                name: "empty hits uses default_action",
                hits: vec![],
                default_action: RuntimeAction::Deny,
                exceptions: vec![],
                want: RuntimeAction::Deny,
            },
            Case {
                name: "expired exception is a no-op",
                hits: vec![hit("prod-restricted", "no-shell", RuntimeAction::Deny)],
                default_action: RuntimeAction::Allow,
                exceptions: vec![live_exception(
                    "",
                    &["prod-restricted"],
                    &["no-shell"],
                    expired,
                )],
                want: RuntimeAction::Deny,
            },
            Case {
                name: "over-90d exception is a no-op",
                hits: vec![hit("prod-restricted", "no-shell", RuntimeAction::Deny)],
                default_action: RuntimeAction::Allow,
                exceptions: vec![live_exception(
                    "",
                    &["prod-restricted"],
                    &["no-shell"],
                    too_long,
                )],
                want: RuntimeAction::Deny,
            },
            Case {
                name: "wrong-policy exception is a no-op",
                hits: vec![hit("prod-restricted", "no-shell", RuntimeAction::Deny)],
                default_action: RuntimeAction::Allow,
                exceptions: vec![live_exception("", &["other-policy"], &["no-shell"], live)],
                want: RuntimeAction::Deny,
            },
            Case {
                name: "wrong-rule exception is a no-op",
                hits: vec![hit("prod-restricted", "no-shell", RuntimeAction::Deny)],
                default_action: RuntimeAction::Allow,
                exceptions: vec![live_exception(
                    "",
                    &["prod-restricted"],
                    &["no-runtime-sock"],
                    live,
                )],
                want: RuntimeAction::Deny,
            },
            Case {
                name: "empty target is a no-op, not a global waiver",
                hits: vec![
                    hit("prod-restricted", "no-shell", RuntimeAction::Deny),
                    hit("prod-restricted", "no-shell", RuntimeAction::Kill),
                ],
                default_action: RuntimeAction::Allow,
                exceptions: vec![{
                    let mut ex = live_exception("", &["prod-restricted"], &["no-shell"], live);
                    ex.target = ExceptionTarget::default();
                    ex
                }],
                want: RuntimeAction::Kill,
            },
            Case {
                name: "namespaced exception does not waive cluster hit",
                hits: vec![hit("prod-restricted", "no-shell", RuntimeAction::Deny)],
                default_action: RuntimeAction::Allow,
                exceptions: vec![live_exception(
                    "payments",
                    &["prod-restricted"],
                    &["no-shell"],
                    live,
                )],
                want: RuntimeAction::Deny,
            },
            Case {
                name: "namespaced exception waives only that namespace",
                hits: vec![ns_hit(
                    "payments",
                    "prod-restricted",
                    "no-shell",
                    RuntimeAction::Deny,
                )],
                default_action: RuntimeAction::Allow,
                exceptions: vec![live_exception(
                    "payments",
                    &["prod-restricted"],
                    &["no-shell"],
                    live,
                )],
                want: RuntimeAction::Allow,
            },
            Case {
                name: "namespaced exception is a no-op in another namespace",
                hits: vec![ns_hit(
                    "kube-system",
                    "prod-restricted",
                    "no-shell",
                    RuntimeAction::Deny,
                )],
                default_action: RuntimeAction::Allow,
                exceptions: vec![live_exception(
                    "payments",
                    &["prod-restricted"],
                    &["no-shell"],
                    live,
                )],
                want: RuntimeAction::Deny,
            },
            Case {
                name: "cluster exception does not waive namespaced SecurityPolicy hit",
                hits: vec![ns_hit(
                    "payments",
                    "ns-policy",
                    "privileged",
                    RuntimeAction::Deny,
                )],
                default_action: RuntimeAction::Allow,
                exceptions: vec![live_exception("", &["ns-policy"], &["privileged"], live)],
                want: RuntimeAction::Deny,
            },
            Case {
                name: "exception covers one deny; the other remains",
                hits: vec![
                    hit("prod-restricted", "no-shell", RuntimeAction::Deny),
                    hit("prod-restricted", "no-module", RuntimeAction::Deny),
                ],
                default_action: RuntimeAction::Allow,
                exceptions: vec![live_exception(
                    "",
                    &["prod-restricted"],
                    &["no-shell"],
                    live,
                )],
                want: RuntimeAction::Deny,
            },
            Case {
                name: "paperwork-invalid exception is a no-op",
                hits: vec![hit("prod-restricted", "no-shell", RuntimeAction::Deny)],
                default_action: RuntimeAction::Allow,
                exceptions: vec![PolicyExceptionSpec {
                    ticket: "".into(),
                    requested_by: "sre".into(),
                    approved_by: "ib".into(),
                    reason: "temporary debug sidecar after incident".into(),
                    expires_at: live,
                    mode: PolicyMode::Audit,
                    four_eyes: true,
                    target: ExceptionTarget {
                        namespace: String::new(),
                        policies: vec!["prod-restricted".into()],
                        rules: vec!["no-shell".into()],
                    },
                }],
                want: RuntimeAction::Deny,
            },
        ];

        for case in cases {
            let got = evaluate(&case.hits, case.default_action, &case.exceptions, now);
            assert_eq!(got, case.want, "{}", case.name);
        }
    }

    #[test]
    fn namespaced_ignore_is_not_an_eval_fallback() {
        let now = Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap();
        let hits = [ns_hit(
            "app",
            "ns-policy",
            "privileged",
            RuntimeAction::Deny,
        )];
        assert_eq!(
            evaluate(&hits, RuntimeAction::Allow, &[], now),
            RuntimeAction::Deny
        );
    }

    #[test]
    fn example_prod_restricted_validates() {
        let yaml = include_str!("../../../policies/examples/prod-restricted.yaml");
        let obj: ClusterSecurityPolicy = serde_yaml::from_str(yaml).expect("example yaml");
        validate_cluster_policy(&obj.spec).expect("prod-restricted");
    }

    #[test]
    fn example_exception_ok_validates() {
        let yaml = include_str!("../../../policies/examples/exception-ok.yaml");
        let obj: PolicyException = serde_yaml::from_str(yaml).expect("example yaml");
        validate_exception(&obj.spec).expect("exception-ok");
        let now = Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap();
        assert!(exception_applies(
            &obj.spec,
            "payments",
            "prod-restricted",
            "no-shell",
            now
        ));
        assert!(!exception_applies(
            &obj.spec,
            "",
            "prod-restricted",
            "no-shell",
            now
        ));
        assert!(!exception_applies(
            &obj.spec,
            "kube-system",
            "prod-restricted",
            "no-shell",
            now
        ));
    }

    #[test]
    fn example_exception_bad_no_ticket_fails() {
        let yaml = include_str!("../../../policies/examples/exception-bad-no-ticket.yaml");
        let obj: PolicyException = serde_yaml::from_str(yaml).expect("example yaml");
        assert!(validate_exception(&obj.spec).is_err());
    }
}
