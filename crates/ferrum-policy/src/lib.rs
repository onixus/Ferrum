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
    // approvedBy обязателен всегда: fourEyes self-declared и не может быть рубильником.
    if spec.approved_by.trim().is_empty() {
        return Err(FerrumError::Validation(
            "PolicyException.approvedBy пуст — waiver без второго согласующего не waiver".into(),
        ));
    }
    if spec.approved_by.trim() == spec.requested_by.trim() {
        return Err(FerrumError::Validation(
            "requestedBy совпадает с approvedBy — self-approve запрещён".into(),
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

/// Инвариант «правило может сработать»: датапас хукает конечное множество
/// syscall'ов, всё остальное — правило, которое валидируется, компилируется,
/// подписывается и не срабатывает никогда. Симметрично «Kill/Isolate без
/// match»: тот ловит слишком широкое правило, этот — слишком узкое.
pub fn validate_rule_syscalls(rule_id: &str, syscalls: &[String]) -> Result<()> {
    for syscall in syscalls {
        let name = syscall.trim();
        if !ferrum_ids::is_datapath_syscall(name) {
            return Err(FerrumError::Validation(format!(
                "rule '{rule_id}': syscall '{name}' — датапас его не наблюдает; правило не может сработать. Наблюдаемые: {}",
                ferrum_ids::DATAPATH_SYSCALLS.join(", ")
            )));
        }
    }
    if let Some((listed, missing)) = ferrum_ids::uncovered_equivalent_syscall(syscalls) {
        return Err(FerrumError::Validation(format!(
            "rule '{rule_id}': syscall '{listed}' назван без '{missing}' — {}. Bundle один на кластер: перечислите обе формы",
            equivalence_gap(listed, missing)
        )));
    }
    Ok(())
}

/// Тот же инвариант «правило может сработать», но для предикатов, а не для
/// syscall'ов: ядро отдаёт `comm` не длиннее TASK_COMM_LEN с NUL, а путь — не
/// длиннее буфера датапаса. Литерал длиннее границы компилируется, подписывается
/// и не совпадает никогда.
pub fn validate_rule_predicates(
    rule_id: &str,
    comm_in: &[String],
    path_prefix: &[String],
    path_suffix: &[String],
) -> Result<()> {
    if let Some((comm, len)) = ferrum_ids::unobservable_comm(comm_in) {
        return Err(FerrumError::Validation(format!(
            "rule '{rule_id}': comm '{comm}' длиной {len} байт, ядро отдаёт не больше {} — правило не может совпасть никогда",
            ferrum_ids::COMM_MATCH_MAX
        )));
    }
    for (field, patterns) in [("pathPrefix", path_prefix), ("pathSuffix", path_suffix)] {
        if let Some((pattern, len)) = ferrum_ids::unobservable_path_pattern(patterns) {
            return Err(FerrumError::Validation(format!(
                "rule '{rule_id}': {field} '{pattern}' длиной {len} байт, датапас несёт не больше {} — правило не может совпасть никогда",
                ferrum_ids::PATH_MATCH_MAX
            )));
        }
    }
    Ok(())
}

/// Тот же инвариант «правило может сработать», но для действия: runtime-план
/// исполняет ровно Allow / Audit / Kill. `Deny` он решает и не исполняет —
/// tracepoint срабатывает после того, как syscall уже выполнен, отменять
/// нечего; это глагол admission. `Isolate` не реализован ни в одном плане.
/// Правило с таким действием валидируется, компилируется, подписывается,
/// совпадает — и не делает ничего, оставляя поток решений, которых не было.
pub fn validate_rule_action(rule_id: &str, action: RuntimeAction) -> Result<()> {
    match action {
        RuntimeAction::Deny => Err(FerrumError::Validation(format!(
            "rule '{rule_id}': action=deny — runtime-план его не исполняет: tracepoint срабатывает после syscall, отменить вызов нечем. Deny — глагол admission (admit.deny); в runtime исполнимы allow, audit, kill"
        ))),
        RuntimeAction::Isolate => Err(FerrumError::Validation(format!(
            "rule '{rule_id}': action=isolate — реализации изоляции нет; правило совпадёт и не сделает ничего. В runtime исполнимы allow, audit, kill"
        ))),
        RuntimeAction::Allow | RuntimeAction::Audit | RuntimeAction::Kill => Ok(()),
    }
}

/// Why naming one spelling of an operation and not the other breaks
/// enforcement. Both directions are holes, but of opposite kinds: the missing
/// form either lets the call through on the arches that serve it, or the named
/// form never exists on the arches that do not.
fn equivalence_gap(listed: &str, missing: &str) -> String {
    match (
        ferrum_ids::arch_restricted_syscall(listed),
        ferrum_ids::arch_restricted_syscall(missing),
    ) {
        (_, Some(r)) => format!(
            "это одна операция ядра, и на {} вызов '{missing}' обходит правило",
            r.arches.join(", ")
        ),
        (Some(r), None) => format!(
            "'{listed}' есть только на {}, на остальных арках правило мертво",
            r.arches.join(", ")
        ),
        (None, None) => format!("это одна операция ядра, вызов '{missing}' обходит правило"),
    }
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
    // Тот же инвариант, что и для действия правила: defaultAction=deny — это
    // решение на каждое событие, которое план не исполняет ни разу.
    if runtime.default_action == RuntimeAction::Deny {
        return Err(FerrumError::Validation(
            "runtime.defaultAction deny — runtime-план его не исполняет: tracepoint срабатывает после syscall. Deny — глагол admission (admit.deny); по умолчанию исполнимы allow и audit".into(),
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
        validate_rule_action(&rule.id, rule.action)?;
        validate_rule_syscalls(&rule.id, &rule.syscalls)?;
        validate_rule_predicates(
            &rule.id,
            &rule.match_on.comm_in,
            &rule.match_on.path_prefix,
            &rule.match_on.path_suffix,
        )?;
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
    fn exception_empty_approved_by_rejected_even_without_four_eyes() {
        let mut spec = live_exception(
            "",
            &["prod-restricted"],
            &["no-shell"],
            Utc::now() + Days::new(7),
        );
        spec.four_eyes = false;
        spec.approved_by = "".into();
        assert!(validate_exception(&spec).is_err());
        spec.approved_by = "   ".into();
        assert!(validate_exception(&spec).is_err());
    }

    #[test]
    fn exception_self_approve_rejected() {
        let mut spec = live_exception(
            "",
            &["prod-restricted"],
            &["no-shell"],
            Utc::now() + Days::new(7),
        );
        spec.requested_by = "sre".into();
        spec.approved_by = "sre".into();
        assert!(validate_exception(&spec).is_err());
        spec.four_eyes = false;
        assert!(validate_exception(&spec).is_err());
    }

    #[test]
    fn exception_distinct_approver_ok() {
        let spec = live_exception(
            "",
            &["prod-restricted"],
            &["no-shell"],
            Utc::now() + Days::new(7),
        );
        assert!(validate_exception(&spec).is_ok());
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

    fn action_rule_spec(action: RuntimeAction) -> ClusterSecurityPolicySpec {
        ClusterSecurityPolicySpec {
            runtime: RuntimeSpec {
                rules: vec![RuntimeRule {
                    id: "no-module".into(),
                    syscalls: vec!["init_module".into(), "finit_module".into(), "bpf".into()],
                    match_on: RuntimeMatch {
                        not_agent_self: true,
                        ..Default::default()
                    },
                    action,
                }],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Same family as the unobserved syscall and the oversized predicate, but
    /// on the action: a rule the runtime plane decides and cannot execute is a
    /// permanent stream of verdicts that never happened. A match cannot save
    /// it, so the well-matched rule is the one that has to be rejected here.
    #[test]
    fn an_action_the_runtime_plane_cannot_execute_is_rejected() {
        let err = validate_cluster_policy(&action_rule_spec(RuntimeAction::Deny))
            .expect_err("runtime deny is not executable");
        let msg = err.to_string();
        assert!(matches!(err, FerrumError::Validation(_)), "{msg}");
        assert!(msg.contains("no-module"), "{msg}");
        assert!(msg.contains("deny"), "{msg}");
        assert!(msg.contains("admission"), "{msg}");

        let err = validate_cluster_policy(&action_rule_spec(RuntimeAction::Isolate))
            .expect_err("isolate has no implementation");
        let msg = err.to_string();
        assert!(matches!(err, FerrumError::Validation(_)), "{msg}");
        assert!(msg.contains("no-module"), "{msg}");
        assert!(msg.contains("isolate"), "{msg}");

        for executable in [
            RuntimeAction::Allow,
            RuntimeAction::Audit,
            RuntimeAction::Kill,
        ] {
            validate_cluster_policy(&action_rule_spec(executable))
                .unwrap_or_else(|e| panic!("{executable:?} is executable: {e}"));
        }
    }

    /// The namespaced kind compiles from the same validator; a policy author
    /// must not get the unexecutable action back by writing a SecurityPolicy.
    #[test]
    fn namespaced_policy_rejects_the_same_action() {
        let spec = SecurityPolicySpec {
            runtime: action_rule_spec(RuntimeAction::Deny).runtime,
            ..Default::default()
        };
        let err = validate_namespaced_policy(&spec).expect_err("runtime deny is not executable");
        assert!(err.to_string().contains("no-module"), "{err}");
    }

    /// `defaultAction: deny` is the same defect on every event rather than on
    /// one rule: nothing matches, everything decides an action nobody runs.
    #[test]
    fn default_action_deny_rejected() {
        let spec = ClusterSecurityPolicySpec {
            runtime: RuntimeSpec {
                default_action: RuntimeAction::Deny,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_cluster_policy(&spec).expect_err("default deny is not executable");
        assert!(err.to_string().contains("defaultAction"), "{err}");
    }

    fn runtime_rule_spec(syscalls: &[&str], action: RuntimeAction) -> ClusterSecurityPolicySpec {
        ClusterSecurityPolicySpec {
            runtime: RuntimeSpec {
                rules: vec![RuntimeRule {
                    id: "probe".into(),
                    syscalls: syscalls.iter().map(|s| (*s).to_string()).collect(),
                    match_on: RuntimeMatch {
                        comm_in: vec!["gdb".into()],
                        ..Default::default()
                    },
                    action,
                }],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn predicate_rule_spec(m: RuntimeMatch) -> ClusterSecurityPolicySpec {
        ClusterSecurityPolicySpec {
            runtime: RuntimeSpec {
                rules: vec![RuntimeRule {
                    id: "probe".into(),
                    syscalls: vec![],
                    match_on: m,
                    action: RuntimeAction::Audit,
                }],
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Same class of defect as an unhooked syscall: `comm` is capped at
    /// TASK_COMM_LEN in the kernel and the path buffer is finite, so a longer
    /// literal is a rule that validates, signs, loads and never matches.
    #[test]
    fn a_predicate_the_kernel_cannot_report_is_rejected() {
        let over_comm = "kubectl-exec-helper".to_string();
        assert!(over_comm.len() > ferrum_ids::COMM_MATCH_MAX);
        let err = validate_cluster_policy(&predicate_rule_spec(RuntimeMatch {
            comm_in: vec![over_comm.clone()],
            ..Default::default()
        }))
        .expect_err("19-byte comm is unobservable");
        let msg = err.to_string();
        assert!(msg.contains("probe"), "{msg}");
        assert!(msg.contains(&over_comm), "{msg}");
        // Names the length and the bound, not just "invalid".
        assert!(msg.contains("19"), "{msg}");
        assert!(
            msg.contains(&ferrum_ids::COMM_MATCH_MAX.to_string()),
            "{msg}"
        );

        let over_path = "p".repeat(ferrum_ids::PATH_MATCH_MAX + 1);
        for m in [
            RuntimeMatch {
                path_prefix: vec![over_path.clone()],
                ..Default::default()
            },
            RuntimeMatch {
                path_suffix: vec![over_path.clone()],
                ..Default::default()
            },
        ] {
            let msg = validate_cluster_policy(&predicate_rule_spec(m))
                .expect_err("oversize path pattern")
                .to_string();
            assert!(
                msg.contains(&(ferrum_ids::PATH_MATCH_MAX + 1).to_string()),
                "{msg}"
            );
            assert!(
                msg.contains(&ferrum_ids::PATH_MATCH_MAX.to_string()),
                "{msg}"
            );
        }

        // At the bound, and empty, both stay valid.
        validate_cluster_policy(&predicate_rule_spec(RuntimeMatch {
            comm_in: vec!["x".repeat(ferrum_ids::COMM_MATCH_MAX)],
            path_prefix: vec!["p".repeat(ferrum_ids::PATH_MATCH_MAX)],
            path_suffix: vec!["s".repeat(ferrum_ids::PATH_MATCH_MAX)],
            ..Default::default()
        }))
        .expect("a predicate the buffers can hold is valid");
    }

    #[test]
    fn syscall_outside_the_datapath_is_rejected() {
        for action in [
            RuntimeAction::Kill,
            RuntimeAction::Allow,
            RuntimeAction::Audit,
        ] {
            let err = validate_cluster_policy(&runtime_rule_spec(&["ptrace"], action))
                .expect_err("ptrace is not hooked");
            let msg = err.to_string();
            assert!(msg.contains("probe"), "{msg}");
            assert!(msg.contains("ptrace"), "{msg}");
            assert!(msg.contains("не наблюдает"), "{msg}");
        }
        // A rule that mixes one observable syscall with one unobservable one is
        // still a rule that only half fires.
        assert!(validate_cluster_policy(&runtime_rule_spec(
            &["execve", "ptrace"],
            RuntimeAction::Kill
        ))
        .is_err());
    }

    #[test]
    fn every_datapath_syscall_is_accepted() {
        for syscall in ferrum_ids::DATAPATH_SYSCALLS {
            let names: Vec<&str> = match ferrum_ids::syscall_equivalence_class(syscall) {
                Some(class) => class.to_vec(),
                None => vec![syscall],
            };
            validate_cluster_policy(&runtime_rule_spec(&names, RuntimeAction::Kill))
                .unwrap_or_else(|e| panic!("{syscall} must validate: {e}"));
        }
    }

    #[test]
    fn open_without_openat_is_dead_on_aarch64() {
        let err = validate_cluster_policy(&runtime_rule_spec(&["open"], RuntimeAction::Kill))
            .expect_err("open alone is arch-split enforcement");
        let msg = err.to_string();
        assert!(msg.contains("x86_64"), "{msg}");
        assert!(msg.contains("openat"), "{msg}");
        validate_cluster_policy(&runtime_rule_spec(&["open", "openat"], RuntimeAction::Kill))
            .expect("open+openat is portable");
    }

    #[test]
    fn openat_without_open_is_bypassed_on_x86_64() {
        let err = validate_cluster_policy(&runtime_rule_spec(&["openat"], RuntimeAction::Kill))
            .expect_err("openat alone leaves open(2) unenforced on x86_64");
        let msg = err.to_string();
        assert!(msg.contains("x86_64"), "{msg}");
        assert!(msg.contains("'open'"), "{msg}");
    }

    #[test]
    fn path_match_without_syscalls_stays_portable() {
        // path_prefix-only rules expand to every path-bearing syscall in the
        // datapath, so they never carry a half-named equivalence class.
        let mut spec = runtime_rule_spec(&[], RuntimeAction::Kill);
        spec.runtime.rules[0].match_on.path_prefix = vec!["/var/run/docker.sock".into()];
        validate_cluster_policy(&spec).expect("path-only rule is portable");
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
            Case {
                name: "empty approvedBy with fourEyes=false is a no-op",
                hits: vec![hit("prod-restricted", "no-shell", RuntimeAction::Kill)],
                default_action: RuntimeAction::Allow,
                exceptions: vec![{
                    let mut ex = live_exception("", &["prod-restricted"], &["no-shell"], live);
                    ex.four_eyes = false;
                    ex.approved_by = "".into();
                    ex
                }],
                want: RuntimeAction::Kill,
            },
            Case {
                name: "self-approved exception is a no-op",
                hits: vec![hit("prod-restricted", "no-shell", RuntimeAction::Deny)],
                default_action: RuntimeAction::Allow,
                exceptions: vec![{
                    let mut ex = live_exception("", &["prod-restricted"], &["no-shell"], live);
                    ex.requested_by = "sre".into();
                    ex.approved_by = "sre".into();
                    ex
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
