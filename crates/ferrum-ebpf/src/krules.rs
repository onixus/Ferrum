//! Which of a policy's rules the kernel can decide on its own, and which it
//! cannot — with a written reason for every one it cannot.
//!
//! Until this module the kernel held no rules at all: `ferrum_rules` was a
//! name in `ferrum-ebpf-progs` with no map behind it, every verdict was
//! reached in userspace after the ring buffer, and enforcement was therefore
//! detect-then-kill by construction. Putting rules in the kernel is the half
//! of phase 2 that both candidate hooks need, so it is built first and on its
//! own.
//!
//! ## The rule this module exists to keep
//!
//! **A rule the kernel cannot decide is named, never dropped.** The failure
//! this guards against is not a crash: it is a policy that looks enforced
//! because some of it is. Every exclusion below carries the reason it was
//! taken, `KernelRuleSet::excluded` hands them to the caller, and a whole
//! policy that may not be enforced in-kernel at all sets `refused` rather than
//! quietly compiling to an empty set — an empty set and a refused set look
//! identical on the wire and mean opposite things.
//!
//! Nothing here weakens the tracepoint path. Everything excluded is still
//! matched in userspace exactly as before; what it loses is prevention, not
//! detection.
//!
//! ## What cannot go to the kernel, and why
//!
//! **A path predicate.** The hook that would use these rules cannot read the
//! executable's path: that means a field of `linux_binprm`, and the pinned
//! toolchain has no CO-RE — `aya-ebpf` publishes no field relocation in any
//! version, and `aya-ebpf-bindings` declares `linux_binprm` opaque
//! deliberately. A hand-written offset refuses to load on a kernel whose
//! layout differs, or matches on garbage when it lands on another field of the
//! same width.
//!
//! What this does *not* cost, contrary to the first reading of it: the §D
//! acceptance case of RFC-02, «`exec` + `/bin/sh` → kill», is caught by
//! `no-shell` in the shipped `prod-restricted`, and that rule matches on
//! `commIn: [sh, bash, ash, dash, zsh]` with `containerOnly` — no path
//! predicate at all. Both are answerable in the hook, so the flagship runtime
//! case *is* representable here. `no-runtime-sock` is the one that is not: it
//! matches `pathSuffix`. `krules_gate.rs` compiles the shipped policy and
//! holds both halves of that.
//!
//! **A selector — no longer.** Label selectors are resolved against a pod
//! identity the kernel does not have, and enforcing a selected policy against
//! every container would refuse execs in workloads the policy never selected.
//! That was a wholesale refusal here for exactly as long as the kernel had no
//! way to know which pods a policy selects. It now has one: every rule of a
//! selected policy carries `KRULE_FLAG_SELECTED_ONLY`, and the hook answers
//! that from `ferrum_selected`, a set userspace fills by resolving this same
//! selector against the cgroup→pod index it already keeps. The kernel never
//! learns what a pod is; it is handed the answer.
//!
//! The caller has an obligation that comes with it, and `selected_only` on the
//! returned set is what states it: publish the rules **and** the selected set,
//! or the rules match nothing.
//!
//! **Anything but enforce.** Observe and Audit modes must not refuse a
//! syscall, and a disabled policy must not either.
//!
//! **A non-allow default.** `defaultAction` other than `allow` is "everything
//! unmatched gets this", which a list of matching rules cannot express. The
//! kernel set is refused rather than approximated.

use crate::spec::{Action, EbpfSpec, Mode, Rule};
use ferrum_ebpf_progs::{
    KernelRule, COMM_LEN, KRULE_FLAG_CONTAINER_ONLY, KRULE_FLAG_NOT_AGENT_SELF,
    KRULE_FLAG_SELECTED_ONLY, KRULE_FLAG_USED, MAX_KERNEL_RULES,
};

/// Syscalls the exec hook decides. A rule naming none of them decides nothing
/// here; a rule naming *no* syscalls at all applies to every one, exec
/// included, and enforcing the exec part of it is a subset of what it asks.
pub const EXEC_SYSCALLS: &[&str] = &["execve", "execveat"];

/// A rule that stays in userspace, and the reason it stays there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Excluded {
    pub rule: String,
    pub reason: String,
}

/// The kernel-side image of one policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KernelRuleSet {
    /// Slots to write into `ferrum_rules`. Empty whenever `refused` is set.
    pub rules: Vec<KernelRule>,
    /// Rules that stay on the tracepoint path, each with its reason.
    pub excluded: Vec<Excluded>,
    /// Every slot carries `KRULE_FLAG_SELECTED_ONLY`, so the rules apply only
    /// to cgroups in `ferrum_selected`. True exactly when the policy carries a
    /// selector, and it is what tells the caller that publishing the rules
    /// without also publishing the selected set would enforce nothing.
    pub selected_only: bool,
    /// Set when no rule of this policy may be enforced in kernel, with the
    /// reason. `Some` and an empty `rules` are not the same statement as
    /// `None` and an empty `rules`: the first is a decision, the second is a
    /// policy with nothing to enforce.
    pub refused: Option<String>,
}

impl KernelRuleSet {
    /// Nothing goes to the kernel from this policy.
    fn refuse(reason: impl Into<String>) -> Self {
        Self {
            rules: Vec::new(),
            excluded: Vec::new(),
            selected_only: false,
            refused: Some(reason.into()),
        }
    }

    pub fn is_refused(&self) -> bool {
        self.refused.is_some()
    }

    /// Slots that will be written. Never larger than [`MAX_KERNEL_RULES`].
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// The kernel-decidable part of `spec`, and a reason for everything else.
pub fn compile_kernel_rules(spec: &EbpfSpec) -> KernelRuleSet {
    if spec.disabled {
        return KernelRuleSet::refuse("политика отключена");
    }
    if spec.mode != Mode::Enforce {
        return KernelRuleSet::refuse(format!(
            "режим не enforce ({:?}): наблюдающая политика не отказывает syscall'у",
            spec.mode
        ));
    }

    // Only a default that would itself refuse an exec is unrepresentable:
    // «всё несовпавшее» списком совпадающих правил не выражается. `allow` и
    // `audit` не предотвращают ничего, поэтому предотвращение целиком
    // определяется совпавшими правилами, и отказывать из-за них значило бы
    // отказывать поставляемой `prod-restricted`, у которой `defaultAction:
    // audit`.
    if !matches!(spec.default_action, Action::Allow | Action::Audit) {
        return KernelRuleSet::refuse(format!(
            "defaultAction = {}: «всё несовпавшее» списком совпадающих правил не выражается",
            spec.default_action.as_str()
        ));
    }

    // A selected policy is enforceable in kernel, and the selector is what
    // decides *where*: every rule of it carries KRULE_FLAG_SELECTED_ONLY, and
    // the hook answers that flag from `ferrum_selected` — a set userspace
    // fills by resolving this same selector against the cgroup→pod index.
    //
    // This used to be a wholesale refusal, and the refusal was correct for as
    // long as the kernel had no way to know which pods a policy selects:
    // enforcing a selected policy against every container refuses execs in
    // workloads it never selected. What changed is not the judgement, it is
    // that the answer can now be handed to the kernel instead of the question.
    let selected_only = !spec.selector.is_empty();

    let mut out = KernelRuleSet {
        selected_only,
        ..Default::default()
    };
    for rule in &spec.rules {
        match kernel_slots(rule, selected_only) {
            Ok(slots) => out.rules.extend(slots),
            Err(reason) => out.excluded.push(Excluded {
                rule: rule.id.clone(),
                reason,
            }),
        }
    }

    // Refused whole, not truncated. A head of a rule set is a policy that
    // prevents some of what it says and reports nothing about the rest, and
    // the shape of that failure is the one `sync_container_cgroups` already
    // refuses for the cgroup map.
    if out.rules.len() > MAX_KERNEL_RULES as usize {
        return KernelRuleSet::refuse(format!(
            "правил для ядра {}, слотов {MAX_KERNEL_RULES}: усечённый набор предотвращал бы \
             часть политики и молчал об остальной",
            out.rules.len()
        ));
    }
    out
}

/// The slots one rule becomes, or the reason it becomes none.
///
/// A rule naming several `comm`s becomes one slot per name: `KernelRule` holds
/// one, which keeps the in-kernel walk flat.
fn kernel_slots(rule: &Rule, selected_only: bool) -> Result<Vec<KernelRule>, String> {
    if !matches!(rule.action, Action::Deny | Action::Kill) {
        return Err(format!(
            "действие {} не отказывает exec'у; в ядре ему нечего делать",
            rule.action.as_str()
        ));
    }
    if !rule.syscalls.is_empty()
        && !rule
            .syscalls
            .iter()
            .any(|s| EXEC_SYSCALLS.contains(&s.as_str()))
    {
        return Err(format!(
            "правило не называет ни один из {EXEC_SYSCALLS:?}, а этот набор решает только exec"
        ));
    }
    if !rule.path_prefix.is_empty() || !rule.path_suffix.is_empty() {
        return Err(
            "предикат по пути: хук не может прочитать путь исполняемого файла этим тулчейном \
             (CO-RE в aya нет, linux_binprm непрозрачен), а правило по префиксу/суффиксу без \
             пути — это правило по чему-то другому"
                .to_string(),
        );
    }

    let flags = KRULE_FLAG_USED
        | if selected_only {
            KRULE_FLAG_SELECTED_ONLY
        } else {
            0
        }
        | if rule.container_only {
            KRULE_FLAG_CONTAINER_ONLY
        } else {
            0
        }
        | if rule.not_agent_self {
            KRULE_FLAG_NOT_AGENT_SELF
        } else {
            0
        };
    let action = rule.action.as_u8();

    if rule.comm_in.is_empty() {
        let mut slot = KernelRule::empty();
        slot.action = action;
        slot.flags = flags;
        return Ok(vec![slot]);
    }

    let mut slots = Vec::with_capacity(rule.comm_in.len());
    for comm in &rule.comm_in {
        let bytes = comm.as_bytes();
        if bytes.is_empty() {
            return Err("пустой comm в comm_in: предикат, который не с чем сравнить".to_string());
        }
        // The kernel copies at most COMM_LEN bytes including the terminator,
        // so a longer literal names a string `bpf_get_current_comm` can never
        // produce. Refusing here rather than truncating: a truncated predicate
        // is a *wider* rule than the one written, and it would refuse execs
        // the policy never named.
        if bytes.len() > COMM_LEN - 1 {
            return Err(format!(
                "comm {comm:?} длиннее {} байт: ядро столько не отдаёт, а обрезанный предикат \
                 шире написанного",
                COMM_LEN - 1
            ));
        }
        let mut slot = KernelRule::empty();
        slot.action = action;
        slot.flags = flags;
        slot.comm_len = bytes.len() as u8;
        slot.comm[..bytes.len()].copy_from_slice(bytes);
        slots.push(slot);
    }
    Ok(slots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::PolicySelector;
    use ferrum_ebpf_progs::{
        action_rank, kernel_verdict, ACTION_ALLOW, ACTION_AUDIT, ACTION_DENY, ACTION_ISOLATE,
        ACTION_KILL,
    };

    fn rule(id: &str, action: Action) -> Rule {
        Rule {
            id: id.to_string(),
            syscalls: vec!["execve".to_string()],
            action,
            comm_in: Vec::new(),
            container_only: true,
            path_prefix: Vec::new(),
            path_suffix: Vec::new(),
            not_agent_self: true,
        }
    }

    fn spec(rules: Vec<Rule>) -> EbpfSpec {
        EbpfSpec {
            abi: crate::AGENT_ABI,
            mode: Mode::Enforce,
            disabled: false,
            priority: 0,
            default_action: Action::Allow,
            selector: PolicySelector::default(),
            rules,
        }
    }

    /// The duplicate that makes the in-kernel walk possible is held to the
    /// enum it duplicates. Two orders would be two policies, one of which
    /// nobody reads.
    #[test]
    fn the_two_action_ranks_are_one_order() {
        for action in [
            Action::Allow,
            Action::Audit,
            Action::Deny,
            Action::Isolate,
            Action::Kill,
        ] {
            assert_eq!(
                action_rank(action.as_u8()),
                action.rank(),
                "{} ranks differently in the two matchers",
                action.as_str()
            );
        }
        // And the byte constants are the same numbers, which is what lets a
        // slot carry `Action::as_u8` at all.
        assert_eq!(Action::Allow.as_u8(), ACTION_ALLOW);
        assert_eq!(Action::Audit.as_u8(), ACTION_AUDIT);
        assert_eq!(Action::Deny.as_u8(), ACTION_DENY);
        assert_eq!(Action::Isolate.as_u8(), ACTION_ISOLATE);
        assert_eq!(Action::Kill.as_u8(), ACTION_KILL);
    }

    #[test]
    fn a_rule_the_kernel_can_decide_becomes_a_slot_that_decides_it() {
        let set = compile_kernel_rules(&spec(vec![rule("no-exec", Action::Kill)]));
        assert!(!set.is_refused(), "{set:?}");
        assert_eq!(set.excluded, Vec::new());
        assert_eq!(set.len(), 1);

        let slot = set.rules[0];
        assert!(slot.is_used() && slot.container_only() && slot.not_agent_self());
        assert_eq!(slot.action, ACTION_KILL);
        assert_eq!(slot.comm_len, 0, "no comm predicate was written");

        // And it decides, on the same function the kernel walks.
        let comm = [0u8; COMM_LEN];
        assert_eq!(
            kernel_verdict(&set.rules, &comm, true, false, true),
            ACTION_KILL
        );
        assert_eq!(
            kernel_verdict(&set.rules, &comm, false, false, true),
            ACTION_ALLOW,
            "container_only decided outside a container"
        );
        assert_eq!(
            kernel_verdict(&set.rules, &comm, true, true, true),
            ACTION_ALLOW,
            "the rule matched the agent itself"
        );
    }

    /// Every exclusion, each with the reason attached to the rule it belongs
    /// to — the list is the product, not a side effect.
    #[test]
    fn every_rule_the_kernel_cannot_decide_is_named_with_its_reason() {
        let mut with_path = rule("no-shell", Action::Kill);
        with_path.path_suffix = vec!["/bin/sh".to_string()];
        let mut other_syscall = rule("no-bpf", Action::Kill);
        other_syscall.syscalls = vec!["bpf".to_string()];
        let mut long_comm = rule("long-comm", Action::Kill);
        long_comm.comm_in = vec!["a".repeat(COMM_LEN)];
        let audit = rule("just-watch", Action::Audit);

        let set = compile_kernel_rules(&spec(vec![
            with_path,
            other_syscall,
            long_comm,
            audit,
            rule("keeps", Action::Kill),
        ]));
        assert!(!set.is_refused());
        assert_eq!(set.len(), 1, "only the decidable rule became a slot");

        let named: Vec<&str> = set.excluded.iter().map(|e| e.rule.as_str()).collect();
        assert_eq!(named, ["no-shell", "no-bpf", "long-comm", "just-watch"]);
        for excluded in &set.excluded {
            assert!(
                excluded.reason.len() > 20,
                "{}: a reason this short is not one",
                excluded.rule
            );
        }
        assert!(
            set.excluded[0].reason.contains("путь"),
            "{}",
            set.excluded[0].reason
        );
    }

    /// A rule naming no syscall at all applies to every one, exec included.
    #[test]
    fn a_rule_naming_no_syscall_still_covers_exec() {
        let mut all = rule("everything", Action::Kill);
        all.syscalls = Vec::new();
        let set = compile_kernel_rules(&spec(vec![all]));
        assert_eq!(set.len(), 1, "{set:?}");
    }

    #[test]
    fn a_rule_naming_several_comms_becomes_one_slot_each() {
        let mut multi = rule("shells", Action::Kill);
        multi.comm_in = vec!["sh".to_string(), "bash".to_string()];
        let set = compile_kernel_rules(&spec(vec![multi]));
        assert_eq!(set.len(), 2);
        assert_eq!(set.rules[0].comm_len, 2);
        assert_eq!(&set.rules[0].comm[..2], b"sh");
        assert_eq!(set.rules[1].comm_len, 4);
        assert_eq!(&set.rules[1].comm[..4], b"bash");

        let mut bash = [0u8; COMM_LEN];
        bash[..4].copy_from_slice(b"bash");
        let mut other = [0u8; COMM_LEN];
        other[..3].copy_from_slice(b"cat");
        assert_eq!(
            kernel_verdict(&set.rules, &bash, true, false, true),
            ACTION_KILL
        );
        assert_eq!(
            kernel_verdict(&set.rules, &other, true, false, true),
            ACTION_ALLOW
        );
    }

    /// The four whole-policy refusals. Each is a `refused` with a reason and
    /// an empty rule list — never an empty list on its own, which reads as
    /// "this policy asks for nothing".
    #[test]
    fn a_policy_the_kernel_may_not_enforce_at_all_is_refused_and_not_emptied() {
        let observing = {
            let mut s = spec(vec![rule("keeps", Action::Kill)]);
            s.mode = Mode::Observe;
            s
        };
        let disabled = {
            let mut s = spec(vec![rule("keeps", Action::Kill)]);
            s.disabled = true;
            s
        };
        let defaulted = {
            let mut s = spec(vec![rule("keeps", Action::Kill)]);
            s.default_action = Action::Kill;
            s
        };
        // And the two defaults that must NOT refuse: neither prevents
        // anything, so prevention stays fully determined by the rules.
        for default in [Action::Allow, Action::Audit] {
            let mut permissive = spec(vec![rule("keeps", Action::Kill)]);
            permissive.default_action = default;
            let set = compile_kernel_rules(&permissive);
            assert!(
                !set.is_refused() && set.len() == 1,
                "defaultAction {} refused a policy it does not affect: {set:?}",
                default.as_str()
            );
        }

        for (name, spec) in [
            ("observe", observing),
            ("disabled", disabled),
            ("default", defaulted),
        ] {
            let set = compile_kernel_rules(&spec);
            let reason = set
                .refused
                .as_deref()
                .unwrap_or_else(|| panic!("{name}: not refused"));
            assert!(reason.len() > 20, "{name}: {reason}");
            assert!(set.is_empty(), "{name}: refused and still emitted slots");
            // A decidable rule was present in every one of them, so none of
            // these passed by having nothing to say.
            assert!(!spec.rules.is_empty());
        }
    }

    /// The one that matters: for every input the kernel set can decide, the
    /// two matchers agree.
    ///
    /// Not a spot check — a sweep over the whole product of the inputs a
    /// kernel slot is made of (`comm` predicate present or not, matching or
    /// not, container flag, agent-self flag) run through `matched_action`,
    /// which is the userspace path an event actually takes, and through
    /// `kernel_verdict`, which is the function the bpf object walks. A rule
    /// set the kernel enforces and userspace would not is a policy nobody
    /// wrote; the reverse is enforcement that silently stopped.
    #[test]
    fn the_kernel_and_the_userspace_matcher_decide_the_same_records() {
        let mut named = rule("named-comm", Action::Kill);
        named.comm_in = vec!["sh".to_string()];
        let mut anyone = rule("any-comm", Action::Kill);
        anyone.comm_in = Vec::new();
        let mut anywhere = rule("host-too", Action::Kill);
        anywhere.container_only = false;
        anywhere.not_agent_self = false;

        for rules in [vec![named], vec![anyone], vec![anywhere]] {
            let spec = spec(rules);
            let set = compile_kernel_rules(&spec);
            assert!(!set.is_refused() && !set.is_empty(), "{set:?}");

            for comm in ["sh", "shred", "cat", ""] {
                for in_container in [true, false] {
                    for agent_self in [true, false] {
                        // Both values of the selected bit, because none of
                        // these policies selects: a slot that grew a
                        // KRULE_FLAG_SELECTED_ONLY it was not asked for would
                        // silently stop matching on nodes whose index is
                        // still filling, and this is what catches that.
                        for selected in [true, false] {
                            let event = crate::eval::SyscallEvent {
                                syscall: "execve",
                                comm,
                                path: "/usr/bin/whatever",
                                in_container,
                                agent_self,
                                path_truncated: false,
                            };
                            let userspace = crate::eval::matched_action(&spec, &event);

                            let mut raw = [0u8; COMM_LEN];
                            raw[..comm.len()].copy_from_slice(comm.as_bytes());
                            let kernel = kernel_verdict(
                                &set.rules,
                                &raw,
                                in_container,
                                agent_self,
                                selected,
                            );

                            assert_eq!(
                                kernel,
                                userspace.action.as_u8(),
                                "{}/{comm}/{in_container}/{agent_self}/selected={selected}: \
                             kernel says {kernel}, userspace says {}",
                                spec.rules[0].id,
                                userspace.action.as_str()
                            );
                        }
                    }
                }
            }
        }
    }

    /// A selected policy is enforceable now, and every slot of it says where.
    ///
    /// This replaced a wholesale refusal. The refusal was right while the
    /// kernel had no way to know which pods a policy selects; the flag is
    /// right now that userspace can hand it the answer. What must not change
    /// is the property the refusal protected: a rule of a selected policy
    /// must never fire on a cgroup the policy does not select.
    #[test]
    fn a_selected_policy_carries_the_flag_on_every_slot_and_fires_only_where_it_selects() {
        let mut selected = spec(vec![rule("keeps", Action::Kill)]);
        selected.selector.namespace_selector.match_labels = [(
            "kubernetes.io/metadata.name".to_string(),
            "prod".to_string(),
        )]
        .into_iter()
        .collect();

        let set = compile_kernel_rules(&selected);
        assert!(!set.is_refused(), "{set:?}");
        assert!(
            set.selected_only,
            "the set does not tell its caller that the selected cgroups must be published too"
        );
        assert_eq!(set.len(), 1);
        assert!(set.rules[0].selected_only());

        let comm = [0u8; COMM_LEN];
        assert_eq!(
            kernel_verdict(&set.rules, &comm, true, false, true),
            ACTION_KILL
        );
        assert_eq!(
            kernel_verdict(&set.rules, &comm, true, false, false),
            ACTION_ALLOW,
            "a selected policy fired on a cgroup it does not select"
        );

        // A policy with no selector must not carry the flag, or it would match
        // nothing at all: `ferrum_selected` is empty for an unselected policy.
        let plain = compile_kernel_rules(&spec(vec![rule("keeps", Action::Kill)]));
        assert!(!plain.selected_only);
        assert!(!plain.rules[0].selected_only());
        assert_eq!(
            kernel_verdict(&plain.rules, &comm, true, false, false),
            ACTION_KILL
        );
    }

    /// Overflow is refused whole. A truncated set prevents part of a policy
    /// and reports nothing about the rest.
    #[test]
    fn a_rule_set_that_does_not_fit_is_refused_rather_than_cut() {
        let fits = spec(
            (0..MAX_KERNEL_RULES)
                .map(|i| rule(&format!("r{i}"), Action::Kill))
                .collect(),
        );
        let set = compile_kernel_rules(&fits);
        assert!(!set.is_refused());
        assert_eq!(set.len(), MAX_KERNEL_RULES as usize);

        let over = spec(
            (0..MAX_KERNEL_RULES + 1)
                .map(|i| rule(&format!("r{i}"), Action::Kill))
                .collect(),
        );
        let set = compile_kernel_rules(&over);
        let reason = set.refused.as_deref().expect("overflow must refuse");
        assert!(reason.contains(&MAX_KERNEL_RULES.to_string()), "{reason}");
        assert!(set.is_empty());
    }
}
