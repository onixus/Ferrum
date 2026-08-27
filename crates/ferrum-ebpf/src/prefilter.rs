//! What a loaded spec would let the datapath drop before it reaches the ring.
//!
//! Derivation only: no map, no kernel, nothing calls this from the agent yet.
//! The image is the artifact the next cycle installs; producing it here first
//! means the set of syscalls a bundle actually needs is inspectable offline.

use crate::spec::{Action, EbpfSpec, Rule};
use ferrum_ids::DATAPATH_SYSCALLS;

/// Syscalls whose record carries a path. A rule that matches only on a path
/// can never match an event without one, so a path-only rule needs exactly
/// these hooked and nothing else.
pub const PATH_BEARING_SYSCALLS: &[&str] = &["execve", "execveat", "open", "openat"];

/// Per-syscall bitmask over `DATAPATH_SYSCALLS` indices plus the two record
/// flags a rule can require. Only ever a superset of what the rules need:
/// dropping an event the userspace evaluator would have matched is a missed
/// enforcement, and there is no signal for one that never arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PrefilterImage {
    /// Bit `i` set means `DATAPATH_SYSCALLS[i]` must reach userspace.
    pub syscalls: u32,
    /// Every reason to look at an event requires EVENT_FLAG_CONTAINER.
    pub container_only: bool,
    /// Every reason to look at an event excludes the agent's own syscalls.
    pub drop_agent_self: bool,
}

impl PrefilterImage {
    pub fn observes(&self, syscall: &str) -> bool {
        match syscall_index(syscall) {
            Some(i) => self.syscalls & (1 << i) != 0,
            None => false,
        }
    }

    /// Nothing passes. Only correct for a spec no event can ever match.
    pub fn is_empty(&self) -> bool {
        self.syscalls == 0
    }

    pub fn observed_syscalls(&self) -> Vec<&'static str> {
        DATAPATH_SYSCALLS
            .iter()
            .enumerate()
            .filter(|(i, _)| self.syscalls & (1 << i) != 0)
            .map(|(_, name)| *name)
            .collect()
    }

    fn set(&mut self, syscall: &str) {
        if let Some(i) = syscall_index(syscall) {
            self.syscalls |= 1 << i;
        }
    }

    fn set_all(&mut self) {
        self.syscalls = all_mask();
    }
}

fn syscall_index(syscall: &str) -> Option<usize> {
    DATAPATH_SYSCALLS.iter().position(|s| *s == syscall)
}

fn all_mask() -> u32 {
    // The mask is u32; the list has to stay inside it.
    debug_assert!(DATAPATH_SYSCALLS.len() <= 32);
    (0..DATAPATH_SYSCALLS.len()).fold(0u32, |m, i| m | (1 << i))
}

/// Derive the image a spec implies.
///
/// A `default_action` other than Allow means every event, matched or not,
/// still produces a verdict, so nothing may be dropped. A rule that names no
/// syscalls is bounded by what it does match on: a path-only rule by the
/// path-bearing syscalls, anything else by the whole set.
pub fn prefilter_image(spec: &EbpfSpec) -> PrefilterImage {
    let mut image = PrefilterImage::default();
    if !matches!(spec.default_action, Action::Allow) {
        image.set_all();
    }
    // Allow rules widen the image like any other: an allow is how a broader
    // rule is out-ranked, so dropping its events changes the verdict.
    for rule in &spec.rules {
        widen_for_rule(&mut image, rule);
    }
    image.container_only = !spec.rules.is_empty()
        && matches!(spec.default_action, Action::Allow)
        && spec.rules.iter().all(|r| r.container_only);
    image.drop_agent_self = !spec.rules.is_empty()
        && matches!(spec.default_action, Action::Allow)
        && spec.rules.iter().all(|r| r.not_agent_self);
    image
}

fn widen_for_rule(image: &mut PrefilterImage, rule: &Rule) {
    if !rule.syscalls.is_empty() {
        for syscall in &rule.syscalls {
            image.set(syscall.trim());
        }
        return;
    }
    let path_only = !rule.path_prefix.is_empty() || !rule.path_suffix.is_empty();
    if path_only {
        for syscall in PATH_BEARING_SYSCALLS {
            image.set(syscall);
        }
    } else {
        image.set_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{Mode, PolicySelector};

    fn rule(id: &str, syscalls: &[&str], action: Action) -> Rule {
        Rule {
            id: id.into(),
            syscalls: syscalls.iter().map(|s| (*s).to_string()).collect(),
            action,
            comm_in: Vec::new(),
            container_only: false,
            path_prefix: Vec::new(),
            path_suffix: Vec::new(),
            not_agent_self: false,
        }
    }

    fn spec(default_action: Action, rules: Vec<Rule>) -> EbpfSpec {
        EbpfSpec {
            abi: ferrum_ids::AGENT_ABI,
            mode: Mode::Enforce,
            disabled: false,
            priority: 0,
            default_action,
            selector: PolicySelector::default(),
            rules,
        }
    }

    #[test]
    fn path_bearing_syscalls_are_datapath_syscalls() {
        for s in PATH_BEARING_SYSCALLS {
            assert!(ferrum_ids::is_datapath_syscall(s), "{s}");
        }
        assert!(!PATH_BEARING_SYSCALLS.contains(&"bpf"));
    }

    /// The invariant that makes the image safe to install: whatever a rule
    /// names, the image lets through.
    #[test]
    fn no_syscall_named_by_a_rule_is_ever_excluded() {
        for named in DATAPATH_SYSCALLS {
            let image = prefilter_image(&spec(
                Action::Allow,
                vec![rule("r", &[named], Action::Kill)],
            ));
            assert!(image.observes(named), "{named} excluded");
        }
        // Several rules, several syscalls, one image.
        let image = prefilter_image(&spec(
            Action::Allow,
            vec![
                rule("shell", &["execve", "execveat"], Action::Kill),
                rule("mod", &["init_module", "bpf"], Action::Deny),
            ],
        ));
        for named in ["execve", "execveat", "init_module", "bpf"] {
            assert!(image.observes(named), "{named}");
        }
        assert!(!image.observes("openat"));
    }

    #[test]
    fn a_path_only_rule_observes_every_path_bearing_syscall() {
        let mut r = rule("sock", &[], Action::Kill);
        r.path_suffix = vec!["docker.sock".into()];
        let image = prefilter_image(&spec(Action::Allow, vec![r]));
        for named in PATH_BEARING_SYSCALLS {
            assert!(image.observes(named), "{named}");
        }
        assert!(!image.observes("bpf"));
        assert!(!image.observes("init_module"));
    }

    #[test]
    fn a_rule_with_no_syscalls_and_no_path_observes_everything() {
        let mut r = rule("comm", &[], Action::Kill);
        r.comm_in = vec!["sh".into()];
        let image = prefilter_image(&spec(Action::Allow, vec![r]));
        assert_eq!(image.observed_syscalls(), DATAPATH_SYSCALLS.to_vec());
    }

    #[test]
    fn a_non_allow_default_observes_everything() {
        for default_action in [Action::Audit, Action::Deny, Action::Kill] {
            let image = prefilter_image(&spec(
                default_action,
                vec![rule("r", &["execve"], Action::Kill)],
            ));
            assert_eq!(
                image.observed_syscalls(),
                DATAPATH_SYSCALLS.to_vec(),
                "{default_action:?} still needs every event"
            );
            assert!(!image.container_only);
            assert!(!image.drop_agent_self);
        }
    }

    #[test]
    fn flags_narrow_only_when_every_rule_agrees() {
        let mut both = rule("a", &["execve"], Action::Kill);
        both.container_only = true;
        both.not_agent_self = true;
        let mut only_container = rule("b", &["openat"], Action::Kill);
        only_container.container_only = true;

        let image = prefilter_image(&spec(Action::Allow, vec![both.clone()]));
        assert!(image.container_only);
        assert!(image.drop_agent_self);

        let image = prefilter_image(&spec(Action::Allow, vec![both, only_container]));
        assert!(image.container_only);
        assert!(!image.drop_agent_self, "one rule still wants agent events");
    }

    #[test]
    fn a_spec_without_rules_and_allow_default_observes_nothing() {
        let image = prefilter_image(&spec(Action::Allow, vec![]));
        assert!(image.is_empty());
        assert!(!image.container_only);
        assert!(!image.drop_agent_self);
    }

    #[test]
    fn prod_restricted_shape_keeps_module_and_path_syscalls() {
        let mut sock = rule("no-runtime-sock", &[], Action::Kill);
        sock.path_suffix = vec!["docker.sock".into()];
        let mut shell = rule("no-shell", &["execve", "execveat"], Action::Kill);
        shell.container_only = true;
        let mut module = rule(
            "no-module",
            &["init_module", "finit_module", "bpf"],
            Action::Deny,
        );
        module.not_agent_self = true;
        let image = prefilter_image(&spec(Action::Allow, vec![shell, sock, module]));
        assert_eq!(image.observed_syscalls(), DATAPATH_SYSCALLS.to_vec());
        assert!(!image.container_only);
        assert!(!image.drop_agent_self);
    }
}
