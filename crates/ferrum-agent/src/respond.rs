//! The reaction half of the datapath: a decision that says Kill has to reach
//! a signal, and every path that does not send one has to say why.
//!
//! Refusals are checked before the system call, not after, and each one is
//! counted and exported with `executed=false`. Silence is not an option here:
//! an operator reading the export must be able to tell "killed" from
//! "decided to kill and did not".

use ferrum_common::{FerrumError, Result};

/// Delivers the reaction. Injectable so tests can assert what would be
/// signalled without CAP_KILL and without a victim process.
pub trait Responder: Send + Sync {
    fn kill(&self, tgid: u32) -> Result<()>;
}

/// SIGKILL to the whole thread group. [`refuse_reason`] runs before this is
/// ever called; nothing here re-checks the target.
pub struct SignalResponder;

impl Responder for SignalResponder {
    #[cfg(unix)]
    fn kill(&self, tgid: u32) -> Result<()> {
        // The only unsafe call in the agent: kill(2) on a tgid already
        // filtered by the guards. Errors are read from errno immediately.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::kill(tgid as libc::pid_t, libc::SIGKILL) };
        if rc == 0 {
            Ok(())
        } else {
            Err(FerrumError::Degraded(format!(
                "kill({tgid}, SIGKILL): {}",
                std::io::Error::last_os_error()
            )))
        }
    }

    #[cfg(not(unix))]
    fn kill(&self, _tgid: u32) -> Result<()> {
        Err(FerrumError::Degraded(
            "signal reaction is unavailable on this platform".into(),
        ))
    }
}

/// A responder that never signals; used when respond is off by default and by
/// callers that want the decision path without a reaction.
pub struct NoopResponder;

impl Responder for NoopResponder {
    fn kill(&self, _tgid: u32) -> Result<()> {
        Err(FerrumError::Degraded("no responder configured".into()))
    }
}

/// Why a reaction did not run. Every variant is exported verbatim in
/// `EnforcementEvent.respond_error`.
pub const REFUSE_ROLE: &str = "respond role disabled";
pub const REFUSE_AGENT_SELF: &str = "agent-self event: the agent does not kill itself";
pub const REFUSE_NOT_CONTAINER: &str = "not a container process";
pub const REFUSE_UNKNOWN_IDENTITY: &str = "unknown workload identity (cgroup not in cache)";
pub const REFUSE_TGID_ZERO: &str = "tgid 0: no process to signal";
pub const REFUSE_TGID_INIT: &str = "tgid 1: init is never a target";
pub const REFUSE_TGID_SELF: &str = "tgid is this agent process";
pub const REFUSE_ISOLATE: &str = "isolate not implemented";
pub const REFUSE_NO_RESPONDER: &str = "no responder wired: reaction backend not installed";

/// Pre-syscall guards, in the order they are checked.
pub fn refuse_reason(
    respond_role: bool,
    tgid: u32,
    agent_self: bool,
    in_container: bool,
    identity_unknown: bool,
) -> Option<&'static str> {
    if !respond_role {
        return Some(REFUSE_ROLE);
    }
    if agent_self {
        return Some(REFUSE_AGENT_SELF);
    }
    if !in_container {
        return Some(REFUSE_NOT_CONTAINER);
    }
    if identity_unknown {
        return Some(REFUSE_UNKNOWN_IDENTITY);
    }
    if tgid == 0 {
        return Some(REFUSE_TGID_ZERO);
    }
    if tgid == 1 {
        return Some(REFUSE_TGID_INIT);
    }
    if tgid == std::process::id() {
        return Some(REFUSE_TGID_SELF);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guards_run_in_order_and_cover_every_hard_refusal() {
        assert_eq!(
            refuse_reason(false, 42, false, true, false),
            Some(REFUSE_ROLE)
        );
        assert_eq!(
            refuse_reason(true, 42, true, true, false),
            Some(REFUSE_AGENT_SELF)
        );
        assert_eq!(
            refuse_reason(true, 42, false, false, false),
            Some(REFUSE_NOT_CONTAINER)
        );
        assert_eq!(
            refuse_reason(true, 42, false, true, true),
            Some(REFUSE_UNKNOWN_IDENTITY)
        );
        assert_eq!(
            refuse_reason(true, 0, false, true, false),
            Some(REFUSE_TGID_ZERO)
        );
        assert_eq!(
            refuse_reason(true, 1, false, true, false),
            Some(REFUSE_TGID_INIT)
        );
        assert_eq!(
            refuse_reason(true, std::process::id(), false, true, false),
            Some(REFUSE_TGID_SELF)
        );
        assert_eq!(refuse_reason(true, 424242, false, true, false), None);
    }

    #[test]
    fn noop_responder_never_claims_success() {
        assert!(NoopResponder.kill(4242).is_err());
    }
}
