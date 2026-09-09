//! eBPF map names and ring-buffer layout, shared by the bpf-target programs
//! in `src/main.rs` and the userspace decoder in `ferrum-ebpf`.
//!
//! This lib stays `no_std`, allocation-free, and buildable on stable 1.75.
//! aya-ebpf is linked only for `target_arch = "bpf"` (see Cargo.toml), which
//! requires nightly + build-std; the default host build never compiles it.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

pub const MAP_EVENTS: &str = "ferrum_events";
pub const MAP_RULES: &str = "ferrum_rules";
/// Single-slot array holding the agent's own tgid; programs flag matching
/// events `EVENT_FLAG_AGENT_SELF`. Zero means "not yet configured".
pub const MAP_SELF: &str = "ferrum_self";
/// cgroup ids known to belong to pod containers (fed from the userspace
/// cgroup→pod index); programs flag matching events `EVENT_FLAG_CONTAINER`.
pub const MAP_CGROUPS: &str = "ferrum_cgroups";
/// cgroup ids the loaded policy's selector actually selects, resolved in
/// userspace against the same cgroup→pod index and published here.
///
/// The kernel has no pod identity and cannot get one: labels live on objects
/// only the apiserver knows about. What it can have is the *answer* — this
/// set — computed by the side that does know, which is how a selected policy
/// becomes enforceable in kernel without the kernel learning anything about
/// pods.
///
/// Separate from [`MAP_CGROUPS`] rather than a second bit in its value: that
/// map's diff is what carries the container flag, the most consequential
/// thing in the datapath, and it is proven by its own gate. This set also has
/// a different lifetime — it changes when the *policy* changes, not only when
/// pods do.
pub const MAP_SELECTED: &str = "ferrum_selected";

/// In-kernel drop counter (per-CPU, single slot; userspace sums the CPUs).
/// Userspace must surface this; never fail-open on flood.
pub const EVENTS_DROPPED_TOTAL: &str = "events_dropped_total";

/// Ring capacity: kernel requires a power-of-2 multiple of the page size.
pub const EVENTS_RING_BYTES: u32 = 1 << 18;
pub const CGROUPS_MAX_ENTRIES: u32 = 65536;

pub const ACTION_ALLOW: u8 = 0;
pub const ACTION_AUDIT: u8 = 1;
pub const ACTION_DENY: u8 = 2;
pub const ACTION_KILL: u8 = 3;
pub const ACTION_ISOLATE: u8 = 4;

pub const COMM_LEN: usize = 16;
pub const PATH_LEN: usize = 256;

pub const EVENT_FLAG_CONTAINER: u8 = 1 << 0;
pub const EVENT_FLAG_AGENT_SELF: u8 = 1 << 1;
/// The `path` buffer does not hold the whole argument: the string did not fit
/// in `PATH_LEN` (head kept), or the pointer could not be read at all
/// (`-EFAULT`, buffer left empty). One flag for both, because either way the
/// bytes present are not the argument; userspace separates the two by whether
/// the buffer is empty, and must not decide any path predicate against an
/// empty one.
///
/// Truncation is NOT an error return. `bpf_probe_read_user_str` truncates and
/// reports the buffer size, which is inside the bounds `aya_ebpf`'s wrapper
/// checks, so the wrapper answers `Ok` — measured on Linux 6.18/x86_64, a
/// 384-byte `openat` pathname arrived as a 255-byte head with this flag
/// unset. The datapath therefore sets it on a read that filled the buffer,
/// not only on one that failed.
///
/// An object built before that fix sets nothing, so userspace does not trust
/// the flag alone: `ferrum_ebpf::path_truncated` also reads the buffer shape
/// — the helper spends the last byte on a terminator, so a string with
/// nowhere to put one did not fit. A node still running a pre-fix object
/// after a rolling upgrade is therefore covered without waiting for its image
/// to be replaced. Keep the two in step: this flag and that derivation state
/// the same comparison, one against the length the helper returned and one
/// against the bytes that arrived.
pub const EVENT_FLAG_PATH_TRUNCATED: u8 = 1 << 2;

/// Layout stamp carried by every ring record in `Event::_pad`.
///
/// The bpf ELF is built out of tree and shipped in the image; nothing else
/// joins it to the decoder, so the record carries the join itself. Bump this
/// BY HAND whenever any `Event` field moves, changes width or changes meaning
/// — a same-size layout with reordered fields is exactly the drift the record
/// length cannot catch. The decoder refuses any other value outright: there is
/// one ELF per image, so a mismatch is refused, never negotiated.
///
/// The high byte is a fixed marker; the low byte is the layout generation.
/// Both bytes are outside the `EVENT_FLAG_*` range so a stamp slot filled from
/// a flags byte (a shifted or zeroed record) can never read as valid.
pub const DATAPATH_ABI: u16 = 0xFE10;

/// Slots in `ferrum_rules`.
///
/// A fixed array and not a growing map: the in-kernel matcher walks every slot
/// on every exec, so the bound is what keeps that walk inside the verifier's
/// instruction budget. Userspace refuses a whole rule set that does not fit
/// rather than writing the head of one — see `compile_kernel_rules`.
pub const MAX_KERNEL_RULES: u32 = 64;

/// The slot holds a rule. Needed because `ACTION_ALLOW` is 0, so a zeroed slot
/// is indistinguishable from a real "allow" rule by its action alone, and an
/// array map starts out zeroed.
pub const KRULE_FLAG_USED: u8 = 1 << 0;
/// Matches only inside a pod container, by presence in `ferrum_cgroups`.
pub const KRULE_FLAG_CONTAINER_ONLY: u8 = 1 << 1;
/// Never matches the agent's own thread group, by `ferrum_self`.
pub const KRULE_FLAG_NOT_AGENT_SELF: u8 = 1 << 2;
/// Matches only cgroups the loaded policy's selector selects, by presence in
/// `ferrum_selected`.
///
/// Set on every rule of a policy that carries any selector, and on none of a
/// policy that carries none. Absence from the set is treated as *not
/// selected*, so an exec in a container whose cgroup has not been published
/// yet is not refused — see `kernel_rule_matches`.
pub const KRULE_FLAG_SELECTED_ONLY: u8 = 1 << 3;

/// The `-EPERM` an LSM hook returns to refuse. Named, because `-1` at a return
/// site is a number and this is a decision.
pub const EPERM: i32 = 1;

/// One rule as the kernel can decide it, with no userspace round trip.
///
/// This is deliberately **not** the whole of [`Rule`](../ferrum_ebpf/spec) —
/// it is the part that needs nothing the hook cannot see. What is absent and
/// why:
///
/// * **No path predicate.** Reading the executable's path inside
///   `bprm_check_security` means reading a field of `linux_binprm`, and the
///   toolchain this tree pins has no CO-RE: `aya-ebpf` carries no field
///   relocation in any published version, and `aya-ebpf-bindings` declares
///   `linux_binprm` opaque on purpose. A hand-written offset would either
///   refuse to load on a kernel whose layout differs or — worse, when the
///   offset happens to land on another field of the same width — match on
///   garbage. So rules naming a path are not represented here at all, are
///   named as such by `compile_kernel_rules`, and stay on the tracepoint path.
/// * **No selector.** Label selectors are resolved against a pod identity the
///   kernel does not have. A policy carrying one is refused wholesale rather
///   than enforced against every container, which is over-enforcement and
///   breaks workloads the policy never selected.
///
/// `comm` is one value, not a list: a rule naming three `comm`s becomes three
/// slots. It keeps this struct flat and the walk branch-free, and the cost is
/// slots, which are counted and bounded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct KernelRule {
    /// `ACTION_DENY` or `ACTION_KILL`; nothing else is written here, because
    /// nothing else refuses an exec.
    pub action: u8,
    pub flags: u8,
    /// Bytes of `comm` that are the predicate. 0 means "any `comm`".
    pub comm_len: u8,
    pub _pad: u8,
    pub comm: [u8; COMM_LEN],
}

impl KernelRule {
    pub const fn empty() -> Self {
        Self {
            action: ACTION_ALLOW,
            flags: 0,
            comm_len: 0,
            _pad: 0,
            comm: [0; COMM_LEN],
        }
    }

    pub const fn is_used(self) -> bool {
        self.flags & KRULE_FLAG_USED != 0
    }

    pub const fn container_only(self) -> bool {
        self.flags & KRULE_FLAG_CONTAINER_ONLY != 0
    }

    pub const fn not_agent_self(self) -> bool {
        self.flags & KRULE_FLAG_NOT_AGENT_SELF != 0
    }

    pub const fn selected_only(self) -> bool {
        self.flags & KRULE_FLAG_SELECTED_ONLY != 0
    }
}

impl Default for KernelRule {
    fn default() -> Self {
        Self::empty()
    }
}

/// Does this slot apply to an exec by `comm` in this context?
///
/// The predicate order is the one `ferrum_ebpf::eval::rule_matches` uses for
/// the same fields, and `krules.rs` has a test that walks both over the same
/// inputs. Two matchers that drift are two policies.
///
/// `comm` is the caller's, which is what `comm_in` has always meant: at
/// `sys_enter_execve` and at `bprm_check_security` alike the new program has
/// not taken over the name yet.
/// `selected` is presence in `ferrum_selected`, and its absence is read as
/// **not selected** rather than as unknown.
///
/// That is fail-open, and it is the deliberate opposite of what userspace
/// does with the same question: `selector_match` fails *closed* on labels it
/// has not observed, applies the rules and degrades the node. The kernel
/// cannot make that trade. It cannot tell "this pod is not selected" from
/// "this pod's cgroup has not been published yet", and the second is the
/// ordinary state for the first seconds of every container's life. Failing
/// closed there would refuse every exec in every starting container — an
/// outage caused by a security control, on a path with no way to say why.
///
/// What is given up is prevention during that window, not detection: the
/// tracepoint path sees the same exec, applies the same rules with the
/// userspace fail-closed semantics, and still kills. So the node under-
/// prevents for a moment and reports exactly as much as it did before this
/// map existed.
pub fn kernel_rule_matches(
    rule: &KernelRule,
    comm: &[u8; COMM_LEN],
    in_container: bool,
    agent_self: bool,
    selected: bool,
) -> bool {
    kernel_rule_mask(rule, comm, in_container, agent_self, selected) != 0
}

/// The same predicate as [`kernel_rule_matches`], as 1 or 0, computed without
/// a single comparison.
///
/// This shape is not a micro-optimisation; it is what makes the LSM program
/// loadable at all. BPF has no conditional move, so every `if`, `&&` and `==`
/// becomes a jump, and this predicate runs once per slot inside a 64-trip
/// loop: the branches multiply across iterations until the verifier walks past
/// its budget and refuses the program --
/// `BPF program is too large. Processed 1000001 insn (limit 1000000)`.
///
/// Measured on the CI node, one change at a time. Early `return`s inside the
/// byte loop: 202 states per instruction. Replacing them with `matches &= a ==
/// b`: LLVM kept sixteen booleans on the stack and ANDed them, 14400 states,
/// still refused. Comparing the names as one `u128`: 39113 states, refused.
/// Cutting the slot count from 64 to 2 changed nothing, which is what finally
/// ruled the loop out as the cause. A loop body of one flag test loads; three
/// do not. Only removing the comparisons themselves loads the whole predicate.
///
/// Every operand below is a bit: flags are masked and shifted rather than
/// tested, the name comparison XOR-accumulates into `diff` and folds it to
/// "was it zero" arithmetically, and the results are ANDed. The one comparison
/// left is in `kernel_rule_matches` above, outside the loop's hot shape.
pub fn kernel_rule_mask(
    rule: &KernelRule,
    comm: &[u8; COMM_LEN],
    in_container: bool,
    agent_self: bool,
    selected: bool,
) -> u8 {
    let flags = rule.flags;
    let used = flags & KRULE_FLAG_USED;
    let container_only = (flags & KRULE_FLAG_CONTAINER_ONLY) >> 1;
    let not_agent_self = (flags & KRULE_FLAG_NOT_AGENT_SELF) >> 2;
    let selected_only = (flags & KRULE_FLAG_SELECTED_ONLY) >> 3;
    // `as u8` on a bool is a zero-extension, not a comparison.
    let in_container = in_container as u8;
    let agent_self = agent_self as u8;
    let selected = selected as u8;

    // The whole name, always sixteen bytes. `compile_kernel_rules` writes into
    // a zeroed slot and `bpf_get_current_comm` pads with NULs, so equality of
    // the sixteen bytes is equality of the names, terminator included -- a rule
    // for `sh` cannot match `shred`, because byte 2 is `r` against `\0`.
    let mut diff = 0u8;
    let mut i = 0;
    while i < COMM_LEN {
        diff |= rule.comm[i] ^ comm[i];
        i += 1;
    }
    // `is_zero(x)`: for a byte, `x | -x` has its top bit set unless `x` is 0.
    let comm_equal = (((diff | diff.wrapping_neg()) >> 7) & 1) ^ 1;
    let names_a_comm = ((rule.comm_len | rule.comm_len.wrapping_neg()) >> 7) & 1;
    let comm_ok = comm_equal | (names_a_comm ^ 1);
    // A slot claiming more name bytes than the kernel reports is corrupt and
    // matches nothing -- the same refusal the old `len > COMM_LEN` guard made,
    // as a borrow out of the high bit instead of a jump.
    let comm_len_ok = ((COMM_LEN as u8).wrapping_sub(rule.comm_len) >> 7) ^ 1;

    used & comm_ok
        & comm_len_ok
        & ((not_agent_self & agent_self) ^ 1)
        & ((container_only & (in_container ^ 1)) ^ 1)
        & ((selected_only & (selected ^ 1)) ^ 1)
}

/// The action of the strongest slot that applies, or `ACTION_ALLOW` when none
/// does.
///
/// Strongest by [`action_rank`], the same order userspace ranks by. The walk
/// is over every slot and never breaks early: a fixed trip count is what makes
/// this shape acceptable to the verifier, and the cost of the branch that
/// would leave early is larger than the loop it saves.
pub fn kernel_verdict(
    rules: &[KernelRule],
    comm: &[u8; COMM_LEN],
    in_container: bool,
    agent_self: bool,
    selected: bool,
) -> u8 {
    let mut best = ACTION_ALLOW;
    let mut i = 0;
    while i < rules.len() {
        let rule = rules[i];
        if kernel_rule_matches(&rule, comm, in_container, agent_self, selected)
            && action_rank(rule.action) > action_rank(best)
        {
            best = rule.action;
        }
        i += 1;
    }
    best
}

/// What an LSM hook must return, given what ran before it.
///
/// Two rules, and the first is not ours to break. BPF LSM programs attached to
/// one hook run as a chain, and each is handed the previous program's verdict
/// as the last BTF argument; the value this function returns is the value the
/// kernel sees, untouched. So returning `0` after another program returned
/// `-EPERM` turns that refusal into an allow — a security control silently
/// defeating another one, which is the single thing it must never do. A
/// non-zero `previous` is therefore passed through whatever we would have
/// decided ourselves.
///
/// The second is ours: refuse with `-EPERM`, allow with `0`.
///
/// This lives here rather than inline in the hook because nothing compiles
/// that hook except a bpf-target build, and a rule this consequential may not
/// be held only by code no test can reach.
pub const fn lsm_verdict(previous: i32, refuses: bool) -> i32 {
    if previous != 0 {
        return previous;
    }
    if refuses {
        -EPERM
    } else {
        0
    }
}

/// Whether this action refuses the exec.
pub const fn action_refuses(action: u8) -> bool {
    action == ACTION_DENY || action == ACTION_KILL
}

/// Severity order of the runtime actions.
///
/// Duplicated from `ferrum_ebpf::spec::Action::rank` because that enum needs
/// `std` and this crate is `no_std` on the bpf target;
/// `krules.rs::the_two_action_ranks_are_one_order` fails the build if the two
/// ever disagree, which is the only thing that makes a duplicate acceptable.
pub const fn action_rank(action: u8) -> u8 {
    // A packed nibble table, not a `match`, and the reason is the verifier.
    // BPF has no conditional move: every comparison is a jump, and this
    // function is called twice per slot inside a 64-trip loop, so a `match`
    // here multiplied the paths the verifier had to walk until it gave up --
    // see `kernel_rule_mask`. One shift and one mask have a single path.
    //
    // Nibble `i` holds the rank of action `i`: allow 0, audit 1, deny 2,
    // kill 4, isolate 3. The mask keeps the shift inside the word for any
    // byte, so a corrupt action reads a nibble of the table rather than
    // shifting past its end; every nibble above isolate is 0, which is the
    // rank the `_` arm gave.
    const RANKS: u64 = 0x0003_4210;
    ((RANKS >> ((action & 7) * 4)) & 0xf) as u8
}

/// Ring-buffer record. No `String`; fixed buffers only.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Event {
    pub cgroup_id: u64,
    pub pid: u32,
    pub tgid: u32,
    pub syscall_nr: u32,
    pub action: u8,
    pub flags: u8,
    /// Layout stamp, always [`DATAPATH_ABI`]; see `decode_event`.
    pub _pad: u16,
    pub comm: [u8; COMM_LEN],
    pub path: [u8; PATH_LEN],
}

impl Event {
    pub const fn new() -> Self {
        Self {
            cgroup_id: 0,
            pid: 0,
            tgid: 0,
            syscall_nr: 0,
            action: ACTION_DENY,
            flags: 0,
            _pad: DATAPATH_ABI,
            comm: [0; COMM_LEN],
            path: [0; PATH_LEN],
        }
    }

    pub const fn in_container(self) -> bool {
        self.flags & EVENT_FLAG_CONTAINER != 0
    }

    pub const fn agent_self(self) -> bool {
        self.flags & EVENT_FLAG_AGENT_SELF != 0
    }

    pub const fn path_truncated(self) -> bool {
        self.flags & EVENT_FLAG_PATH_TRUNCATED != 0
    }
}

impl Default for Event {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    /// The value size the map ABI check in `kernel.rs` states, and the reason
    /// it may not drift by accident: a slot that grew is a map the shipped ELF
    /// and this userspace disagree about, and both write into it.
    #[test]
    fn a_kernel_rule_is_the_size_the_map_abi_declares() {
        assert_eq!(size_of::<KernelRule>(), 20);
        assert_eq!(core::mem::align_of::<KernelRule>(), 1);
        // A zeroed slot — what an array map starts as — is not a rule.
        assert!(!KernelRule::empty().is_used());
        assert!(!kernel_rule_matches(
            &KernelRule::empty(),
            &[0; COMM_LEN],
            true,
            false,
            true
        ));
    }

    /// The whole name, not a prefix of it: the byte after the predicate has to
    /// be the terminator. Without this a rule for `sh` refuses `shred`, which
    /// is a refusal the policy never asked for.
    #[test]
    fn a_comm_predicate_is_the_whole_name() {
        let mut rule = KernelRule::empty();
        rule.flags = KRULE_FLAG_USED;
        rule.action = ACTION_DENY;
        rule.comm[..2].copy_from_slice(b"sh");
        rule.comm_len = 2;

        let mut sh = [0u8; COMM_LEN];
        sh[..2].copy_from_slice(b"sh");
        let mut shred = [0u8; COMM_LEN];
        shred[..5].copy_from_slice(b"shred");

        assert!(kernel_rule_matches(&rule, &sh, false, false, true));
        assert!(!kernel_rule_matches(&rule, &shred, false, false, true));
    }

    /// The two gates the kernel *can* answer, each on its own.
    #[test]
    fn container_only_and_not_agent_self_are_each_decidable() {
        let mut rule = KernelRule::empty();
        rule.flags = KRULE_FLAG_USED | KRULE_FLAG_CONTAINER_ONLY | KRULE_FLAG_NOT_AGENT_SELF;
        rule.action = ACTION_KILL;
        let comm = [0u8; COMM_LEN];

        assert!(kernel_rule_matches(&rule, &comm, true, false, true));
        assert!(
            !kernel_rule_matches(&rule, &comm, false, false, true),
            "container_only matched outside a container"
        );
        assert!(
            !kernel_rule_matches(&rule, &comm, true, true, true),
            "not_agent_self matched the agent itself"
        );
    }

    /// A verdict from an earlier program in the chain survives ours.
    ///
    /// The failure this pins is not hypothetical: the first version of the
    /// hook ignored the argument entirely and returned `0` on every exec no
    /// rule of ours matched, so a node running a second BPF-LSM tool had that
    /// tool's refusals turned into allows by us.
    #[test]
    fn an_earlier_lsm_refusal_is_never_turned_into_an_allow() {
        // Ours to decide, because nobody decided before us.
        assert_eq!(lsm_verdict(0, false), 0);
        assert_eq!(lsm_verdict(0, true), -EPERM);

        // Somebody did. Their answer stands either way — including when we
        // would have allowed, which is the case that was broken.
        assert_eq!(lsm_verdict(-EPERM, false), -EPERM);
        assert_eq!(lsm_verdict(-EPERM, true), -EPERM);
        // Not just EPERM: any non-zero verdict is a decision already taken,
        // and this must not narrow it to the one errno we happen to use.
        for previous in [-1, -2, -13, -1000, 7] {
            assert_eq!(
                lsm_verdict(previous, false),
                previous,
                "verdict {previous} from an earlier program was replaced"
            );
            assert_eq!(lsm_verdict(previous, true), previous);
        }
    }

    /// Absence from the selected set reads as "not selected", never as
    /// "unknown" — and the cost of that choice is bounded to prevention.
    ///
    /// A container whose cgroup has not been published yet is absent from the
    /// set, and a hook that refused on absence would refuse every exec in
    /// every starting container. The tracepoint path still sees the same exec
    /// and still applies the userspace fail-closed rules, so what this gives
    /// up is a moment of prevention and nothing of detection.
    #[test]
    fn an_unpublished_cgroup_is_not_selected_rather_than_unknown() {
        let mut selected = KernelRule::empty();
        selected.flags = KRULE_FLAG_USED | KRULE_FLAG_SELECTED_ONLY;
        selected.action = ACTION_KILL;
        let mut unselected = KernelRule::empty();
        unselected.flags = KRULE_FLAG_USED;
        unselected.action = ACTION_KILL;
        let comm = [0u8; COMM_LEN];

        assert!(kernel_rule_matches(&selected, &comm, true, false, true));
        assert!(
            !kernel_rule_matches(&selected, &comm, true, false, false),
            "a rule of a selected policy fired on a cgroup the policy does not select"
        );
        // A policy with no selector carries no such flag and is unaffected by
        // the set in either direction.
        assert!(kernel_rule_matches(&unselected, &comm, true, false, false));
        assert!(kernel_rule_matches(&unselected, &comm, true, false, true));

        assert_eq!(
            kernel_verdict(&[selected], &comm, true, false, false),
            ACTION_ALLOW
        );
        assert_eq!(
            kernel_verdict(&[selected], &comm, true, false, true),
            ACTION_KILL
        );
    }

    /// The strongest applying slot wins, and a set with nothing applying is
    /// allow — never the zero value of some other field.
    #[test]
    fn the_verdict_is_the_strongest_slot_that_applies() {
        let used = |action: u8| {
            let mut r = KernelRule::empty();
            r.flags = KRULE_FLAG_USED;
            r.action = action;
            r
        };
        let comm = [0u8; COMM_LEN];

        assert_eq!(kernel_verdict(&[], &comm, true, false, true), ACTION_ALLOW);
        assert_eq!(
            kernel_verdict(&[KernelRule::empty(); 4], &comm, true, false, true),
            ACTION_ALLOW,
            "an untouched array must not decide anything"
        );
        assert_eq!(
            kernel_verdict(
                &[used(ACTION_DENY), used(ACTION_KILL)],
                &comm,
                true,
                false,
                true
            ),
            ACTION_KILL
        );
        assert_eq!(
            kernel_verdict(
                &[used(ACTION_KILL), used(ACTION_DENY)],
                &comm,
                true,
                false,
                true
            ),
            ACTION_KILL,
            "the order of the slots decided the verdict"
        );
        assert!(action_refuses(ACTION_DENY) && action_refuses(ACTION_KILL));
        assert!(!action_refuses(ACTION_ALLOW) && !action_refuses(ACTION_AUDIT));
        // Isolate is not an exec refusal, and is never written into a slot.
        assert!(!action_refuses(ACTION_ISOLATE));
    }

    #[test]
    fn map_names() {
        assert_eq!(MAP_EVENTS, "ferrum_events");
        assert_eq!(MAP_RULES, "ferrum_rules");
        assert_eq!(MAP_SELF, "ferrum_self");
        assert_eq!(MAP_CGROUPS, "ferrum_cgroups");
        assert_eq!(EVENTS_DROPPED_TOTAL, "events_dropped_total");
        assert!(EVENTS_RING_BYTES.is_power_of_two());
    }

    #[test]
    fn event_is_fixed_layout() {
        assert_eq!(size_of::<Event>(), 296);
        let event = Event::new();
        assert_eq!(event.action, ACTION_DENY);
        assert_eq!(event._pad, DATAPATH_ABI);
        assert!(!event.in_container());
        assert!(!event.agent_self());
        assert!(!event.path_truncated());
    }

    #[test]
    fn flags_are_distinct_bits_of_one_byte() {
        let all = EVENT_FLAG_CONTAINER | EVENT_FLAG_AGENT_SELF | EVENT_FLAG_PATH_TRUNCATED;
        assert_eq!(all.count_ones(), 3);
        let mut event = Event::new();
        event.flags = EVENT_FLAG_PATH_TRUNCATED;
        assert!(event.path_truncated());
        assert!(!event.in_container());
        assert!(!event.agent_self());
    }

    /// A record whose stamp slot was filled from a flags byte, or left as the
    /// zero padding an older datapath wrote, must not read as a valid stamp.
    #[test]
    fn abi_stamp_is_not_confusable_with_flags_or_zero() {
        assert_ne!(DATAPATH_ABI, 0);
        let all_flags = EVENT_FLAG_CONTAINER | EVENT_FLAG_AGENT_SELF;
        for byte in DATAPATH_ABI.to_ne_bytes() {
            assert!(byte > all_flags, "stamp byte {byte:#04x} is in flag range");
        }
    }
}
