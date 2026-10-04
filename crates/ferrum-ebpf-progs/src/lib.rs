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
/// The slot carries a path prefix in `prefix`/`prefix_len`, matched against
/// the path the exec was asked for.
pub const KRULE_FLAG_PATH_PREFIX: u8 = 1 << 4;
/// The slot carries a path suffix in `suffix`/`suffix_len`.
pub const KRULE_FLAG_PATH_SUFFIX: u8 = 1 << 5;

/// The read-only global the loader fills with the offset of
/// `linux_binprm::filename` before the program is loaded. Equal to the symbol
/// name in `src/main.rs`; attribute and symbol names cannot reference a const.
pub const BPRM_FILENAME_OFFSET_GLOBAL: &str = "FERRUM_BPRM_FILENAME_OFF";

/// Bytes of one path pattern a slot can hold.
///
/// Not `PATH_LEN`: a slot is walked on every exec and the map is
/// `MAX_KERNEL_RULES` of them, so the pattern buffer is what the slot costs.
/// Sixty-four bytes hold every pattern in the shipped policies with room to
/// spare (`containerd.sock` is fifteen); a longer pattern is not truncated —
/// a truncated prefix is a *wider* rule than the one written — but kept on
/// the tracepoint path with a reason, by `compile_kernel_rules`.
pub const KPATH_LEN: usize = 64;

/// [`ExecPath::flags`]: the hook knows where the path lives in this kernel's
/// `linux_binprm` and tried to read it. Without it, a slot with a path
/// predicate matches nothing — see [`kernel_rule_mask`].
pub const EXEC_PATH_KNOWN: u8 = 1 << 0;
/// [`ExecPath::flags`]: `bytes` is not the whole path — the same statement
/// [`EVENT_FLAG_PATH_TRUNCATED`] makes about a ring record, and decided the
/// same way: a read that filled the buffer did not fit, and a read that
/// failed left it empty.
pub const EXEC_PATH_TRUNCATED: u8 = 1 << 1;

/// The path an exec was asked for, as the LSM hook reads it.
///
/// It is `linux_binprm::filename`: the kernel's own copy of the string the
/// caller passed to `execve`, taken by `getname()` before the hook runs. So it
/// is the same string the `sys_enter_execve` record carries — which is what
/// lets one matcher serve both sides — but read from kernel memory, after the
/// copy, so a second thread rewriting the user buffer between the tracepoint
/// and the exec has nothing left to rewrite. That is the double-fetch of the
/// tracepoint path, closed for exec.
///
/// One place the two strings differ, and it is written down rather than
/// smoothed over: `execveat` with a directory descriptor and a relative path.
/// The record carries the relative path; the kernel builds `/dev/fd/<n>/<path>`
/// for `filename`. A prefix rule therefore matches neither, and a suffix rule
/// can match the kernel's string where it did not match the record's — the
/// kernel side is the stricter of the two there, never the looser.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExecPath {
    pub bytes: [u8; PATH_LEN],
    /// Bytes before the terminator. At most `PATH_LEN - 1`.
    pub len: u16,
    pub flags: u8,
    pub _pad: u8,
}

impl ExecPath {
    /// A hook that does not know where the path is. Path predicates match
    /// nothing against it.
    pub const fn unknown() -> Self {
        Self {
            bytes: [0; PATH_LEN],
            len: 0,
            flags: 0,
            _pad: 0,
        }
    }

    /// The path as the userspace matcher sees it: `bytes` up to `len`, and the
    /// truncation flag a ring record would carry.
    ///
    /// For tests and for the userspace side of the equivalence sweep; the hook
    /// fills the struct itself.
    pub fn from_bytes(path: &[u8], truncated: bool) -> Self {
        let mut out = Self::unknown();
        let len = if path.len() > PATH_LEN - 1 {
            PATH_LEN - 1
        } else {
            path.len()
        };
        let mut i = 0;
        while i < len {
            out.bytes[i] = path[i];
            i += 1;
        }
        out.len = len as u16;
        // The datapath's own rule: a string that reached the last usable byte
        // did not fit, whether or not it would have ended there.
        out.flags = EXEC_PATH_KNOWN
            | if truncated || path.len() >= PATH_LEN - 1 {
                EXEC_PATH_TRUNCATED
            } else {
                0
            };
        out
    }
}

/// The `-EPERM` an LSM hook returns to refuse. Named, because `-1` at a return
/// site is a number and this is a decision.
pub const EPERM: i32 = 1;

/// One rule as the kernel can decide it, with no userspace round trip.
///
/// This is deliberately **not** the whole of [`Rule`](../ferrum_ebpf/spec) —
/// it is the part that needs nothing the hook cannot see. What is absent and
/// why:
///
/// * **A path predicate, now, with one condition.** The hook reads
///   `linux_binprm::filename`, and the pinned toolchain has no CO-RE: `aya-ebpf`
///   carries no field relocation and `aya-ebpf-bindings` declares
///   `linux_binprm` opaque on purpose. The offset is therefore not written
///   here by hand — it is read by userspace out of *this kernel's* vmlinux BTF
///   (`ferrum_ebpf::btf`), checked to be a `char *` named `filename` inside
///   `struct linux_binprm`, and handed to the program as a read-only global
///   before load. A kernel whose BTF does not answer that gets no path slots
///   at all, and the rules that need them are named as excluded.
/// * **No selector of its own.** Label selectors are resolved against a pod
///   identity the kernel does not have; what the slot carries instead is
///   `KRULE_FLAG_SELECTED_ONLY`, answered from `ferrum_selected`.
///
/// `comm` is one value, not a list: a rule naming three `comm`s becomes three
/// slots. It keeps this struct flat and the walk branch-free, and the cost is
/// slots, which are counted and bounded. Path patterns follow the same rule:
/// one prefix and one suffix per slot, so a rule naming two prefixes and three
/// suffixes is six slots.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct KernelRule {
    /// `ACTION_DENY` or `ACTION_KILL`; nothing else is written here, because
    /// nothing else refuses an exec.
    pub action: u8,
    pub flags: u8,
    /// Bytes of `comm` that are the predicate. 0 means "any `comm`".
    pub comm_len: u8,
    /// Bytes of `prefix` that are the predicate, under
    /// `KRULE_FLAG_PATH_PREFIX`.
    pub prefix_len: u8,
    /// Bytes of `suffix` that are the predicate, under
    /// `KRULE_FLAG_PATH_SUFFIX`.
    pub suffix_len: u8,
    pub _pad: [u8; 3],
    pub comm: [u8; COMM_LEN],
    pub prefix: [u8; KPATH_LEN],
    pub suffix: [u8; KPATH_LEN],
}

impl KernelRule {
    pub const fn empty() -> Self {
        Self {
            action: ACTION_ALLOW,
            flags: 0,
            comm_len: 0,
            prefix_len: 0,
            suffix_len: 0,
            _pad: [0; 3],
            comm: [0; COMM_LEN],
            prefix: [0; KPATH_LEN],
            suffix: [0; KPATH_LEN],
        }
    }

    /// Make this slot require the path to start with `pattern`. The caller
    /// keeps `pattern` non-empty, NUL-free and at most [`KPATH_LEN`] bytes;
    /// `compile_kernel_rules` refuses anything else before it gets here.
    pub fn set_prefix(&mut self, pattern: &[u8]) {
        let len = pattern.len().min(KPATH_LEN);
        self.flags |= KRULE_FLAG_PATH_PREFIX;
        self.prefix_len = len as u8;
        self.prefix = [0; KPATH_LEN];
        self.prefix[..len].copy_from_slice(&pattern[..len]);
    }

    /// Make this slot require the path to end with `pattern`, on the same
    /// terms as [`Self::set_prefix`].
    pub fn set_suffix(&mut self, pattern: &[u8]) {
        let len = pattern.len().min(KPATH_LEN);
        self.flags |= KRULE_FLAG_PATH_SUFFIX;
        self.suffix_len = len as u8;
        self.suffix = [0; KPATH_LEN];
        self.suffix[..len].copy_from_slice(&pattern[..len]);
    }

    /// The slot names a path, so it can only be decided by a hook that knows
    /// where the path is.
    pub const fn names_a_path(self) -> bool {
        self.flags & (KRULE_FLAG_PATH_PREFIX | KRULE_FLAG_PATH_SUFFIX) != 0
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
///
/// `path` is the exec's path as the hook read it. Its two predicates mirror
/// `rule_matches` exactly, fail-closed half included: a prefix on a path that
/// could not be read at all, and a suffix on a path that did not fit, are
/// *matches* — the same "unknown asserts" userspace applies, because a rule
/// that skips on an unreadable path is a rule an attacker skips by making the
/// path unreadable. A hook that does not know where the path lives
/// ([`EXEC_PATH_KNOWN`] clear) is the opposite case and decides the other way:
/// that is not an attacker's doing but a kernel this build could not read,
/// and failing closed there would refuse every exec the rule's other
/// predicates allow. Userspace never publishes path slots to such a hook; the
/// flag is the second wall, not the first.
pub fn kernel_rule_matches(
    rule: &KernelRule,
    comm: &[u8; COMM_LEN],
    in_container: bool,
    agent_self: bool,
    selected: bool,
    path: &ExecPath,
) -> bool {
    kernel_rule_mask(rule, comm, in_container, agent_self, selected, path) != 0
}

/// 1 when `x` is non-zero, as arithmetic.
#[inline(always)]
const fn nonzero(x: u8) -> u8 {
    ((x | x.wrapping_neg()) >> 7) & 1
}

/// The XOR-accumulated difference between the slot's prefix and the head of
/// the path: zero exactly when the path starts with the prefix.
///
/// The three comparisons of a slot — this, [`suffix_diff`] and [`comm_diff`]
/// — are each a function of their own that is never inlined, and each returns
/// the raw difference rather than a verdict. That shape is what loads, and
/// every other one tried on Linux 6.17 did not:
///
/// * fully branch-free, bytes masked to the pattern length: LLVM compiled
///   `i < len` to a compare and the masked XOR to a select, which BPF makes a
///   jump — sixty-four per pattern, past the verifier's million instructions;
/// * branch-free with the masks stored in the slot as data: no jumps (10 344
///   instructions), but one basic block of some three hundred loads that LLVM
///   hoisted and spilled — a 336-byte callback frame which with the hook's own
///   went past the 512-byte limit on a call chain;
/// * loops bounded by the pattern length, inlined: the frame was fine, but
///   with the three comparisons in one function InstCombine turned the `comm`
///   difference back into sixteen equality jumps, and their forks multiplied
///   with the loop exits.
///
/// Behind a call boundary the caller only ever sees a byte, so nothing folds
/// across it; and the loop exits inside collapse at the return, where the
/// index is dead and the difference is the only thing left.
#[inline(never)]
fn prefix_diff(rule: &KernelRule, path: &ExecPath) -> u8 {
    let len = rule.prefix_len as usize;
    let mut diff = 0u8;
    let mut i = 0;
    while i < len && i < KPATH_LEN {
        diff |= rule.prefix[i] ^ path.bytes[i];
        i += 1;
    }
    diff
}

/// The same for the suffix, compared against the tail of the path. The path
/// index is masked into the buffer rather than checked, so the access is
/// bounded without a branch; a path shorter than the suffix wraps into its own
/// zero padding, which a NUL-free pattern never equals, and the caller checks
/// the length as well rather than leaning on the padding alone.
#[inline(never)]
fn suffix_diff(rule: &KernelRule, path: &ExecPath) -> u8 {
    let len = rule.suffix_len as usize;
    let start = path.len.wrapping_sub(rule.suffix_len as u16);
    let mut diff = 0u8;
    let mut i = 0;
    while i < len && i < KPATH_LEN {
        let at = (start.wrapping_add(i as u16) as usize) & (PATH_LEN - 1);
        diff |= rule.suffix[i] ^ path.bytes[at];
        i += 1;
    }
    diff
}

/// The whole sixteen bytes of the name, as one XOR-accumulated difference.
#[inline(never)]
fn comm_diff(rule: &[u8; COMM_LEN], comm: &[u8; COMM_LEN]) -> u8 {
    let mut diff = 0u8;
    let mut i = 0;
    while i < COMM_LEN {
        diff |= rule[i] ^ comm[i];
        i += 1;
    }
    diff
}

/// Whether the path starts with the slot's prefix, as 1 or 0. A path shorter
/// than the pattern compares its zero padding against pattern bytes, and
/// patterns carry no NUL (`compile_kernel_rules` refuses one), so a short
/// path differs rather than matching on what it lacks.
#[inline(always)]
fn prefix_hit(rule: &KernelRule, path: &ExecPath) -> u8 {
    let fits = ((KPATH_LEN as u8).wrapping_sub(rule.prefix_len) >> 7) ^ 1;
    (nonzero(prefix_diff(rule, path)) ^ 1) & nonzero(rule.prefix_len) & fits
}

/// Whether the path ends with the slot's suffix, as 1 or 0.
#[inline(always)]
fn suffix_hit(rule: &KernelRule, path: &ExecPath) -> u8 {
    let start = path.len.wrapping_sub(rule.suffix_len as u16);
    let long_enough = ((start >> 15) as u8 & 1) ^ 1;
    let fits = ((KPATH_LEN as u8).wrapping_sub(rule.suffix_len) >> 7) ^ 1;
    (nonzero(suffix_diff(rule, path)) ^ 1) & nonzero(rule.suffix_len) & long_enough & fits
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
    path: &ExecPath,
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
    let diff = comm_diff(&rule.comm, comm);
    // `is_zero(x)`: for a byte, `x | -x` has its top bit set unless `x` is 0.
    let comm_equal = (((diff | diff.wrapping_neg()) >> 7) & 1) ^ 1;
    let names_a_comm = ((rule.comm_len | rule.comm_len.wrapping_neg()) >> 7) & 1;
    let comm_ok = comm_equal | (names_a_comm ^ 1);
    // A slot claiming more name bytes than the kernel reports is corrupt and
    // matches nothing -- the same refusal the old `len > COMM_LEN` guard made,
    // as a borrow out of the high bit instead of a jump.
    let comm_len_ok = ((COMM_LEN as u8).wrapping_sub(rule.comm_len) >> 7) ^ 1;

    // The path, in `rule_matches`' own terms: unreadable is "truncated with
    // nothing read", and it asserts a prefix; truncated at all asserts a
    // suffix.
    let has_prefix = (flags & KRULE_FLAG_PATH_PREFIX) >> 4;
    let has_suffix = (flags & KRULE_FLAG_PATH_SUFFIX) >> 5;
    let known = path.flags & EXEC_PATH_KNOWN;
    let truncated = (path.flags & EXEC_PATH_TRUNCATED) >> 1;
    let unreadable = truncated & (nonzero(path.len as u8 | (path.len >> 8) as u8) ^ 1);
    let prefix_ok = (has_prefix ^ 1) | prefix_hit(rule, path) | unreadable;
    let suffix_ok = (has_suffix ^ 1) | suffix_hit(rule, path) | truncated;
    let path_decidable = ((has_prefix | has_suffix) & (known ^ 1)) ^ 1;

    used & comm_ok
        & prefix_ok
        & suffix_ok
        & path_decidable
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
    path: &ExecPath,
) -> u8 {
    let mut best = ACTION_ALLOW;
    let mut i = 0;
    while i < rules.len() {
        let rule = rules[i];
        if kernel_rule_matches(&rule, comm, in_container, agent_self, selected, path)
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
        assert_eq!(size_of::<KernelRule>(), 152);
        assert_eq!(core::mem::align_of::<KernelRule>(), 1);
        // A zeroed slot — what an array map starts as — is not a rule.
        assert!(!KernelRule::empty().is_used());
        assert!(!kernel_rule_matches(
            &KernelRule::empty(),
            &[0; COMM_LEN],
            true,
            false,
            true,
            &ExecPath::unknown()
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

        assert!(kernel_rule_matches(
            &rule,
            &sh,
            false,
            false,
            true,
            &ExecPath::unknown()
        ));
        assert!(!kernel_rule_matches(
            &rule,
            &shred,
            false,
            false,
            true,
            &ExecPath::unknown()
        ));
    }

    /// The two gates the kernel *can* answer, each on its own.
    #[test]
    fn container_only_and_not_agent_self_are_each_decidable() {
        let mut rule = KernelRule::empty();
        rule.flags = KRULE_FLAG_USED | KRULE_FLAG_CONTAINER_ONLY | KRULE_FLAG_NOT_AGENT_SELF;
        rule.action = ACTION_KILL;
        let comm = [0u8; COMM_LEN];

        assert!(kernel_rule_matches(
            &rule,
            &comm,
            true,
            false,
            true,
            &ExecPath::unknown()
        ));
        assert!(
            !kernel_rule_matches(&rule, &comm, false, false, true, &ExecPath::unknown()),
            "container_only matched outside a container"
        );
        assert!(
            !kernel_rule_matches(&rule, &comm, true, true, true, &ExecPath::unknown()),
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

        assert!(kernel_rule_matches(
            &selected,
            &comm,
            true,
            false,
            true,
            &ExecPath::unknown()
        ));
        assert!(
            !kernel_rule_matches(&selected, &comm, true, false, false, &ExecPath::unknown()),
            "a rule of a selected policy fired on a cgroup the policy does not select"
        );
        // A policy with no selector carries no such flag and is unaffected by
        // the set in either direction.
        assert!(kernel_rule_matches(
            &unselected,
            &comm,
            true,
            false,
            false,
            &ExecPath::unknown()
        ));
        assert!(kernel_rule_matches(
            &unselected,
            &comm,
            true,
            false,
            true,
            &ExecPath::unknown()
        ));

        assert_eq!(
            kernel_verdict(&[selected], &comm, true, false, false, &ExecPath::unknown()),
            ACTION_ALLOW
        );
        assert_eq!(
            kernel_verdict(&[selected], &comm, true, false, true, &ExecPath::unknown()),
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

        assert_eq!(
            kernel_verdict(&[], &comm, true, false, true, &ExecPath::unknown()),
            ACTION_ALLOW
        );
        assert_eq!(
            kernel_verdict(
                &[KernelRule::empty(); 4],
                &comm,
                true,
                false,
                true,
                &ExecPath::unknown()
            ),
            ACTION_ALLOW,
            "an untouched array must not decide anything"
        );
        assert_eq!(
            kernel_verdict(
                &[used(ACTION_DENY), used(ACTION_KILL)],
                &comm,
                true,
                false,
                true,
                &ExecPath::unknown()
            ),
            ACTION_KILL
        );
        assert_eq!(
            kernel_verdict(
                &[used(ACTION_KILL), used(ACTION_DENY)],
                &comm,
                true,
                false,
                true,
                &ExecPath::unknown()
            ),
            ACTION_KILL,
            "the order of the slots decided the verdict"
        );
        assert!(action_refuses(ACTION_DENY) && action_refuses(ACTION_KILL));
        assert!(!action_refuses(ACTION_ALLOW) && !action_refuses(ACTION_AUDIT));
        // Isolate is not an exec refusal, and is never written into a slot.
        assert!(!action_refuses(ACTION_ISOLATE));
    }

    fn path_rule(prefix: Option<&str>, suffix: Option<&str>) -> KernelRule {
        let mut rule = KernelRule::empty();
        rule.flags = KRULE_FLAG_USED;
        rule.action = ACTION_DENY;
        if let Some(p) = prefix {
            rule.set_prefix(p.as_bytes());
        }
        if let Some(p) = suffix {
            rule.set_suffix(p.as_bytes());
        }
        rule
    }

    fn hits(rule: &KernelRule, path: &ExecPath) -> bool {
        kernel_rule_matches(rule, &[0; COMM_LEN], true, false, true, path)
    }

    /// Prefix and suffix are the string's own head and tail, nothing looser:
    /// a path shorter than the pattern, a pattern in the middle, and the
    /// string `/usr/bin/true` against a `/bin/` prefix (the symlink is not
    /// followed — the predicate is about what was asked for) all miss.
    #[test]
    fn a_path_predicate_is_the_head_or_the_tail_of_the_string() {
        let ok = |p: &str| ExecPath::from_bytes(p.as_bytes(), false);
        let prefix = path_rule(Some("/bin/"), None);
        assert!(hits(&prefix, &ok("/bin/true")));
        assert!(hits(&prefix, &ok("/bin/")));
        assert!(
            !hits(&prefix, &ok("/bin")),
            "a path shorter than the prefix matched it"
        );
        assert!(!hits(&prefix, &ok("/usr/bin/true")));
        assert!(!hits(&prefix, &ok("")));

        let suffix = path_rule(None, Some("docker.sock"));
        assert!(hits(&suffix, &ok("/run/docker.sock")));
        assert!(
            hits(&suffix, &ok("docker.sock")),
            "the whole path is its own suffix"
        );
        assert!(!hits(&suffix, &ok("ocker.sock")));
        assert!(!hits(&suffix, &ok("/run/docker.sock.bak")));
        assert!(!hits(&suffix, &ok("")));

        // Both on one slot: both must hold.
        let both = path_rule(Some("/usr/"), Some("/sh"));
        assert!(hits(&both, &ok("/usr/bin/sh")));
        assert!(!hits(&both, &ok("/bin/sh")));
        assert!(!hits(&both, &ok("/usr/bin/bash")));

        // A suffix compared at the far end of the buffer, where the index
        // mask is what keeps the access inside it.
        // 254 bytes is the longest path that fits; one more fills the buffer
        // and is read as truncated, where a suffix is unknown and asserts.
        let mut tail = "/a".repeat(126);
        tail.push_str("/x");
        assert_eq!(tail.len(), PATH_LEN - 2);
        assert!(hits(&path_rule(None, Some("/x")), &ok(&tail)));
        assert!(!hits(&path_rule(None, Some("/y")), &ok(&tail)));
        tail.push('z');
        assert!(hits(&path_rule(None, Some("/y")), &ok(&tail)));
    }

    /// The fail-closed half of `rule_matches`, in kernel terms: a prefix on a
    /// path that could not be read and a suffix on a path that did not fit are
    /// matches, not misses.
    #[test]
    fn an_unknown_path_asserts_the_predicate_it_cannot_decide() {
        let unreadable = ExecPath::from_bytes(b"", true);
        let head = ExecPath::from_bytes(b"/opt/very/long/head", true);

        assert!(hits(&path_rule(Some("/bin/"), None), &unreadable));
        assert!(hits(&path_rule(None, Some("/sh")), &unreadable));
        // A head that was read decides the prefix; only the suffix is unknown.
        assert!(!hits(&path_rule(Some("/bin/"), None), &head));
        assert!(hits(&path_rule(Some("/opt/"), None), &head));
        assert!(hits(&path_rule(None, Some("/sh")), &head));
    }

    /// A hook that does not know where the path lives decides no path slot.
    ///
    /// Not fail-closed, and on purpose: this is a kernel the build could not
    /// read, not a path an attacker hid, and closing here would refuse every
    /// exec the rule's other predicates allow on every node of that kernel.
    #[test]
    fn a_hook_without_the_layout_decides_no_path_slot_and_every_other_one() {
        let unknown = ExecPath::unknown();
        assert!(!hits(&path_rule(Some("/bin/"), None), &unknown));
        assert!(!hits(&path_rule(None, Some("/sh")), &unknown));
        let mut plain = KernelRule::empty();
        plain.flags = KRULE_FLAG_USED;
        plain.action = ACTION_KILL;
        assert!(
            hits(&plain, &unknown),
            "a slot naming no path stopped matching"
        );
    }

    /// A slot that names a pattern and holds none hits nothing — the empty
    /// pattern `rule_matches` skips — and a length past the slot is corrupt
    /// and matches nothing, the same refusal the comm length gets.
    #[test]
    fn an_empty_or_corrupt_pattern_matches_nothing() {
        let path = ExecPath::from_bytes(b"/bin/true", false);
        let mut empty = path_rule(Some("/"), None);
        empty.prefix_len = 0;
        assert!(!hits(&empty, &path));
        let mut empty = path_rule(None, Some("e"));
        empty.suffix_len = 0;
        assert!(!hits(&empty, &path));

        let mut prefix = path_rule(Some("/bin/"), None);
        prefix.prefix_len = KPATH_LEN as u8 + 1;
        assert!(!hits(&prefix, &path));
        let mut suffix = path_rule(None, Some("true"));
        suffix.suffix_len = KPATH_LEN as u8 + 1;
        assert!(!hits(&suffix, &path));
    }

    /// The setters write what the matcher reads, and nothing of a longer
    /// pattern survives a shorter one written over it.
    #[test]
    fn a_pattern_setter_writes_the_pattern_the_matcher_reads() {
        let mut rule = KernelRule::empty();
        rule.set_prefix(b"/usr/");
        assert!(rule.names_a_path());
        assert_eq!(rule.prefix_len, 5);
        rule.set_prefix(b"/a");
        assert_eq!(rule.prefix_len, 2);
        assert_eq!(&rule.prefix[..3], b"/a\0");
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
