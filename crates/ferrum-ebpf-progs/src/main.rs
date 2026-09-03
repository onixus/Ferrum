//! sys_enter tracepoint programs writing `Event` records into `ferrum_events`.
//!
//! Built only for `target_arch = "bpf"` (bpfel-unknown-none, nightly +
//! build-std); the host build compiles to an empty stub so the stable-1.75
//! workspace gates stay green. Userspace attach stays behind the opt-in
//! `attach` feature of `ferrum-ebpf`.
//!
//! The object this crate produces is not a build artefact of the workspace:
//! the `Dockerfile` copies it in from the build context, at the path
//! `--bpf-elf` names in both shipped DaemonSets, and re-runs the map-ABI
//! inspection against the binary it is being put in the image beside. The
//! Jenkins 'BPF attach' stage is where these programs meet a verifier — that
//! stage, and nothing else in this repository, executes one of their
//! instructions.

#![cfg_attr(target_arch = "bpf", no_std, no_main)]

#[cfg(target_arch = "bpf")]
mod progs {
    use aya_ebpf::{
        helpers::{
            bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes,
            gen::bpf_get_current_cgroup_id,
        },
        macros::{lsm, map, tracepoint},
        maps::{Array, HashMap, PerCpuArray, RingBuf},
        programs::{LsmContext, TracePointContext},
    };
    use ferrum_ebpf_progs::{
        action_rank, action_refuses, kernel_rule_matches, Event, KernelRule, ACTION_ALLOW,
        ACTION_AUDIT, CGROUPS_MAX_ENTRIES, COMM_LEN, EPERM, EVENTS_RING_BYTES,
        EVENT_FLAG_AGENT_SELF, EVENT_FLAG_CONTAINER, EVENT_FLAG_PATH_TRUNCATED, MAX_KERNEL_RULES,
        PATH_LEN,
    };

    // The `#[map(name = ...)]` literals must stay equal to the MAP_* /
    // EVENTS_DROPPED_TOTAL constants in lib.rs; attribute args cannot
    // reference consts.
    #[map(name = "ferrum_events")]
    static FERRUM_EVENTS: RingBuf = RingBuf::with_byte_size(EVENTS_RING_BYTES, 0);

    #[map(name = "events_dropped_total")]
    static EVENTS_DROPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

    #[map(name = "ferrum_self")]
    static FERRUM_SELF: Array<u64> = Array::with_max_entries(1, 0);

    #[map(name = "ferrum_cgroups")]
    static FERRUM_CGROUPS: HashMap<u64, u8> = HashMap::with_max_entries(CGROUPS_MAX_ENTRIES, 0);

    // The rules this side decides on its own. Userspace fills every slot on
    // every policy change — including the ones a shorter policy leaves over,
    // which is what retires the previous one; see `sync_kernel_rules`.
    #[map(name = "ferrum_rules")]
    static FERRUM_RULES: Array<KernelRule> = Array::with_max_entries(MAX_KERNEL_RULES, 0);

    // sys_enter_* record layout: common header (8 bytes), `long id`, then
    // 8-byte argument slots. Reading the syscall nr from the record keeps the
    // programs arch-neutral (x86_64 and aarch64 use different numbers).
    const TP_SYSCALL_NR: usize = 8;
    const TP_ARG0: usize = 16;
    const TP_ARG1: usize = 24;

    #[tracepoint(category = "syscalls", name = "sys_enter_execve")]
    pub fn ferrum_sys_enter_execve(ctx: TracePointContext) -> u32 {
        emit(&ctx, Some(TP_ARG0))
    }

    #[tracepoint(category = "syscalls", name = "sys_enter_execveat")]
    pub fn ferrum_sys_enter_execveat(ctx: TracePointContext) -> u32 {
        emit(&ctx, Some(TP_ARG1))
    }

    #[tracepoint(category = "syscalls", name = "sys_enter_open")]
    pub fn ferrum_sys_enter_open(ctx: TracePointContext) -> u32 {
        emit(&ctx, Some(TP_ARG0))
    }

    #[tracepoint(category = "syscalls", name = "sys_enter_openat")]
    pub fn ferrum_sys_enter_openat(ctx: TracePointContext) -> u32 {
        emit(&ctx, Some(TP_ARG1))
    }

    #[tracepoint(category = "syscalls", name = "sys_enter_bpf")]
    pub fn ferrum_sys_enter_bpf(ctx: TracePointContext) -> u32 {
        emit(&ctx, None)
    }

    #[tracepoint(category = "syscalls", name = "sys_enter_init_module")]
    pub fn ferrum_sys_enter_init_module(ctx: TracePointContext) -> u32 {
        emit(&ctx, None)
    }

    #[tracepoint(category = "syscalls", name = "sys_enter_finit_module")]
    pub fn ferrum_sys_enter_finit_module(ctx: TracePointContext) -> u32 {
        emit(&ctx, None)
    }

    /// Refuse an exec the loaded rules refuse, before it happens.
    ///
    /// This used to read `ferrum_cgroups` and compare its value against
    /// `ACTION_DENY`/`ACTION_KILL`. That map is a set of the cgroups that
    /// belong to pod containers and its value is the constant 1 written by
    /// `insert_container_cgroup` — `ACTION_AUDIT` — so the comparison was
    /// never true and the hook refused nothing while reporting itself
    /// attached. The verdict now comes from `ferrum_rules`, which holds
    /// rules and nothing else.
    ///
    /// What this hook decides is bounded by what it can see, and the bound is
    /// enforced on the other side: `compile_kernel_rules` puts a rule here
    /// only when every one of its predicates is answerable from `comm`, the
    /// container flag and the agent's own tgid. Rules naming a path — the §D
    /// acceptance case among them — never reach this map and stay on the
    /// tracepoint path, which still matches and still reports them.
    ///
    /// The walk visits every slot and never breaks early: a fixed trip count
    /// is what makes this shape acceptable to the verifier. `kernel_rule_matches`
    /// is the same function userspace tests against `eval::rule_matches`, so
    /// the predicate cannot drift; only this loop is written twice, and it is
    /// three lines of "strongest wins".
    #[lsm(hook = "bprm_check_security")]
    pub fn ferrum_bprm_check_security(_ctx: LsmContext) -> i32 {
        let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        let in_container = FERRUM_CGROUPS.get_ptr(&cgroup_id).is_some();
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let agent_self = match FERRUM_SELF.get(0) {
            Some(self_tgid) => *self_tgid != 0 && *self_tgid == u64::from(tgid),
            None => false,
        };
        // An unreadable comm is the empty name, which matches only rules that
        // name no comm at all. Not a refusal on its own: a hook that denies
        // when it cannot read the caller's name denies every exec on a kernel
        // that stops answering the helper.
        let comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);

        let mut verdict = ACTION_ALLOW;
        let mut index = 0;
        while index < MAX_KERNEL_RULES {
            if let Some(rule) = FERRUM_RULES.get(index) {
                if kernel_rule_matches(rule, &comm, in_container, agent_self)
                    && action_rank(rule.action) > action_rank(verdict)
                {
                    verdict = rule.action;
                }
            }
            index += 1;
        }
        if action_refuses(verdict) {
            -EPERM
        } else {
            0
        }
    }

    #[inline(always)]
    fn emit(ctx: &TracePointContext, path_arg: Option<usize>) -> u32 {
        let mut event = Event::new();
        event.syscall_nr = match unsafe { ctx.read_at::<i64>(TP_SYSCALL_NR) } {
            Ok(nr) => nr as u32,
            Err(_) => return 0,
        };
        let pid_tgid = bpf_get_current_pid_tgid();
        event.tgid = (pid_tgid >> 32) as u32;
        event.pid = pid_tgid as u32;
        event.cgroup_id = unsafe { bpf_get_current_cgroup_id() };
        // Verdicts are userspace policy in this slice; the kernel side only
        // observes, so every record carries audit.
        event.action = ACTION_AUDIT;
        if let Ok(comm) = bpf_get_current_comm() {
            event.comm = comm;
        }
        if FERRUM_CGROUPS.get_ptr(&event.cgroup_id).is_some() {
            event.flags |= EVENT_FLAG_CONTAINER;
        }
        if let Some(self_tgid) = FERRUM_SELF.get(0) {
            if *self_tgid != 0 && *self_tgid == u64::from(event.tgid) {
                event.flags |= EVENT_FLAG_AGENT_SELF;
            }
        }
        if let Some(offset) = path_arg {
            // Both failures set one flag: the buffer already distinguishes
            // them. A path longer than PATH_LEN leaves a valid-looking head,
            // and an unreadable pointer (the helper cannot fault in a
            // non-resident page) leaves the buffer as `Event::new` left it —
            // empty. Either way the recorded bytes are not the argument.
            // Straight-line code only — no extra branching on the pointer, no
            // loops.
            //
            // Truncation is not an Err. `bpf_probe_read_user_str` truncates
            // and returns the buffer size, which is inside the bounds aya's
            // wrapper checks, so it answers Ok with a PATH_LEN-1 byte slice —
            // measured on 6.18/x86_64, a 384-byte pathname came back as a
            // 255-byte head and nothing was flagged. So the length decides:
            // anything that reached the last usable byte did not fit.
            let read_len = match unsafe { ctx.read_at::<*const u8>(offset) } {
                Ok(ptr) => unsafe { bpf_probe_read_user_str_bytes(ptr, &mut event.path) }
                    .map(|read| read.len()),
                Err(err) => Err(err),
            };
            let fits = match read_len {
                Ok(len) => len < PATH_LEN - 1,
                Err(_) => false,
            };
            if !fits {
                event.flags |= EVENT_FLAG_PATH_TRUNCATED;
            }
        }
        match FERRUM_EVENTS.reserve::<Event>(0) {
            Some(mut slot) => {
                slot.write(event);
                slot.submit(0);
            }
            None => {
                // Ring full: drop in kernel and count. Userspace surfaces the
                // per-CPU sum as events_dropped_total; never stall the caller.
                if let Some(count) = EVENTS_DROPPED.get_ptr_mut(0) {
                    unsafe { *count = (*count).wrapping_add(1) };
                }
            }
        }
        0
    }

    #[panic_handler]
    fn panic(_info: &core::panic::PanicInfo) -> ! {
        loop {}
    }
}

#[cfg(not(target_arch = "bpf"))]
fn main() {}
