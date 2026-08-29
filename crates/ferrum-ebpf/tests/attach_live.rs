//! The shipped ELF, in a real kernel.
//!
//! `tests/elf_inspect.rs` reads the ELF; this one loads it. Everything checked
//! here is unobservable by reading: the verifier's opinion of the datapath
//! programs, the `sys_enter_*` record offsets `TP_SYSCALL_NR`/`TP_ARG0`/
//! `TP_ARG1`, what `EVENT_FLAG_PATH_TRUNCATED` actually means for a path the
//! kernel could not carry whole, and whether `EVENT_FLAG_AGENT_SELF` tells the
//! agent apart from everybody else.
//!
//! The ELF comes from `FERRUM_BPF_ELF`, and there are exactly three reasons
//! anything here declines to run. Two are checked *before* the code under
//! test: the env var is unset, so there is no ELF to load; or this kernel
//! exposes *no* datapath tracepoint at all (read from tracefs, not inferred
//! from a failure), leaving nothing to measure. A kernel missing only *some*
//! of them — one built without `CONFIG_MODULES` has no `init_module` — is not
//! a reason to decline: the attach narrows the enforceable set and says which
//! syscalls it dropped, and that report is checked here against tracefs.
//! `FERRUM_BPF_ELF_REQUIRED` — which the Jenkins stage sets — turns both of
//! those skips into failures. An attach that fails for any *other* reason is
//! always a failure: a test that returns green when the load refuses would be
//! the fail-open this gate exists to close.
//!
//! The third reason is the one no assertion inside the gate can reach. Built
//! without `--features attach`, every test below is compiled out; the binary
//! then runs zero tests and exits 0. A dropped or renamed feature flag on the
//! Jenkins line would turn the only stage that puts the datapath in a kernel
//! into a green no-op, and `FERRUM_BPF_ELF_REQUIRED` could not say so, because
//! the code that reads it would not have been compiled. So that check lives
//! outside the `cfg`: `the_gate_must_not_be_compiled_out` is the one test here
//! that survives a build without the feature, and it fails whenever
//! `FERRUM_BPF_ELF_REQUIRED` says a real gate was expected. A default
//! `cargo test --workspace`, which sets no such thing, still passes.
//!
//! Needs CAP_BPF/root and tracefs.

/// The gate, compiled out.
///
/// `FERRUM_BPF_ELF_REQUIRED` is the caller's statement that this run *is* the
/// gate and not a default workspace build. Without the `attach` feature there
/// is nothing left in this binary to honour it, so this is the only place that
/// can refuse — and it is deliberately outside the `cfg` that would remove it.
#[cfg(not(feature = "attach"))]
#[test]
fn the_gate_must_not_be_compiled_out() {
    assert!(
        std::env::var_os("FERRUM_BPF_ELF_REQUIRED").is_none(),
        "FERRUM_BPF_ELF_REQUIRED is set, but this binary was built without \
         --features attach: every kernel test in attach_live.rs is compiled out, \
         so this run executed nothing against a kernel and proves nothing about \
         the datapath. Add --features attach."
    );
}

#[cfg(feature = "attach")]
mod gate {
    use std::ffi::CString;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use ferrum_ebpf::{
        decode_event, syscall_name, tracepoint_syscall, tracepoints_absent_on_arch,
        tracepoints_for_arch, Event, KernelHandle, RingReader, SyscallArch, DATAPATH_ABI,
        EVENT_FLAG_AGENT_SELF, EVENT_FLAG_PATH_TRUNCATED, PATH_LEN,
    };
    use ferrum_ebpf_progs::ACTION_AUDIT;

    /// Every test attaches system-wide tracepoints and then filters the ring by
    /// tgid — the *same* tgid for every test in this binary. Two at once would put
    /// one test's syscalls in the other's ring, so they take turns; threads parked
    /// on this lock make no syscalls.
    fn serialized() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = LOCK.get_or_init(|| Mutex::new(()));
        lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The compiled ELF, or None when there is nothing to load.
    fn elf_or_skip() -> Option<(String, Vec<u8>)> {
        let Ok(path) = std::env::var("FERRUM_BPF_ELF") else {
            if required() {
                panic!("FERRUM_BPF_ELF_REQUIRED is set but FERRUM_BPF_ELF is not");
            }
            println!("skipping: FERRUM_BPF_ELF not set (no compiled bpf ELF to load)");
            return None;
        };
        let elf = std::fs::read(&path).unwrap_or_else(|err| panic!("read {path}: {err}"));
        Some((path, elf))
    }

    fn required() -> bool {
        std::env::var_os("FERRUM_BPF_ELF_REQUIRED").is_some()
    }

    /// The syscalls this arch's datapath wants that the *running kernel* does not
    /// expose a tracepoint for, read straight from tracefs.
    ///
    /// This is a fact about the environment, established before anything is
    /// loaded — not a failure of the code under test. A kernel built without
    /// loadable module support has no `init_module`/`finit_module` syscall and so
    /// no tracepoint for either; `KernelHandle::attach_for_arch` skips those and
    /// reports them, and this is the independent second opinion its report is
    /// checked against — read here with a different code path than the one under
    /// test, so a probe that answered "absent" for everything could not pass.
    fn absent_from_tracefs(arch: SyscallArch) -> Vec<&'static str> {
        tracepoints_for_arch(arch)
            .into_iter()
            .filter(|(_, category, name)| {
                !["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
                    .iter()
                    .any(|root| {
                        std::path::Path::new(&format!("{root}/events/{category}/{name}/id"))
                            .exists()
                    })
            })
            .filter_map(tracepoint_syscall)
            .collect()
    }

    /// Every datapath syscall with no hook on this node: absent from the arch, or
    /// absent from this kernel. What `KernelHandle::unhooked_syscalls` must name.
    fn expected_unhooked(arch: SyscallArch) -> Vec<&'static str> {
        let mut all = tracepoints_absent_on_arch(arch);
        all.extend(absent_from_tracefs(arch));
        all.sort_unstable();
        all
    }

    /// The kernel accounts BPF memory to the cgroup since 5.11, but older ones
    /// charge RLIMIT_MEMLOCK and a default 8 MiB does not fit the ring plus the
    /// cgroup hash. Raise it rather than let the load fail for a reason that has
    /// nothing to do with the datapath.
    fn raise_memlock() {
        let unlimited = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        // Best effort: without CAP_SYS_RESOURCE this fails and the load below is
        // what reports the real problem.
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &unlimited) };
    }

    /// A loaded datapath with its ring in hand.
    ///
    /// Always through `KernelHandle::attach_for_arch`, which is the path
    /// production takes and the one this gate is about. A kernel missing a
    /// tracepoint the datapath wants no longer kills the attach: the hook is
    /// skipped and named in `unhooked_syscalls`, and this file asserts the handle
    /// names exactly the set tracefs says is missing.
    struct Live {
        arch: SyscallArch,
        ring: RingReader,
        handle: KernelHandle,
    }

    fn live() -> Option<Live> {
        let (path, elf) = elf_or_skip()?;
        raise_memlock();
        let arch = SyscallArch::host().expect("no syscall decode table for this arch");
        let unhooked = expected_unhooked(arch);

        // Nothing left to hook at all: the attach must refuse (a handle with no
        // hooks is a blind runtime plane reported as healthy), and there is
        // nothing for the checks below to measure.
        if unhooked.len() == ferrum_ebpf::TRACEPOINTS.len() {
            let err = match KernelHandle::attach_for_arch(&elf, arch) {
                Ok(_) => {
                    panic!("this kernel has no datapath tracepoint at all, yet attach succeeded")
                }
                Err(err) => err.to_string(),
            };
            assert!(
                !err.contains("load eBPF ELF"),
                "the ELF itself would not load: {err}"
            );
            if required() {
                panic!(
                    "FERRUM_BPF_ELF_REQUIRED is set, but this kernel exposes no datapath \
                     tracepoint at all ({err}). Run this stage on a kernel with tracefs."
                );
            }
            println!("skipping: no datapath tracepoint on this kernel ({err})");
            return None;
        }

        let mut handle = KernelHandle::attach_for_arch(&elf, arch)
            .unwrap_or_else(|err| panic!("attach {path} on {}: {err}", arch.as_str()));
        // The narrowed enforceable set is not free, and the handle is the only
        // thing that carries it to the operator. It must name exactly what is
        // missing: a syscall it omits is a rule silently dead on this node, and
        // one it invents is a hook reported blind that is in fact live.
        let mut reported = handle.unhooked_syscalls().to_vec();
        reported.sort_unstable();
        assert_eq!(
            reported,
            unhooked,
            "the handle's unhooked set disagrees with tracefs on {}",
            arch.as_str()
        );
        handle
            .set_self_tgid(u64::from(std::process::id()))
            .expect("publish self tgid into ferrum_self");
        let ring = handle.take_ring_reader().expect("take ferrum_events");
        Some(Live { arch, ring, handle })
    }

    /// Records left by one syscall, split by who made it.
    struct Observed {
        /// Records whose tgid is this process's — the tgid published into
        /// `ferrum_self`.
        events: Vec<Event>,
        /// Records from every other tgid on the node. Kept rather than
        /// dropped: `EVENT_FLAG_AGENT_SELF` is only meaningful if it is
        /// *absent* here, and nothing else in this file can see that.
        others: Vec<Event>,
    }

    impl Live {
        /// Run `make_syscall` and collect the records it left, separating this
        /// process's from everybody else's. The ring is drained empty first: it
        /// is system-wide, and everything already in it predates the syscall.
        fn observe(&mut self, make_syscall: impl FnOnce()) -> Observed {
            let tgid = std::process::id();
            // Two passes: the first empties what the attach itself and the rest of
            // the system produced, the second catches records the first raced past.
            self.ring.drain(|_| {});
            self.ring.drain(|_| {});

            make_syscall();

            let mut events = Vec::new();
            let mut others = Vec::new();
            self.ring.drain(|bytes| {
                let event = decode_event(bytes).expect("decode_event rejected a live ring record");
                if event.tgid == tgid {
                    events.push(event);
                } else {
                    others.push(event);
                }
            });
            Observed { events, others }
        }
    }

    fn path_bytes(event: &Event) -> &[u8] {
        let end = event
            .path
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(event.path.len());
        &event.path[..end]
    }

    fn comm(event: &Event) -> String {
        let end = event
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(event.comm.len());
        String::from_utf8_lossy(&event.comm[..end]).into_owned()
    }

    /// The one record for `syscall`, or a panic naming what did arrive.
    fn only(observed: &Observed, arch: SyscallArch, syscall: &str) -> Event {
        let hits: Vec<&Event> = observed
            .events
            .iter()
            .filter(|e| syscall_name(arch, e.syscall_nr) == Some(syscall))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "expected exactly one {syscall} record from this process, got {} out of {:?}",
            hits.len(),
            observed
                .events
                .iter()
                .map(|e| (e.syscall_nr, syscall_name(arch, e.syscall_nr)))
                .collect::<Vec<_>>()
        );
        *hits[0]
    }

    /// What every record carries regardless of who made it: this build's
    /// stamp, audit, a live thread id, a cgroup and a decodable syscall nr.
    fn assert_common_shape(event: &Event, arch: SyscallArch) {
        assert_eq!(
            event._pad, DATAPATH_ABI,
            "record stamp disagrees with this decoder"
        );
        assert_eq!(event.action, ACTION_AUDIT, "datapath verdict is not audit");
        assert_ne!(event.pid, 0, "no thread id on the record");
        assert_ne!(event.cgroup_id, 0, "no cgroup id on the record");
        assert!(
            syscall_name(arch, event.syscall_nr).is_some(),
            "syscall_nr {} is not one this arch's table knows: TP_SYSCALL_NR is wrong for {}",
            event.syscall_nr,
            arch.as_str()
        );
        assert!(!comm(event).is_empty(), "no comm on the record");
    }

    /// A record from *this* process, whose tgid `live()` published into
    /// `ferrum_self`: the common shape, plus the agent-self flag set.
    ///
    /// On its own this half proves nothing about the flag — a datapath that
    /// sets it unconditionally satisfies every call here. The other half is
    /// `a_foreign_record_is_not_flagged_agent_self`.
    fn assert_record_shape(event: &Event, arch: SyscallArch) {
        assert_common_shape(event, arch);
        assert_eq!(event.tgid, std::process::id(), "wrong tgid");
        assert!(
            event.flags & EVENT_FLAG_AGENT_SELF != 0,
            "ferrum_self was published with this tgid but the record is not flagged agent-self"
        );
    }

    /// The invariant: the shipped ELF loads, every tracepoint this arch has
    /// attaches, and one `openat` from this process produces exactly one ring
    /// record `decode_event` accepts, carrying this build's `DATAPATH_ABI`, the
    /// arch-correct syscall nr, this process's tgid and the path that was passed.
    ///
    /// `openat` takes its pathname in the second argument slot, so this is also
    /// the only check `TP_ARG1` has ever had against a kernel.
    #[test]
    fn openat_produces_one_decodable_record() {
        let _serial = serialized();
        let Some(mut live) = live() else {
            return;
        };
        let arch = live.arch;

        let target = format!("/tmp/ferrum-attach-live-{}-openat", std::process::id());
        let c_target = CString::new(target.clone()).expect("path has no NUL");
        let observed = live.observe(|| {
            // Must fail: this only has to reach sys_enter, and a real open would
            // leave a descriptor behind.
            let fd = unsafe { libc::openat(libc::AT_FDCWD, c_target.as_ptr(), libc::O_RDONLY) };
            assert_eq!(fd, -1, "the probe path must not exist");
        });

        let event = only(&observed, arch, "openat");
        assert_record_shape(&event, arch);
        assert_eq!(
            String::from_utf8_lossy(path_bytes(&event)),
            target,
            "TP_ARG1 does not point at the openat pathname on {}",
            arch.as_str()
        );
        assert_eq!(
            event.flags & EVENT_FLAG_PATH_TRUNCATED,
            0,
            "a {}-byte path fits in PATH_LEN={PATH_LEN} but was flagged truncated",
            target.len()
        );

        // The counter the agent surfaces as events_dropped_total is readable off a
        // loaded handle, not only from the aya type checker.
        live.handle
            .events_dropped_total()
            .expect("read events_dropped_total off a live handle");
        println!(
            "attached through KernelHandle on {}; unhooked on this node: {:?}",
            arch.as_str(),
            live.handle.unhooked_syscalls()
        );
    }

    /// `execve` carries its pathname in the *first* argument slot; nothing has
    /// ever checked `TP_ARG0` against a kernel.
    #[test]
    fn execve_path_comes_from_the_first_argument_slot() {
        let _serial = serialized();
        let Some(mut live) = live() else {
            return;
        };
        let arch = live.arch;

        let target = format!("/tmp/ferrum-attach-live-{}-execve", std::process::id());
        let c_target = CString::new(target.clone()).expect("path has no NUL");
        let argv = [std::ptr::null::<libc::c_char>()];
        let observed = live.observe(|| {
            // Nonexistent, so sys_enter fires and the exec never happens: this
            // process survives to read the ring.
            let rc = unsafe { libc::execve(c_target.as_ptr(), argv.as_ptr(), argv.as_ptr()) };
            assert_eq!(rc, -1, "the probe path must not be executable");
        });

        let event = only(&observed, arch, "execve");
        assert_record_shape(&event, arch);
        assert_eq!(
            String::from_utf8_lossy(path_bytes(&event)),
            target,
            "TP_ARG0 does not point at the execve pathname on {}",
            arch.as_str()
        );
    }

    /// A syscall with no path argument leaves the buffer empty and unflagged.
    /// `bpf()` not made by the agent is an RFC §D acceptance case and its rule
    /// carries no path predicate; a spurious truncation flag here would make
    /// every path rule in the spec apply to it.
    #[test]
    fn a_syscall_without_a_path_argument_is_not_flagged() {
        let _serial = serialized();
        let Some(mut live) = live() else {
            return;
        };
        let arch = live.arch;

        let observed = live.observe(|| {
            // Invalid command, so nothing is created; sys_enter still fires.
            unsafe { libc::syscall(libc::SYS_bpf, -1, std::ptr::null::<libc::c_void>(), 0usize) };
        });

        let event = only(&observed, arch, "bpf");
        assert_record_shape(&event, arch);
        assert!(path_bytes(&event).is_empty(), "bpf() has no pathname");
        assert_eq!(
            event.flags & EVENT_FLAG_PATH_TRUNCATED,
            0,
            "a syscall the datapath reads no path for was flagged path-truncated"
        );
    }

    /// A pointer the helper cannot read.
    ///
    /// `bpf_probe_read_user_str` runs with page faults disabled, so an untouched
    /// anonymous page is unreadable to it while the syscall itself proceeds
    /// normally. The datapath must flag the record *and* leave the buffer empty:
    /// that pair is what `eval::rule_matches` reads as "nothing about the path is
    /// known", the only case in which neither a prefix nor a suffix predicate may
    /// reject.
    #[test]
    fn unreadable_path_pointer_is_flagged_with_an_empty_buffer() {
        let _serial = serialized();
        let Some(mut live) = live() else {
            return;
        };
        let arch = live.arch;

        let observed = live.observe(|| {
            let page = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(page, libc::MAP_FAILED, "mmap for the probe page failed");
            // Deliberately never written to: a written page is resident and the
            // helper would read it happily.
            let rc = unsafe {
                libc::openat(libc::AT_FDCWD, page.cast::<libc::c_char>(), libc::O_RDONLY)
            };
            assert_eq!(rc, -1, "an empty pathname must not open");
            unsafe { libc::munmap(page, 4096) };
        });

        let event = only(&observed, arch, "openat");
        assert_record_shape(&event, arch);
        let path = path_bytes(&event);
        assert!(
            event.flags & EVENT_FLAG_PATH_TRUNCATED != 0,
            "an unreadable path pointer left the record unflagged: every path predicate \
             would then be decided against an empty buffer"
        );
        assert!(
            path.is_empty(),
            "the helper failed but {} bytes reached the buffer; eval::rule_matches derives \
             path_unreadable from the buffer being empty",
            path.len()
        );
    }

    /// A path longer than `PATH_LEN`. This is the finding the file was written
    /// for, and the assertions record what the kernel and aya *do*, not what the
    /// datapath comment claims.
    ///
    /// Cycle 8 measured this on Linux 6.18/x86_64 with a 384-byte pathname: the
    /// record carried the 255-byte head and `EVENT_FLAG_PATH_TRUNCATED` was **not**
    /// set. `bpf_probe_read_user_str` returns the buffer size on truncation, which
    /// is inside the bounds `aya_ebpf`'s wrapper checks, so the wrapper returned
    /// `Ok` and `emit()` — flagging only on `Err` — set nothing. The consequence
    /// was a fail-open on an RFC §D acceptance case: a `path_suffix` rule for
    /// `/var/run/docker.sock` silently failed to match a path over `PATH_LEN`,
    /// with `is_degraded()` false and no signal anywhere.
    ///
    /// `emit()` now decides on the length instead: a read that reached the last
    /// usable byte did not fit. This assertion is the only place that can tell
    /// whether the kernel agrees, so it asserts the corrected behaviour — the head
    /// intact, and the flag set.
    #[test]
    fn a_long_path_arrives_as_a_flagged_head() {
        let _serial = serialized();
        let Some(mut live) = live() else {
            return;
        };
        let arch = live.arch;

        let prefix = format!("/tmp/ferrum-attach-live-{}-long/", std::process::id());
        let mut target = prefix.clone();
        while target.len() < PATH_LEN + 128 {
            target.push('a');
        }
        let c_target = CString::new(target.clone()).expect("path has no NUL");
        let observed = live.observe(|| {
            let rc = unsafe { libc::openat(libc::AT_FDCWD, c_target.as_ptr(), libc::O_RDONLY) };
            assert_eq!(rc, -1, "the probe path must not exist");
        });

        let event = only(&observed, arch, "openat");
        assert_record_shape(&event, arch);
        let path = path_bytes(&event);
        println!(
            "long path: {} bytes passed, flags={:#04x}, {} bytes recorded",
            target.len(),
            event.flags,
            path.len()
        );

        assert!(
            path.starts_with(prefix.as_bytes()),
            "the head of a truncated path is not the head of the argument"
        );
        assert!(
            path.len() < target.len(),
            "a {}-byte path came back whole out of a {PATH_LEN}-byte buffer",
            target.len()
        );
        assert_eq!(
            path.len(),
            PATH_LEN - 1,
            "the helper spends the last byte on a terminator, so a truncated read fills the \
             buffer to exactly this length; anything else means the length test in emit() is \
             comparing against the wrong bound"
        );
        assert_ne!(
            event.flags & EVENT_FLAG_PATH_TRUNCATED,
            0,
            "a path the datapath could not carry whole is unflagged: eval::rule_matches then \
             lets a path_suffix predicate reject on a tail nobody saw, which is the fail-open \
             on the docker.sock acceptance case"
        );
        // Both halves of the flag's contract, on one record: flagged, and not
        // empty. That pair is what eval::rule_matches reads as "the head is real,
        // the tail is unknown" — a prefix predicate still decides, a suffix one
        // may not reject.
        assert!(
            !path.is_empty(),
            "a truncated head must not read as -EFAULT"
        );
    }

    /// `EVENT_FLAG_AGENT_SELF` must be *absent* on a record somebody else made.
    ///
    /// Every other test here filters the ring to its own tgid and asserts the
    /// flag is set, which a datapath that sets it unconditionally passes just
    /// as happily — a `ferrum_self` read that returned 0, or a comparison
    /// written the wrong way round. In production that exempts every process
    /// on the node from every `notAgentSelf` rule, including the RFC §D
    /// `bpf() not from the agent → deny` case: the one rule whose whole
    /// predicate is this flag.
    ///
    /// The foreign record is manufactured rather than scavenged. Waiting for
    /// the ring to happen to contain one from another process would make a
    /// quiet no-match indistinguishable from a pass, which is the same defect
    /// this test exists to close — so a child is forked, given a pathname only
    /// it will open, and reaped before the ring is read. The assertions then
    /// pin the record to that child by both tgid and path, and the test fails
    /// if no such record arrived.
    #[test]
    fn a_foreign_record_is_not_flagged_agent_self() {
        let _serial = serialized();
        let Some(mut live) = live() else {
            return;
        };
        let arch = live.arch;

        let target = format!("/tmp/ferrum-attach-live-{}-foreign", std::process::id());
        let c_target = CString::new(target.clone()).expect("path has no NUL");
        let child = std::cell::Cell::new(-1);
        let observed = live.observe(|| {
            // Between fork and _exit the child touches nothing but the openat
            // it is here to make: the test harness is multi-threaded, and only
            // this thread survives into the child.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe {
                    // Read one byte of the pathname before passing it. Not
                    // ceremony: `bpf_probe_read_user_str` does not fault, and
                    // on the aarch64 6.12 node this stage runs on, the page
                    // holding this string is not reachable to it in a child
                    // that has done nothing since `fork` — the record then
                    // arrives with an empty path and
                    // `EVENT_FLAG_PATH_TRUNCATED`, and the pathname this test
                    // identifies the child's record by is gone. Faulting it in
                    // restores the identification without weakening what is
                    // asserted below, which is about the agent-self flag and
                    // not about path readability. The behaviour that made this
                    // necessary is itself gated, one test down, because a
                    // datapath that reported the same empty path *without* the
                    // flag would take every path rule out silently.
                    std::ptr::read_volatile(c_target.as_ptr());
                    libc::openat(libc::AT_FDCWD, c_target.as_ptr(), libc::O_RDONLY);
                    libc::_exit(0);
                }
            }
            assert!(pid > 0, "fork failed");
            child.set(pid);
            // Reaped before the ring is read, so the record is already in it.
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(pid, &mut status, 0) },
                pid,
                "waitpid on the probe child failed"
            );
        });

        let child_tgid = u32::try_from(child.get()).expect("child pid");
        assert_ne!(
            child_tgid,
            std::process::id(),
            "the 'foreign' record would have come from this very process"
        );

        let hits: Vec<&Event> = observed
            .others
            .iter()
            .filter(|e| e.tgid == child_tgid)
            .collect();
        // Identified by the pathname only the child passed, so this cannot be
        // satisfied by an unrelated process that happened to be running: a
        // vacuous pass here would restore exactly the hole this test closes.
        assert!(
            hits.iter().any(|e| {
                syscall_name(arch, e.syscall_nr) == Some("openat")
                    && path_bytes(e) == target.as_bytes()
            }),
            "the forked child opened {target} but no such record reached the ring: \
             there is nothing foreign to check the agent-self flag against, and the \
             assertions below would pass without having looked at anything. Saw {:?}",
            hits.iter()
                .map(|e| (e.tgid, syscall_name(arch, e.syscall_nr)))
                .collect::<Vec<_>>()
        );

        for event in &hits {
            assert_common_shape(event, arch);
            assert_eq!(
                event.flags & EVENT_FLAG_AGENT_SELF,
                0,
                "a record from tgid {child_tgid} is flagged agent-self, but ferrum_self \
                 holds {}: the datapath sets EVENT_FLAG_AGENT_SELF for everyone, so every \
                 process on this node is exempt from every notAgentSelf rule — including \
                 `bpf() not from the agent → deny`",
                std::process::id()
            );
        }
        println!(
            "foreign records from tgid {child_tgid}: {}, none flagged agent-self",
            hits.len()
        );
    }

    /// A path this kernel could not read is never reported as a short one.
    ///
    /// Measured on the arm64 node this stage runs on, and it does not happen
    /// on the x86_64 stand every `K` row in `docs/MVP-1-BOUNDARY.md` was taken
    /// against: a child that calls `openat` having done nothing since `fork`
    /// passes a pathname `bpf_probe_read_user_str` cannot reach — the helper
    /// does not fault, and the page is not there for it yet. Two outcomes are
    /// therefore legitimate and this test accepts both.
    ///
    /// What it refuses is the third: an empty path with no flag. That record
    /// is indistinguishable from a syscall that carried no path at all, and
    /// `matched_action` decides the two differently on purpose — an unreadable
    /// path asserts the match and sets `path_unknown`
    /// (`lib.rs::an_unreadable_path_still_kills_on_the_runtime_sock_rule`),
    /// while an honest empty one does not match. So a datapath that dropped
    /// the flag here would not fail loudly; it would quietly take every
    /// `pathPrefix` and `pathSuffix` rule out of force for any process in this
    /// state, on the arch where the state occurs. That is the fail-open this
    /// test exists to close, and nothing in userspace can close it: whether
    /// the flag is set is decided in the kernel.
    #[test]
    fn a_path_this_kernel_could_not_read_is_never_reported_as_a_short_one() {
        let _serial = serialized();
        let Some(mut live) = live() else {
            return;
        };
        let arch = live.arch;

        let target = format!("/tmp/ferrum-attach-live-{}-unfaulted", std::process::id());
        let c_target = CString::new(target.clone()).expect("path has no NUL");
        let child = std::cell::Cell::new(-1);
        let observed = live.observe(|| {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe {
                    // Deliberately not touched first: that is the state under
                    // test.
                    libc::openat(libc::AT_FDCWD, c_target.as_ptr(), libc::O_RDONLY);
                    libc::_exit(0);
                }
            }
            assert!(pid > 0, "fork failed");
            child.set(pid);
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(pid, &mut status, 0) },
                pid,
                "waitpid on the probe child failed"
            );
        });

        let child_tgid = u32::try_from(child.get()).expect("child pid");
        let hits: Vec<&Event> = observed
            .others
            .iter()
            .filter(|e| e.tgid == child_tgid && syscall_name(arch, e.syscall_nr) == Some("openat"))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "the child's openat did not reach the ring at all, so this test looked at \
             nothing: {:?}",
            observed
                .others
                .iter()
                .map(|e| (e.tgid, syscall_name(arch, e.syscall_nr)))
                .collect::<Vec<_>>()
        );
        let event = hits[0];
        assert_common_shape(event, arch);

        let path = path_bytes(event);
        let flagged = event.flags & EVENT_FLAG_PATH_TRUNCATED != 0;
        if path == target.as_bytes() {
            assert!(
                !flagged,
                "the whole path arrived and is still flagged truncated: the flag would then \
                 mean nothing, and `path_unknown` would be set on records whose path is known"
            );
            println!("unfaulted child path: read whole on {}", arch.as_str());
        } else {
            assert!(
                path.is_empty(),
                "the path is neither whole nor empty: {:?}. This test knows two outcomes and \
                 has met a third, which nothing here decides.",
                String::from_utf8_lossy(path)
            );
            assert!(
                flagged,
                "the path arrived empty with no EVENT_FLAG_PATH_TRUNCATED. That record is \
                 indistinguishable from a syscall that carried no path, and matched_action \
                 decides the two differently: an unreadable path asserts the match, an \
                 honest empty one does not. Every pathPrefix and pathSuffix rule is out of \
                 force for this process, silently, on this arch."
            );
            println!(
                "unfaulted child path: unreadable and flagged on {}",
                arch.as_str()
            );
        }
    }

    /// `attach_for_arch` raises the soft `RLIMIT_MEMLOCK` it loads under.
    ///
    /// The wiring, not the function. `raise_memlock()` had two unit tests, both
    /// calling it directly, and nothing anywhere asserted that the production
    /// attach path calls it at all: deleting that one line left every test in
    /// this workspace green while the boundary document went on claiming the
    /// raise happens inside the call that charges the memory — the whole
    /// architectural argument for the raise living in `ferrum-ebpf` rather than
    /// in each caller.
    ///
    /// Measured by lowering the soft limit and reading it back afterwards, so
    /// the observable is the raise itself and not the load. It has to be: this
    /// kernel charges BPF memory to the cgroup, so a low `RLIMIT_MEMLOCK` does
    /// not stop the load here and the attach succeeding proves nothing either
    /// way. The lowered value is deliberately not zero for the same reason —
    /// a load that failed would be a different fact.
    ///
    /// `live()` is not used: it raises the limit itself, before anything under
    /// test runs.
    #[test]
    fn attach_raises_the_soft_memlock_it_loads_under() {
        let _serial = serialized();
        let Some((path, elf)) = elf_or_skip() else {
            return;
        };
        let arch = SyscallArch::host().expect("no syscall decode table for this arch");
        if expected_unhooked(arch).len() == ferrum_ebpf::TRACEPOINTS.len() {
            if required() {
                panic!(
                    "FERRUM_BPF_ELF_REQUIRED is set, but this kernel exposes no datapath \
                     tracepoint at all. Run this stage on a kernel with tracefs."
                );
            }
            println!("skipping: no datapath tracepoint on this kernel");
            return;
        }

        let mut before = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut before) },
            0,
            "RLIMIT_MEMLOCK is unreadable on this node"
        );
        // Small enough that the raise has somewhere to go, large enough that a
        // kernel which does charge this would still be the one reporting it.
        let lowered = libc::rlimit {
            rlim_cur: 64 * 1024,
            rlim_max: before.rlim_max,
        };
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lowered) },
            0,
            "could not lower RLIMIT_MEMLOCK: this test cannot measure anything"
        );

        let attached = KernelHandle::attach_for_arch(&elf, arch);

        let mut after = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let read = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut after) };
        // Put it back before anything can fail: every other test in this binary
        // loads under whatever this one leaves behind.
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &before) };

        attached.unwrap_or_else(|err| panic!("attach {path} on {}: {err}", arch.as_str()));
        assert_eq!(
            read, 0,
            "RLIMIT_MEMLOCK became unreadable across the attach"
        );
        assert_eq!(
            after.rlim_cur, before.rlim_max,
            "attach_for_arch loaded under a soft RLIMIT_MEMLOCK of {} it never raised to the hard \
             {}. On a kernel before 5.11 the ring and the cgroup hash are charged against that \
             soft limit, so the load an operator gets is the one this node just avoided by \
             accident",
            after.rlim_cur, before.rlim_max
        );
    }

    /// The cgroup map the agent rewrites on every index tick takes inserts and
    /// removals from a loaded handle, and the handle's mirror follows.
    #[test]
    fn cgroup_map_round_trips_on_a_live_handle() {
        let _serial = serialized();
        let Some(mut live) = live() else {
            return;
        };
        let handle = &mut live.handle;
        let id = 0xfe11_0000_0000_0001;
        handle
            .insert_container_cgroup(id)
            .expect("insert into ferrum_cgroups");
        handle
            .remove_container_cgroup(id)
            .expect("remove from ferrum_cgroups");
    }
}
