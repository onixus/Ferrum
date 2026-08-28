//! The shipped ELF, in a real kernel.
//!
//! `tests/elf_inspect.rs` reads the ELF; this one loads it. Everything checked
//! here is unobservable by reading: the verifier's opinion of the datapath
//! programs, the `sys_enter_*` record offsets `TP_SYSCALL_NR`/`TP_ARG0`/
//! `TP_ARG1`, and what `EVENT_FLAG_PATH_TRUNCATED` actually means for a path
//! the kernel could not carry whole.
//!
//! The ELF comes from `FERRUM_BPF_ELF`, and there are exactly two reasons
//! anything here declines to run, both checked *before* the code under test:
//! the env var is unset, so there is no ELF to load; or this kernel does not
//! expose a tracepoint the datapath needs (read from tracefs, not inferred
//! from a failure). `FERRUM_BPF_ELF_REQUIRED` — which the Jenkins stage sets —
//! turns both into failures. An attach that fails for any *other* reason is
//! always a failure: a test that returns green when the load refuses would be
//! the fail-open this gate exists to close.
//!
//! Needs CAP_BPF/root and tracefs.
#![cfg(feature = "attach")]

use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, OnceLock};

use aya::maps::{Array, MapData, RingBuf};
use aya::programs::TracePoint;
use aya::Bpf;
use ferrum_ebpf::{
    decode_event, syscall_name, tracepoints_for_arch, Event, KernelHandle, RingReader, SyscallArch,
    DATAPATH_ABI, EVENT_FLAG_AGENT_SELF, EVENT_FLAG_PATH_TRUNCATED, MAP_EVENTS, MAP_SELF, PATH_LEN,
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

/// Tracepoints this arch's datapath wants that the *running kernel* does not
/// have, read straight from tracefs.
///
/// This is a fact about the environment, established before anything is
/// loaded — not a failure of the code under test. A kernel built without
/// loadable module support has no `init_module`/`finit_module` syscall and so
/// no tracepoint for either; `KernelHandle::attach_for_arch` is all-or-nothing
/// and cannot produce a handle there.
fn absent_from_tracefs(arch: SyscallArch) -> Vec<&'static str> {
    tracepoints_for_arch(arch)
        .into_iter()
        .filter(|(_, category, name)| {
            !["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
                .iter()
                .any(|root| {
                    std::path::Path::new(&format!("{root}/events/{category}/{name}/id")).exists()
                })
        })
        .map(|(prog, _, _)| *prog)
        .collect()
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
/// `handle` is `Some` whenever `KernelHandle::attach_for_arch` could produce
/// one, which is the path production takes and the one the gate is about. It
/// is `None` only on a kernel that does not expose a tracepoint the datapath
/// needs — established from tracefs before anything is loaded, never inferred
/// from a failure — and there the programs are attached here, minus the ones
/// that have no tracepoint, so the datapath itself is still measured rather
/// than skipped. `attach_for_arch` is asserted to refuse, and to refuse for
/// exactly that reason, before the fallback is built.
struct Live {
    arch: SyscallArch,
    ring: RingReader,
    handle: Option<KernelHandle>,
    /// Owns the fallback programs and their links; dropping it detaches.
    _bpf: Option<Bpf>,
}

fn live() -> Option<Live> {
    let (path, elf) = elf_or_skip()?;
    raise_memlock();
    let arch = SyscallArch::host().expect("no syscall decode table for this arch");
    let absent = absent_from_tracefs(arch);

    if absent.is_empty() {
        let mut handle = KernelHandle::attach_for_arch(&elf, arch)
            .unwrap_or_else(|err| panic!("attach {path} on {}: {err}", arch.as_str()));
        handle
            .set_self_tgid(u64::from(std::process::id()))
            .expect("publish self tgid into ferrum_self");
        let ring = handle.take_ring_reader().expect("take ferrum_events");
        return Some(Live {
            arch,
            ring,
            handle: Some(handle),
            _bpf: None,
        });
    }

    // The refusal is expected on this kernel, but it must be *this* refusal.
    // An error naming the ELF load or a program load would mean the verifier
    // rejected the datapath, and that is never something to walk past.
    let err = match KernelHandle::attach_for_arch(&elf, arch) {
        Ok(_) => {
            panic!("this kernel has no tracepoint for {absent:?} yet the attach reported success")
        }
        Err(err) => err.to_string(),
    };
    assert!(
        !err.contains("load eBPF ELF"),
        "the ELF itself would not load: {err}"
    );
    assert!(
        absent.iter().any(|prog| err.contains(prog)),
        "this kernel lacks tracepoints for {absent:?}, but the attach failed for another \
         reason entirely: {err}"
    );
    if required() {
        panic!(
            "FERRUM_BPF_ELF_REQUIRED is set, but this kernel exposes no tracepoint for \
             {absent:?} (a kernel built without CONFIG_MODULES has neither the init_module \
             nor the finit_module syscall). Run this stage on a kernel that has them, or \
             KernelHandle::attach_for_arch is not being gated at all."
        );
    }
    println!(
        "KernelHandle::attach_for_arch refused, correctly, because this kernel has no \
         tracepoint for {absent:?} ({err}). The ELF loaded and the programs passed the \
         verifier; the datapath checks below run against the rest, attached here."
    );
    Some(attach_available(&elf, arch, &absent))
}

/// Attach every datapath program whose tracepoint this kernel actually has.
///
/// Only reached on a kernel `KernelHandle` cannot serve. It exists so the
/// record layout, the argument offsets and the truncation flag are still
/// measured there — not so an attach failure has somewhere to go.
fn attach_available(elf: &[u8], arch: SyscallArch, absent: &[&str]) -> Live {
    let mut bpf = Bpf::load(elf).expect("Bpf::load");
    for (prog, category, name) in tracepoints_for_arch(arch) {
        if absent.contains(prog) {
            continue;
        }
        let program = bpf
            .program_mut(prog)
            .unwrap_or_else(|| panic!("program {prog} missing from the ELF"));
        let tracepoint: &mut TracePoint = program.try_into().expect("not a tracepoint program");
        tracepoint
            .load()
            .unwrap_or_else(|err| panic!("verifier rejected {prog}: {err}"));
        tracepoint
            .attach(category, name)
            .unwrap_or_else(|err| panic!("attach {prog}: {err}"));
    }
    {
        let map = bpf.map_mut(MAP_SELF).expect("ferrum_self");
        let mut slot: Array<_, u64> = Array::try_from(map).expect("ferrum_self is an array");
        slot.set(0, u64::from(std::process::id()), 0)
            .expect("publish self tgid");
    }
    let map = bpf.take_map(MAP_EVENTS).expect("ferrum_events");
    let ring: RingBuf<MapData> = RingBuf::try_from(map).expect("ferrum_events is a ring buffer");
    Live {
        arch,
        ring: RingReader::new(ring),
        handle: None,
        _bpf: Some(bpf),
    }
}

/// Records left by one syscall.
struct Observed {
    events: Vec<Event>,
}

impl Live {
    /// Run `make_syscall` and collect the records it left that came from this
    /// process. The ring is drained empty first: it is system-wide, and
    /// everything already in it belongs to somebody else.
    fn observe(&mut self, make_syscall: impl FnOnce()) -> Observed {
        let tgid = std::process::id();
        // Two passes: the first empties what the attach itself and the rest of
        // the system produced, the second catches records the first raced past.
        self.ring.drain(|_| {});
        self.ring.drain(|_| {});

        make_syscall();

        let mut events = Vec::new();
        self.ring.drain(|bytes| {
            let event = decode_event(bytes).expect("decode_event rejected a live ring record");
            if event.tgid == tgid {
                events.push(event);
            }
        });
        Observed { events }
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

/// Every record the datapath writes carries this build's stamp, audit, the
/// caller's tgid, a live thread id, a cgroup and a decodable syscall nr.
fn assert_record_shape(event: &Event, arch: SyscallArch) {
    assert_eq!(
        event._pad, DATAPATH_ABI,
        "record stamp disagrees with this decoder"
    );
    assert_eq!(event.action, ACTION_AUDIT, "datapath verdict is not audit");
    assert_eq!(event.tgid, std::process::id(), "wrong tgid");
    assert_ne!(event.pid, 0, "no thread id on the record");
    assert_ne!(event.cgroup_id, 0, "no cgroup id on the record");
    assert!(
        syscall_name(arch, event.syscall_nr).is_some(),
        "syscall_nr {} is not one this arch's table knows: TP_SYSCALL_NR is wrong for {}",
        event.syscall_nr,
        arch.as_str()
    );
    assert!(
        event.flags & EVENT_FLAG_AGENT_SELF != 0,
        "ferrum_self was published with this tgid but the record is not flagged agent-self"
    );
    assert!(!comm(event).is_empty(), "no comm on the record");
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
    if let Some(handle) = &live.handle {
        handle
            .events_dropped_total()
            .expect("read events_dropped_total off a live handle");
        println!(
            "attached through KernelHandle on {}; unhooked on this arch: {:?}",
            arch.as_str(),
            handle.unhooked_syscalls()
        );
    }
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
        let rc =
            unsafe { libc::openat(libc::AT_FDCWD, page.cast::<libc::c_char>(), libc::O_RDONLY) };
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
/// Measured on Linux 6.18/x86_64 with a 384-byte pathname: the record carries
/// the 255-byte head and `EVENT_FLAG_PATH_TRUNCATED` is **not** set.
/// `bpf_probe_read_user_str` returns the buffer size on truncation, which is
/// inside the bounds `aya_ebpf`'s wrapper checks, so the wrapper returns `Ok`
/// and `emit()` — which flags only on `Err` — sets nothing.
///
/// The consequence is a fail-open on an RFC §D acceptance case: a
/// `path_suffix` rule for `/var/run/docker.sock` silently fails to match a
/// path over `PATH_LEN`, with `is_degraded()` false and no signal anywhere.
/// Fixing it changes the match semantics of two predicate families in
/// `eval::rule_matches` and belongs in its own reviewed change, so this test
/// pins the present behaviour instead of hiding it: the fix cannot land
/// unnoticed, and the defect cannot drift further.
#[test]
fn long_path_is_truncated_into_the_buffer_without_the_truncated_flag() {
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
    // Observed, not desired. See the doc comment: the helper truncated and
    // reported success, so no flag was set, and eval::rule_matches therefore
    // lets a path_suffix predicate reject on a tail the datapath never saw.
    assert_eq!(
        event.flags & EVENT_FLAG_PATH_TRUNCATED,
        0,
        "the datapath now flags an over-long path — the path_unknown derivation in \
         eval::rule_matches was written against the old behaviour and must be revisited \
         together with this assertion"
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
    let Some(handle) = live.handle.as_mut() else {
        // No KernelHandle on this kernel; live() already reported why.
        return;
    };
    let id = 0xfe11_0000_0000_0001;
    handle
        .insert_container_cgroup(id)
        .expect("insert into ferrum_cgroups");
    handle
        .remove_container_cgroup(id)
        .expect("remove from ferrum_cgroups");
}
