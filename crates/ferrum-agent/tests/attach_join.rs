//! The join: a record the kernel wrote, through the signed bundle, to a signal.
//!
//! `crates/ferrum-ebpf/tests/attach_live.rs` proves the datapath writes the
//! record this agent decodes; `crates/ferrum-testkit/tests/replay.rs` proves
//! the decision path answers §D correctly on recorded bytes. Neither links the
//! other, so between them sat the one claim MVP-1 rests on with nothing
//! executing it: that a record `emit()` put in `ferrum_events` **on this
//! kernel**, drained through `RingReader`, decided against the **signed
//! `prod-restricted` bundle**, reaches `SignalResponder` and kills the process
//! that made the syscall. Every `→ kill` in RFC §D was proven up to a
//! `Responder` trait object backed by a fake; `SignalResponder::kill` — the
//! only unsafe call in the agent — had never returned `Ok` in any test.
//!
//! What is deliberately *not* faked here, because each is a way to pass while
//! proving the easy half:
//!
//! - The record. It comes off the ring as bytes and goes into `pump_records`
//!   as bytes; nothing in this file constructs a `SyscallEvent`. A run that
//!   finds no such record fails, it does not skip.
//! - The bundle. Compiled from the shipped `prod-restricted` fixture and
//!   signed, not a hand-encoded FEBP: cycle 7 found exactly that substitution
//!   rotting a round-trip test.
//! - The reaction. `SignalResponder`, a real `kill(2)`, confirmed by `waitpid`
//!   reporting `WIFSIGNALED` with `SIGKILL`. A child still alive when the
//!   export says `executed=true` fails this file.
//! - The stale-target guard. `ProcCgroupCheck` reads the real `/proc` and the
//!   real cgroup2 mount. It is the difference between killing a workload and
//!   killing whatever inherited its pid, and a join that stubs it out proves
//!   only that the agent can send a signal.
//!
//! The environment is stated up front, never inferred from a failure: the ELF
//! from `FERRUM_BPF_ELF`, a datapath tracepoint in tracefs, and a cgroup2
//! mount to put the probe process in. `FERRUM_BPF_ELF_REQUIRED` — which the
//! Jenkins stage sets — turns each of those skips into a failure. Anything
//! else that goes wrong is always a failure.
//!
//! Needs CAP_BPF/root (the load), CAP_KILL over the probe (which is this
//! process's own child), tracefs, and a writable cgroup2 hierarchy.

/// The gate, compiled out.
///
/// Built without `--features attach` every test below disappears, and the
/// binary then runs zero tests and exits 0 — cycle 8 measured that a stage
/// which lost the flag stayed green. `FERRUM_BPF_ELF_REQUIRED` cannot say so
/// from inside the `cfg`, because the code that reads it would not have been
/// compiled, so this check lives outside it.
#[cfg(not(feature = "attach"))]
#[test]
fn the_gate_must_not_be_compiled_out() {
    assert!(
        std::env::var_os("FERRUM_BPF_ELF_REQUIRED").is_none(),
        "FERRUM_BPF_ELF_REQUIRED is set, but this binary was built without \
         --features attach: every test in attach_join.rs is compiled out, so this \
         run joined nothing to a kernel and killed nothing. Add --features attach."
    );
}

#[cfg(feature = "attach")]
mod gate {
    use std::ffi::CString;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::{Duration, Instant};

    use ferrum_agent::TargetCheck;
    use ferrum_agent::{
        encode_fsig, pump_records, Agent, AgentConfig, AgentRole, ProcCgroupCheck, SignalResponder,
        DEGRADED_RECOVERY, DEG_PATH_TRUNCATED, REFUSE_STALE_TARGET, RESPOND_SIGNAL_FAILING,
        RESPOND_SIGNAL_FAILING_MIN, TARGET_CHECK_UNPROVABLE, TARGET_NEVER_PROVEN,
    };
    use ferrum_api::PolicyMode;
    use ferrum_compiler::{bundle_digest_material, compile_cluster_policy};
    use ferrum_crypto::{public_key_from_secret, sign_bundle};
    use ferrum_ebpf::{
        decode_event, syscall_name, Event, KernelHandle, RingReader, SyscallArch,
        EVENT_FLAGS_OFFSET, EVENT_FLAG_CONTAINER, EVENT_FLAG_PATH_TRUNCATED, PATH_LEN,
    };
    use ferrum_export::MemorySink;
    use ferrum_ids::{Digest, ADMISSION_ABI, AGENT_ABI};
    use ferrum_k8smeta::WorkloadIdentity;
    use ferrum_proto::EnforcementEvent;

    /// RFC 8032 §7.1 test-1 seed: fixture only, not a prod key. The same seed
    /// the replay harness signs with, so a bundle this file accepts is the one
    /// that harness accepts.
    const SK: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    /// How long a kernel record may take to reach the ring, and how long a
    /// process may take to die of SIGKILL. Both are microseconds in practice;
    /// the bound exists so that a datapath which records nothing, or a reaction
    /// which signals nothing, fails instead of hanging the stage.
    const PATIENCE: Duration = Duration::from_secs(10);

    /// Tracepoints are system-wide and every test here filters the ring by the
    /// tgid of its own probe, but the ring is one buffer: two tests draining it
    /// at once would each swallow the other's records. They take turns.
    fn serialized() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = LOCK.get_or_init(|| Mutex::new(()));
        lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn required() -> bool {
        std::env::var_os("FERRUM_BPF_ELF_REQUIRED").is_some()
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

    /// See `attach_live.rs`: BPF memory is charged to the cgroup since 5.11,
    /// but an older kernel charges RLIMIT_MEMLOCK and the default does not fit
    /// the ring.
    fn raise_memlock() {
        let unlimited = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        // Best effort; the load below reports the real problem if this fails.
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &unlimited) };
    }

    /// Where cgroup2 is mounted on this node: `bpf_get_current_cgroup_id()`
    /// answers for the unified hierarchy, and on a hybrid host that is not
    /// `/sys/fs/cgroup`. This file used to carry its own copy of the
    /// derivation, which is how the defect stayed invisible — the test read
    /// `mountinfo` to work here at all, and production did not. It is now the
    /// production derivation, called from the one place that needs the root
    /// for its own bookkeeping (creating the probe's cgroup); `join_agent`
    /// takes none, because `ProcCgroupCheck::new()` does this itself.
    fn cgroup2_root() -> Option<PathBuf> {
        ferrum_k8smeta::detect_cgroup2_root().ok()
    }

    /// A cgroup of this test's own, so the probe has an identity the index can
    /// resolve and `ProcCgroupCheck` can confirm. Removed on drop; a leftover
    /// directory holds an inode the next run must not be handed.
    struct Cgroup {
        root: PathBuf,
        dir: PathBuf,
        id: u64,
    }

    impl Cgroup {
        fn create(root: &Path, tag: &str) -> Cgroup {
            let dir = root.join(format!(
                "ferrum-join-{}-{}-{tag}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time")
                    .as_nanos()
            ));
            std::fs::create_dir(&dir)
                .unwrap_or_else(|err| panic!("mkdir {}: {err}", dir.display()));
            let id = {
                use std::os::unix::fs::MetadataExt;
                std::fs::metadata(&dir)
                    .unwrap_or_else(|err| panic!("stat {}: {err}", dir.display()))
                    .ino()
            };
            assert_ne!(id, 0, "cgroup directory has no inode to key on");
            Cgroup {
                root: root.to_path_buf(),
                dir,
                id,
            }
        }

        /// Move a live pid into this cgroup. Every syscall it makes afterwards
        /// carries `id` as the record's cgroup, and `/proc/<pid>/cgroup` names
        /// this directory.
        fn attach(&self, pid: libc::pid_t) {
            let procs = self.dir.join("cgroup.procs");
            std::fs::write(&procs, format!("{pid}\n"))
                .unwrap_or_else(|err| panic!("write {pid} to {}: {err}", procs.display()));
        }
    }

    impl Drop for Cgroup {
        fn drop(&mut self) {
            // A populated cgroup will not rmdir, and a failure here is not
            // worth masking whatever assertion brought us here.
            let _ = std::fs::remove_dir(&self.dir);
        }
    }

    /// A loaded datapath, its ring, and the cgroup this test's probe runs in.
    struct Live {
        arch: SyscallArch,
        ring: RingReader,
        handle: KernelHandle,
        cgroup: Cgroup,
    }

    /// Attach the shipped ELF the way production does, publish this process's
    /// tgid, and register the probe cgroup as a container so `containerOnly`
    /// rules apply to it — the same two map writes the agent's own refresher
    /// makes.
    fn live(tag: &str) -> Option<Live> {
        let (path, elf) = elf_or_skip()?;
        raise_memlock();
        let arch = SyscallArch::host().expect("no syscall decode table for this arch");

        let Some(root) = cgroup2_root() else {
            if required() {
                panic!(
                    "FERRUM_BPF_ELF_REQUIRED is set, but no cgroup2 filesystem is mounted on this \
                     node. The probe process would have no cgroup identity, so nothing here could \
                     join a record to a workload or check a target for pid reuse."
                );
            }
            println!("skipping: no cgroup2 mount (no cgroup identity for the probe)");
            return None;
        };

        // Read from tracefs, not inferred from the attach failing: a kernel
        // with no datapath tracepoint at all leaves nothing to measure, and
        // that is a fact about the node rather than a verdict on the code.
        let hooked =
            ferrum_ebpf::tracepoints_for_arch(arch)
                .into_iter()
                .any(|(_, category, name)| {
                    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
                        .iter()
                        .any(|r| Path::new(&format!("{r}/events/{category}/{name}/id")).exists())
                });
        if !hooked {
            if required() {
                panic!(
                    "FERRUM_BPF_ELF_REQUIRED is set, but this kernel exposes no datapath \
                     tracepoint at all. Run this stage on a kernel with tracefs."
                );
            }
            println!("skipping: no datapath tracepoint on this kernel");
            return None;
        }

        let mut handle = KernelHandle::attach_for_arch(&elf, arch)
            .unwrap_or_else(|err| panic!("attach {path} on {}: {err}", arch.as_str()));
        handle
            .set_self_tgid(u64::from(std::process::id()))
            .expect("publish self tgid into ferrum_self");
        let cgroup = Cgroup::create(&root, tag);
        handle
            .insert_container_cgroup(cgroup.id)
            .expect("publish the probe cgroup into ferrum_cgroups");
        let ring = handle.take_ring_reader().expect("take ferrum_events");
        Some(Live {
            arch,
            ring,
            handle,
            cgroup,
        })
    }

    /// A forked process that makes one syscall for the agent to decide on and
    /// then stays alive to be signalled. Reaped on drop whatever happened, so a
    /// failing assertion does not leave a `sleep` behind on the node.
    struct Probe {
        pid: libc::pid_t,
        reaped: bool,
    }

    impl Probe {
        fn tgid(&self) -> u32 {
            u32::try_from(self.pid).expect("probe pid")
        }

        /// `Some(status)` once the child has been reaped, `None` while it is
        /// still running.
        fn poll(&mut self) -> Option<libc::c_int> {
            if self.reaped {
                return None;
            }
            let mut status = 0;
            let rc = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            assert!(rc >= 0, "waitpid on probe {}: {}", self.pid, errno());
            if rc == 0 {
                return None;
            }
            self.reaped = true;
            Some(status)
        }

        /// Wait for the child to die, or fail saying it did not. This is the
        /// assertion the file exists for: an export claiming `executed=true` is
        /// the agent's word, and a process still running is the node's.
        fn wait_for_death(&mut self, context: &str) -> libc::c_int {
            let deadline = Instant::now() + PATIENCE;
            loop {
                if let Some(status) = self.poll() {
                    return status;
                }
                assert!(
                    Instant::now() < deadline,
                    "{context}: probe pid {} is still alive {PATIENCE:?} after the agent reported \
                     the reaction ran. Nothing was killed.",
                    self.pid
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        fn assert_alive(&mut self, context: &str) {
            assert!(
                self.poll().is_none(),
                "{context}: probe pid {} is gone, but no reaction should have reached it",
                self.pid
            );
        }
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
                let mut status = 0;
                libc::waitpid(self.pid, &mut status, 0);
            }
        }
    }

    fn errno() -> String {
        std::io::Error::last_os_error().to_string()
    }

    impl Live {
        /// Fork a child into the probe cgroup and run `body` in it.
        ///
        /// Between `fork` and `body` the child does nothing but block on a
        /// pipe: the parent has to move it into the cgroup *before* it makes
        /// the syscall under test, or the record would carry the harness's own
        /// cgroup and prove nothing. Only this thread survives into the child,
        /// and `body` must stay inside libc — the harness is multi-threaded.
        ///
        /// A `body` that returns parks the child on `pause()`, so its pid stays
        /// the workload until the agent decides what to do about it.
        fn spawn_probe(&self, body: impl FnOnce()) -> Probe {
            let mut fds = [0; 2];
            assert_eq!(
                unsafe { libc::pipe(fds.as_mut_ptr()) },
                0,
                "pipe: {}",
                errno()
            );
            let (read_fd, write_fd) = (fds[0], fds[1]);
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe {
                    libc::close(write_fd);
                    let mut go = 0u8;
                    let n = libc::read(read_fd, std::ptr::addr_of_mut!(go).cast(), 1);
                    if n != 1 {
                        // The parent never released us: exit rather than make
                        // the syscall from the wrong cgroup.
                        libc::_exit(97);
                    }
                    libc::close(read_fd);
                }
                body();
                loop {
                    unsafe { libc::pause() };
                }
            }
            assert!(pid > 0, "fork failed: {}", errno());
            unsafe { libc::close(read_fd) };
            self.cgroup.attach(pid);
            let go = 1u8;
            assert_eq!(
                unsafe { libc::write(write_fd, std::ptr::addr_of!(go).cast(), 1) },
                1,
                "release the probe: {}",
                errno()
            );
            unsafe { libc::close(write_fd) };
            Probe { pid, reaped: false }
        }

        /// Every record this tgid left in the ring, as the bytes the kernel
        /// wrote, waited for until one of them satisfies `wanted`.
        ///
        /// Nothing is filtered on content: the whole tgid's traffic goes to the
        /// agent in ring order, so the verdict is decided by the policy and not
        /// by this file picking the record it likes. A run in which `wanted`
        /// never arrives fails — a join that skips when the kernel recorded
        /// nothing is the fail-open `attach_live.rs` already had to close once.
        fn records_of(
            &mut self,
            tgid: u32,
            what: &str,
            wanted: impl Fn(&Event, SyscallArch) -> bool,
        ) -> Vec<Vec<u8>> {
            let arch = self.arch;
            let deadline = Instant::now() + PATIENCE;
            let mut raw: Vec<Vec<u8>> = Vec::new();
            let mut seen: Vec<(u32, Option<&'static str>)> = Vec::new();
            let mut found = false;
            loop {
                self.ring.drain(|bytes| {
                    let event =
                        decode_event(bytes).expect("decode_event rejected a live ring record");
                    if event.tgid != tgid {
                        return;
                    }
                    seen.push((event.syscall_nr, syscall_name(arch, event.syscall_nr)));
                    found |= wanted(&event, arch);
                    raw.push(bytes.to_vec());
                });
                if found || Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(
                found,
                "the probe (tgid {tgid}) was supposed to leave a {what} record in ferrum_events \
                 and none arrived within {PATIENCE:?}. There is nothing from this kernel to decide \
                 on, and every assertion after this point would have passed without having looked \
                 at a record. Saw: {seen:?}"
            );
            raw
        }
    }

    /// compile → sign: FSIG over the FRMB material of the shipped
    /// `prod-restricted` fixture, in enforce. Not a hand-written FEBP.
    fn signed_bundle() -> (Vec<u8>, Digest) {
        let mut spec = ferrum_testkit::prod_restricted().spec;
        spec.mode = PolicyMode::Enforce;
        let bundle = compile_cluster_policy(&spec).expect("compile prod-restricted");
        let frmb = bundle_digest_material(
            AGENT_ABI,
            ADMISSION_ABI,
            &bundle.admission_program,
            &bundle.ebpf_spec,
            &bundle.wasm,
        )
        .expect("frmb material");
        let pk = public_key_from_secret(&SK).expect("public key");
        let sig = sign_bundle(&frmb, &SK).expect("sign");
        let fsig = encode_fsig(&frmb, &sig, &pk).expect("fsig");
        (fsig, bundle.digest)
    }

    /// The workload the probe cgroup resolves to: in scope for the
    /// `prod-restricted` selector (pci zone, pinned registry with a digest), so
    /// its rules apply.
    fn join_identity() -> WorkloadIdentity {
        let mut id = WorkloadIdentity {
            namespace: "payments".into(),
            pod: "web-1".into(),
            container: "app".into(),
            service_account: "web".into(),
            ..Default::default()
        };
        id.namespace_labels
            .insert("ferrum.io/zone".into(), "pci".into());
        // The labels above were listed, not guessed. Without this the record
        // decides fail-closed on the K stand — the kills still fire, so no
        // assertion here would break, but the node would report
        // `DEG_LABELS_UNKNOWN` for a namespace it did observe.
        id.namespace_labels_observed = true;
        id.image = "registry.internal.example/app@sha256:abc".into();
        id.image_digest = "sha256:abc".into();
        id
    }

    /// A respond-role agent holding the signed bundle, with the probe cgroup
    /// resolved and **both halves of the reaction real**: `SignalResponder`
    /// sends the signal, and `ProcCgroupCheck` re-reads `/proc` to confirm the
    /// target is still in the cgroup that raised the record.
    fn join_agent(live: &Live) -> Agent {
        let (fsig, digest) = signed_bundle();
        let mut agent = Agent::new(AgentConfig {
            role: AgentRole::Respond,
            trust_root: public_key_from_secret(&SK).expect("public key"),
            policy_name: "prod-restricted".into(),
            ..Default::default()
        });
        let applied = agent.apply_fsig(&fsig, Some(&digest)).expect("apply FSIG");
        assert_eq!(applied, digest, "the applied bundle is not the signed one");
        agent.insert_cgroup(live.cgroup.id, join_identity());
        agent.set_responder(Box::new(SignalResponder));
        // The production constructor, not `with_roots`: the root it derives is
        // the claim under test. A test that hands it the answer proves only
        // that the guard works once somebody else has found the hierarchy,
        // which is the half that was never in doubt.
        let check = ProcCgroupCheck::new();
        assert_eq!(
            check.cgroup_root(),
            Ok(live.cgroup.root.as_path()),
            "ProcCgroupCheck::new() keyed itself on a different hierarchy than the one this \
             probe's cgroup was created in: every reaction on this node would refuse as a stale \
             target on a workload that never moved"
        );
        agent.set_target_check(Box::new(check));
        agent
    }

    fn nul_trimmed(bytes: &[u8]) -> &[u8] {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        &bytes[..end]
    }

    /// What a record from the probe must carry before any verdict on it means
    /// anything: this build's kernel-side identity for the workload.
    ///
    /// The cgroup id is the load-bearing one. It is what the index resolves to
    /// a pod and what `ProcCgroupCheck` re-reads from `/proc` before the
    /// signal, and the two are computed by entirely different code — one by
    /// `bpf_get_current_cgroup_id()` in the kernel, one by `stat` on the
    /// cgroup2 directory. If they ever disagreed, every reaction on this node
    /// would refuse as a stale target and the agent would look healthy doing
    /// it.
    fn assert_probe_record(event: &Event, cgroup: &Cgroup, tgid: u32) {
        assert_eq!(event.tgid, tgid, "record is not from the probe");
        assert_eq!(
            event.cgroup_id,
            cgroup.id,
            "bpf_get_current_cgroup_id() and the inode of {} disagree: the cgroup index and \
             ProcCgroupCheck are keyed on different numbers",
            cgroup.dir.display()
        );
        assert_ne!(
            event.flags & EVENT_FLAG_CONTAINER,
            0,
            "the probe cgroup is in ferrum_cgroups but the record is not flagged as a container: \
             every containerOnly rule — which is both §D kill rules — silently does not apply"
        );
        assert!(!event.agent_self(), "the probe is not the agent");
    }

    fn only_rule<'a>(events: &'a [EnforcementEvent], rule: &str) -> &'a EnforcementEvent {
        let hits: Vec<&EnforcementEvent> =
            events.iter().filter(|e| e.rule.as_str() == rule).collect();
        assert_eq!(
            hits.len(),
            1,
            "expected exactly one {rule} verdict, got {:?}",
            events
                .iter()
                .map(|e| (e.rule.as_str(), e.syscall.as_str(), e.action.as_str()))
                .collect::<Vec<_>>()
        );
        hits[0]
    }

    /// What a §D kill looks like on the export once it really happened.
    fn assert_killed(event: &EnforcementEvent, rule: &str, tgid: u32) {
        assert_eq!(event.rule.as_str(), rule);
        assert_eq!(event.action.as_str(), "kill", "{:?}", event.respond_error);
        assert!(
            event.executed,
            "{rule} matched but no signal was sent: {:?}",
            event.respond_error
        );
        assert_eq!(event.respond_error, None);
        assert_eq!(event.tgid, tgid, "the export names a different process");
        assert_eq!(event.namespace, "payments");
        assert_eq!(event.pod, "web-1");
        assert_eq!(
            event.image_digest.as_ref().map(Digest::as_str),
            Some("sha256:abc"),
            "the record is unjoinable to the supply-chain side of the same workload"
        );
    }

    /// The line a stage outside this file greps for to tell a run that carried
    /// a record to a signal from one that skipped every test and exited 0.
    ///
    /// Every skip in `live()` is an early `return` from a `#[test]`, so the
    /// pass count cannot tell those apart; only `waitpid` having reported a
    /// SIGKILL can. One line per test that got that far, in one shape, so the
    /// stage can require a *count* rather than the presence of one test's
    /// line. `Jenkinsfile` currently greps for `no-shell: kernel record`,
    /// which is what this prints for that test — the text is unchanged.
    fn signalled(what: &str, pid: libc::pid_t) {
        println!(
            "{what}: kernel record → signed bundle → SIGKILL, confirmed by waitpid on pid {pid}"
        );
    }

    /// RFC §D: `kubectl exec` + `/bin/sh` → kill.
    ///
    /// The shell is a real `/bin/sh`, not a process renamed to look like one:
    /// the child execs it, and the record the `no-shell` rule decides on is the
    /// shell's own `execve` of the command it was given, which is where `comm`
    /// is `sh` for the same reason it would be under `kubectl exec`. The
    /// process left behind is alive and killable, which is the point — a probe
    /// that had already exited would make a signal that went nowhere
    /// indistinguishable from one that worked.
    #[test]
    fn a_kernel_execve_of_a_shell_is_killed_by_the_signed_bundle() {
        let _serial = serialized();
        let Some(mut live) = live("shell") else {
            return;
        };
        let arch = live.arch;

        let sh = CString::new("/bin/sh").expect("no NUL");
        let dash_c = CString::new("-c").expect("no NUL");
        // `exec` so the shell replaces itself: one execve, from comm `sh`, and
        // the pid survives as something that will sit still to be killed.
        let script = CString::new("exec /bin/sleep 600").expect("no NUL");
        let mut probe = live.spawn_probe(move || unsafe {
            let argv = [
                sh.as_ptr(),
                dash_c.as_ptr(),
                script.as_ptr(),
                std::ptr::null(),
            ];
            let envp = [std::ptr::null::<libc::c_char>()];
            libc::execve(sh.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(98);
        });
        let tgid = probe.tgid();

        // The record the rule decides on: an execve made *by* the shell.
        let records = live.records_of(tgid, "execve from comm=sh", |event, arch| {
            syscall_name(arch, event.syscall_nr) == Some("execve")
                && nul_trimmed(&event.comm) == b"sh"
        });
        for bytes in &records {
            assert_probe_record(&decode_event(bytes).expect("decode"), &live.cgroup, tgid);
        }

        let agent = join_agent(&live);
        let sink = MemorySink::new();
        let stats = pump_records(&agent, arch, &records, &sink);
        assert_eq!(stats.decode_failed, 0, "a kernel record failed to decode");

        let events = sink.events();
        let killed = only_rule(&events, "no-shell");
        assert_killed(killed, "no-shell", tgid);
        assert_eq!(killed.syscall, "execve");
        assert_eq!(killed.comm, "sh");
        assert_eq!(agent.respond_kill_total(), 1);

        // The agent's word, and then the node's.
        let status = probe.wait_for_death("no-shell");
        assert!(
            libc::WIFSIGNALED(status),
            "the probe exited on its own (status {status:#x}); nothing proves a signal reached it"
        );
        assert_eq!(
            libc::WTERMSIG(status),
            libc::SIGKILL,
            "the probe died of signal {}, not SIGKILL",
            libc::WTERMSIG(status)
        );
        signalled("no-shell", probe.pid);
        let _ = live.handle.events_dropped_total();
    }

    /// RFC §D: docker.sock → kill. `no-runtime-sock` names no syscall and no
    /// comm, so this is the path predicate alone, decided on a path the kernel
    /// copied out of the probe's own address space.
    #[test]
    fn a_kernel_openat_of_docker_sock_is_killed_by_the_signed_bundle() {
        let _serial = serialized();
        let Some(mut live) = live("sock") else {
            return;
        };
        let arch = live.arch;

        let target = format!("/tmp/ferrum-join-{}/docker.sock", std::process::id());
        let c_target = CString::new(target.clone()).expect("no NUL");
        let mut probe = live.spawn_probe(move || unsafe {
            // Must fail: reaching sys_enter is the whole requirement, and a
            // real socket would outlive the test.
            libc::openat(libc::AT_FDCWD, c_target.as_ptr(), libc::O_RDONLY);
        });
        let tgid = probe.tgid();

        let wanted = target.clone();
        let records = live.records_of(tgid, "openat of a docker.sock path", move |event, arch| {
            syscall_name(arch, event.syscall_nr) == Some("openat")
                && nul_trimmed(&event.path) == wanted.as_bytes()
        });
        for bytes in &records {
            assert_probe_record(&decode_event(bytes).expect("decode"), &live.cgroup, tgid);
        }

        let agent = join_agent(&live);
        let sink = MemorySink::new();
        pump_records(&agent, arch, &records, &sink);

        let events = sink.events();
        let killed = only_rule(&events, "no-runtime-sock");
        assert_killed(killed, "no-runtime-sock", tgid);
        assert!(
            !killed.path_unknown,
            "a {}-byte path fits in PATH_LEN={PATH_LEN}: this verdict must be proven, not asserted",
            target.len()
        );
        assert_eq!(agent.respond_kill_total(), 1);

        let status = probe.wait_for_death("no-runtime-sock");
        assert!(libc::WIFSIGNALED(status), "the probe exited on its own");
        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
        signalled("no-runtime-sock", probe.pid);
    }

    /// The same case with a path the datapath cannot carry whole.
    ///
    /// Cycle 8's finding lives here: `bpf_probe_read_user_str` reports
    /// truncation as success, so a pre-fix `emit()` wrote a 255-byte head and
    /// no flag, and `path_suffix` then rejected `docker.sock` on a tail nobody
    /// saw — a §D acceptance case failing open in silence. Two independent
    /// things now stop that, and this test measures both on one record: the
    /// datapath sets `EVENT_FLAG_PATH_TRUNCATED` from the length it read, and
    /// `ferrum_ebpf::path_truncated` derives the same answer from the bytes
    /// that arrived, for ELFs already deployed that predate the fix. The
    /// verdict is therefore still kill, and it is marked `path_unknown` so an
    /// operator can tell an asserted match from a proven one.
    #[test]
    fn a_truncated_docker_sock_path_still_kills_and_says_the_match_was_asserted() {
        let _serial = serialized();
        let Some(mut live) = live("trunc") else {
            return;
        };
        let arch = live.arch;

        let prefix = format!("/tmp/ferrum-join-{}-long/", std::process::id());
        let mut target = prefix.clone();
        while target.len() < PATH_LEN + 64 {
            target.push('a');
        }
        target.push_str("/docker.sock");
        let c_target = CString::new(target.clone()).expect("no NUL");
        let mut probe = live.spawn_probe(move || unsafe {
            libc::openat(libc::AT_FDCWD, c_target.as_ptr(), libc::O_RDONLY);
        });
        let tgid = probe.tgid();

        let head = prefix.clone();
        let records = live.records_of(tgid, "openat of an over-long path", move |event, arch| {
            syscall_name(arch, event.syscall_nr) == Some("openat")
                && nul_trimmed(&event.path).starts_with(head.as_bytes())
        });

        // The record itself, before any verdict: the head is real, the tail is
        // gone, and the datapath said so. This is the only assertion in the
        // file that reads the raw flag rather than what the agent made of it —
        // the decoder's derived fallback would otherwise cover for an `emit()`
        // that stopped setting it, and a silent fallback is a defect waiting
        // for the next producer that has no fallback.
        let truncated = records
            .iter()
            .map(|bytes| decode_event(bytes).expect("decode"))
            .find(|event| nul_trimmed(&event.path).starts_with(prefix.as_bytes()))
            .expect("the record we waited for");
        assert_probe_record(&truncated, &live.cgroup, tgid);
        let path = nul_trimmed(&truncated.path);
        assert_eq!(
            path.len(),
            PATH_LEN - 1,
            "a {}-byte path did not fill the buffer: emit() is comparing against the wrong bound",
            target.len()
        );
        assert!(
            truncated.path_truncated(),
            "emit() did not flag a path it could not carry whole. The decoder derives truncation \
             from the buffer as well, so the verdict below still holds — but the datapath half of \
             that pair has stopped working and only this assertion can see it"
        );
        assert!(
            !path.ends_with(b"docker.sock"),
            "the suffix survived truncation, so this record does not exercise the asserted match"
        );

        let agent = join_agent(&live);
        let sink = MemorySink::new();
        pump_records(&agent, arch, &records, &sink);

        let events = sink.events();
        let killed = only_rule(&events, "no-runtime-sock");
        assert_killed(killed, "no-runtime-sock", tgid);
        assert!(
            killed.path_unknown,
            "a match on a tail the datapath never carried is asserted, not proven, and the export \
             must say so"
        );
        assert!(
            agent.path_truncated_total() >= 1,
            "the node counter for truncated paths did not move"
        );

        let status = probe.wait_for_death("no-runtime-sock (truncated path)");
        assert!(libc::WIFSIGNALED(status), "the probe exited on its own");
        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
        signalled("no-runtime-sock (truncated path)", probe.pid);
    }

    /// The same over-long path again, with the datapath's flag taken away:
    /// what a node still running a pre-cycle-8 ELF writes.
    ///
    /// Cycle 8 closed the fail-open twice. `emit()` sets
    /// `EVENT_FLAG_PATH_TRUNCATED` from the length the helper returned — the
    /// test above measures that — and `ferrum_ebpf::path_truncated` derives the
    /// same answer from the shape of the buffer that arrived. The second half
    /// exists for one reason: an image is replaced on its own schedule, so
    /// after a rolling upgrade this agent runs in front of an object that
    /// predates the fix, and no new kernel flag can reach an object already
    /// deployed. Until now that half had no kernel-level proof at all. Its only
    /// demonstration was a unit test on a record Rust had written
    /// (`ferrum-ebpf/src/event.rs`), which cannot say whether a *kernel* record
    /// with no flag on it still reaches a signal.
    ///
    /// So the record here is this kernel's. The probe opens the same over-long
    /// `docker.sock` path, the ring is drained, and then exactly one bit is
    /// cleared in the bytes — `EVENT_FLAG_PATH_TRUNCATED`, at
    /// `EVENT_FLAGS_OFFSET`, asserted below to be the only byte that moved.
    /// Nothing is rebuilt from parts: an `Event` re-encoded with the flag
    /// dropped is a synthesised record and would prove no more than
    /// `replay.rs` already does. The head, the cgroup id, the tgid, the syscall
    /// nr and the ABI stamp are all still the ones the kernel wrote, and the
    /// verdict below is decided on them.
    ///
    /// The test above must keep asserting the raw flag, and does; this one does
    /// not repeat that assertion, because a record that still carried the flag
    /// would make everything below vacuous. It asserts instead that there *was*
    /// a flag to clear, which is the same fact stated as this test's premise.
    #[test]
    fn a_kernel_record_stripped_of_the_flag_is_still_read_as_truncated() {
        let _serial = serialized();
        let Some(mut live) = live("prefix") else {
            return;
        };
        let arch = live.arch;

        let prefix = format!("/tmp/ferrum-join-{}-prefix/", std::process::id());
        let mut target = prefix.clone();
        while target.len() < PATH_LEN + 64 {
            target.push('a');
        }
        target.push_str("/docker.sock");
        let c_target = CString::new(target.clone()).expect("no NUL");
        let mut probe = live.spawn_probe(move || unsafe {
            libc::openat(libc::AT_FDCWD, c_target.as_ptr(), libc::O_RDONLY);
        });
        let tgid = probe.tgid();

        let head = prefix.clone();
        let records = live.records_of(tgid, "openat of an over-long path", move |event, arch| {
            syscall_name(arch, event.syscall_nr) == Some("openat")
                && nul_trimmed(&event.path).starts_with(head.as_bytes())
        });

        // One bit, in the bytes off the ring. Everything else is the kernel's,
        // and the assertion is that this is literally true: a single byte
        // differs, and re-decoding it gives back the same record minus the flag.
        let mut flagless: Vec<Vec<u8>> = Vec::with_capacity(records.len());
        let mut had_the_flag = 0usize;
        for bytes in &records {
            let mut stripped = bytes.clone();
            stripped[EVENT_FLAGS_OFFSET] &= !EVENT_FLAG_PATH_TRUNCATED;
            let moved = bytes
                .iter()
                .zip(&stripped)
                .filter(|(before, after)| before != after)
                .count();
            assert!(
                moved <= 1,
                "clearing EVENT_FLAG_PATH_TRUNCATED changed {moved} bytes: the offset no longer \
                 addresses flags, so this record is not the one a pre-fix ELF writes"
            );
            had_the_flag += moved;

            let before = decode_event(bytes).expect("decode the ring record");
            let after = decode_event(&stripped).expect("decode the stripped record");
            assert_eq!(after.flags, before.flags & !EVENT_FLAG_PATH_TRUNCATED);
            assert_eq!(after.cgroup_id, before.cgroup_id);
            assert_eq!(after.tgid, before.tgid);
            assert_eq!(after.syscall_nr, before.syscall_nr);
            assert_eq!(after.path, before.path, "the kernel's bytes are untouched");
            flagless.push(stripped);
        }
        assert!(
            had_the_flag >= 1,
            "no record from this probe carried EVENT_FLAG_PATH_TRUNCATED, so nothing was cleared \
             and this test is standing in for a producer that does not exist. The datapath half \
             has stopped setting the flag — see \
             a_truncated_docker_sock_path_still_kills_and_says_the_match_was_asserted"
        );

        // The record as a pre-fix ELF would have written it: the head fills the
        // buffer, the suffix the rule names is gone, and nothing in the record
        // says so. This is the state in which cycle 8 measured `path_suffix`
        // rejecting a §D kill rule on a tail nobody saw.
        let pre_fix = flagless
            .iter()
            .map(|bytes| decode_event(bytes).expect("decode"))
            .find(|event| nul_trimmed(&event.path).starts_with(prefix.as_bytes()))
            .expect("the record we waited for");
        assert_probe_record(&pre_fix, &live.cgroup, tgid);
        let path = nul_trimmed(&pre_fix.path);
        assert_eq!(
            path.len(),
            PATH_LEN - 1,
            "the head does not fill the buffer"
        );
        assert!(!pre_fix.path_truncated(), "the flag is still on the record");
        assert!(
            !path.ends_with(b"docker.sock"),
            "the suffix survived truncation, so this record does not exercise the asserted match"
        );

        let agent = join_agent(&live);
        let sink = MemorySink::new();
        let stats = pump_records(&agent, arch, &flagless, &sink);
        assert_eq!(stats.decode_failed, 0, "a kernel record failed to decode");

        let events = sink.events();
        let killed = only_rule(&events, "no-runtime-sock");
        assert_killed(killed, "no-runtime-sock", tgid);
        assert!(
            killed.path_unknown,
            "the flag is the only thing missing and the buffer is unchanged, so the match is \
             still asserted rather than proven and the export must still say so"
        );
        assert!(
            agent.path_truncated_total() >= 1,
            "the node counter for truncated paths did not move on a record whose only defect is \
             that its producer predates the flag"
        );

        // Degraded on this reason, and decaying: a node running an old ELF must
        // say so while the traffic lasts and recover on its own once it stops,
        // exactly as one running the current ELF does. A latch here would pin
        // every pre-upgrade node to Degraded forever.
        let now = Instant::now();
        assert!(agent.path_truncated_recent_at(now));
        assert!(
            agent
                .degraded_reasons_at(now)
                .iter()
                .any(|reason| reason == DEG_PATH_TRUNCATED),
            "the node does not name the truncation: {:?}",
            agent.degraded_reasons_at(now)
        );
        let later = now + DEGRADED_RECOVERY;
        assert!(!agent.path_truncated_recent_at(later));
        assert!(
            !agent
                .degraded_reasons_at(later)
                .iter()
                .any(|reason| reason == DEG_PATH_TRUNCATED),
            "the truncation signal is latched, not decaying"
        );
        assert!(
            agent.path_truncated_total() >= 1,
            "the total decayed with the window"
        );

        let status = probe.wait_for_death("no-runtime-sock (pre-fix ELF record)");
        assert!(libc::WIFSIGNALED(status), "the probe exited on its own");
        assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
        signalled("no-runtime-sock (flagless truncated path)", probe.pid);
    }

    /// The guard between killing a workload and killing whatever inherited its
    /// pid, on the real `/proc`.
    ///
    /// A join that stubs `ProcCgroupCheck` out proves only the easy half. Here
    /// the record is real, the rule really matches, the role really is respond
    /// — and between the record and the reaction the probe leaves the cgroup
    /// that raised it, exactly as a recycled pid would have. The agent must
    /// refuse by name, and the probe must survive.
    #[test]
    fn a_target_that_left_the_cgroup_is_refused_and_survives() {
        let _serial = serialized();
        let Some(mut live) = live("stale") else {
            return;
        };
        let arch = live.arch;

        let target = format!("/tmp/ferrum-join-stale-{}/docker.sock", std::process::id());
        let c_target = CString::new(target.clone()).expect("no NUL");
        let mut probe = live.spawn_probe(move || unsafe {
            libc::openat(libc::AT_FDCWD, c_target.as_ptr(), libc::O_RDONLY);
        });
        let tgid = probe.tgid();

        let wanted = target.clone();
        let records = live.records_of(tgid, "openat of a docker.sock path", move |event, arch| {
            syscall_name(arch, event.syscall_nr) == Some("openat")
                && nul_trimmed(&event.path) == wanted.as_bytes()
        });

        // The pid moves on; the record does not. Back to the root of the
        // hierarchy, which is where a pid that outlived its container ends up.
        std::fs::write(live.cgroup.root.join("cgroup.procs"), format!("{tgid}\n"))
            .expect("move the probe out of the test cgroup");

        let agent = join_agent(&live);
        let sink = MemorySink::new();
        pump_records(&agent, arch, records, &sink);

        let events = sink.events();
        let refused = only_rule(&events, "no-runtime-sock");
        assert_eq!(refused.action.as_str(), "kill");
        assert!(
            !refused.executed,
            "the agent signalled a pid that had left the cgroup that raised the record"
        );
        assert_eq!(
            refused.respond_error.as_deref(),
            Some(REFUSE_STALE_TARGET),
            "the refusal must name pid reuse, not some other guard"
        );
        assert_eq!(agent.respond_kill_total(), 0);
        assert_eq!(agent.respond_stale_target_total(), 1);
        probe.assert_alive("stale target");
    }

    /// The step after the guard: the signal was made and the kernel refused it.
    ///
    /// This is the one path in `react` that is a reaction *failing* rather than
    /// being refused, and until this cycle it was the one path with no reason.
    /// A respond DaemonSet whose `capabilities.add` lost `KILL` gets `EPERM`
    /// from every `kill(2)`; the guards all pass, `executed=false` rides the
    /// export, `respond_failed_total` climbs, and the node reports healthy.
    ///
    /// Getting a real refusal out of this kernel needs care, because the
    /// harness is root and root can signal nearly everything. The errno used
    /// here is `ESRCH` from a tgid that **cannot** name a process: one past
    /// `/proc/sys/kernel/pid_max`. That is deliberate and it is a safety
    /// property, not a convenience — a test that signalled a *reaped* pid to
    /// get `ESRCH` would race pid reuse and eventually SIGKILL an unrelated
    /// process on the node.
    ///
    /// What stays the kernel's:
    ///
    /// - The record. It is the one this kernel wrote for the probe's `openat`,
    ///   with four bytes rewritten to carry the phantom tgid — asserted, by
    ///   re-decoding, to be the only field that moved, the same idiom as
    ///   `a_kernel_record_stripped_of_the_flag_is_still_read_as_truncated`.
    /// - The verdict. The signed `prod-restricted` bundle, in enforce.
    /// - The syscall. `SignalResponder` makes a real `kill(2)` and the errno
    ///   comes back from this kernel.
    /// - The guard. `ProcCgroupCheck` with its production derivation, over a
    ///   copy of this node's own `mountinfo`, resolving to this node's real
    ///   cgroup directory by `stat`. Only the `/proc/<tgid>` entry is
    ///   synthetic, because the tgid is.
    ///
    /// And the interaction that made the defect invisible is asserted here as
    /// well: the guard is satisfied every time, so `respond_target_confirmed`
    /// is non-zero and `TARGET_NEVER_PROVEN` is permanently disarmed on the
    /// step before the failure. Nothing else in the agent can see this.
    #[test]
    fn a_kill_this_kernel_refuses_is_degraded_and_named() {
        let _serial = serialized();
        let Some(mut live) = live("eperm") else {
            return;
        };
        let arch = live.arch;

        // One past pid_max: no process can hold it, so `kill(2)` on it is
        // ESRCH from this kernel and reaches nothing.
        let pid_max: u32 = std::fs::read_to_string("/proc/sys/kernel/pid_max")
            .expect("read /proc/sys/kernel/pid_max")
            .trim()
            .parse()
            .expect("pid_max is a number");
        let phantom = pid_max + 1;
        let rc = unsafe { libc::kill(libc::pid_t::try_from(phantom).expect("pid"), 0) };
        assert_eq!(rc, -1, "pid {phantom} exists on this node; it must not");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "signalling pid {phantom} did not fail with ESRCH, so this test would be aiming a \
             SIGKILL at something real"
        );

        let target = format!("/tmp/ferrum-join-eperm-{}/docker.sock", std::process::id());
        let c_target = CString::new(target.clone()).expect("no NUL");
        let mut probe = live.spawn_probe(move || unsafe {
            libc::openat(libc::AT_FDCWD, c_target.as_ptr(), libc::O_RDONLY);
        });
        let tgid = probe.tgid();

        let wanted = target.clone();
        let records = live.records_of(tgid, "openat of a docker.sock path", move |event, arch| {
            syscall_name(arch, event.syscall_nr) == Some("openat")
                && nul_trimmed(&event.path) == wanted.as_bytes()
        });

        // Four bytes, in the bytes off the ring, and nothing else. Re-decoding
        // is the check that the offset still addresses `tgid`: every other
        // field must come back identical.
        let mut aimed: Vec<Vec<u8>> = Vec::with_capacity(records.len());
        for bytes in &records {
            let mut moved = bytes.clone();
            moved[12..16].copy_from_slice(&phantom.to_ne_bytes());
            let before = decode_event(bytes).expect("decode the ring record");
            let after = decode_event(&moved).expect("decode the re-aimed record");
            assert_eq!(after.tgid, phantom, "the tgid field is not at bytes 12..16");
            assert_eq!(after.cgroup_id, before.cgroup_id);
            assert_eq!(after.pid, before.pid);
            assert_eq!(after.syscall_nr, before.syscall_nr);
            assert_eq!(after.flags, before.flags);
            assert_eq!(after.path, before.path, "the kernel's bytes are untouched");
            assert_eq!(after.comm, before.comm);
            aimed.push(moved);
        }

        // A `/proc` for a tgid that does not exist, and nothing else fictional:
        // the mountinfo is this node's own, so the derivation below is the
        // production one answering about the production hierarchy, and the
        // cgroup line names the directory this probe really ran in.
        let fake_proc = std::env::temp_dir().join(format!(
            "ferrum-join-eperm-proc-{}-{}",
            std::process::id(),
            phantom
        ));
        std::fs::create_dir_all(fake_proc.join("self")).expect("fake /proc/self");
        std::fs::copy(
            "/proc/self/mountinfo",
            fake_proc.join("self").join("mountinfo"),
        )
        .expect("copy this node's mountinfo");
        std::fs::create_dir_all(fake_proc.join(phantom.to_string())).expect("fake /proc/<tgid>");
        let rel = live
            .cgroup
            .dir
            .strip_prefix(&live.cgroup.root)
            .expect("the probe cgroup is under the derived root");
        std::fs::write(
            fake_proc.join(phantom.to_string()).join("cgroup"),
            format!("0::/{}\n", rel.display()),
        )
        .expect("write the target's cgroup line");

        let mut agent = join_agent(&live);
        let check = ProcCgroupCheck::with_proc_root(&fake_proc);
        assert_eq!(
            check.cgroup_root(),
            Ok(live.cgroup.root.as_path()),
            "the production derivation over this node's own mountinfo named another hierarchy"
        );
        assert_eq!(
            check.cgroup_id(phantom),
            Some(live.cgroup.id),
            "the guard does not resolve the phantom target to the cgroup the kernel recorded, so \
             the reaction would refuse before ever reaching the syscall and this test would be \
             measuring the wrong refusal"
        );
        assert!(check.unprovable().is_none());
        agent.set_target_check(Box::new(check));

        let sink = MemorySink::new();
        for _ in 0..RESPOND_SIGNAL_FAILING_MIN {
            pump_records(&agent, arch, aimed.clone(), &sink);
        }
        std::fs::remove_dir_all(&fake_proc).ok();

        assert_eq!(
            agent.respond_kill_total(),
            0,
            "a signal this kernel refused was counted as delivered"
        );
        assert!(
            agent.respond_failed_total() >= RESPOND_SIGNAL_FAILING_MIN,
            "only {} reactions reached the syscall",
            agent.respond_failed_total()
        );
        // The guard passed every time: this is why no other reason can see it.
        assert!(agent.respond_target_confirmed_total() >= RESPOND_SIGNAL_FAILING_MIN);
        assert_eq!(agent.respond_stale_target_total(), 0);
        assert_eq!(agent.respond_refused_total(), 0);

        let events = sink.events();
        let refused = events
            .iter()
            .filter(|e| e.rule.as_str() == "no-runtime-sock")
            .collect::<Vec<_>>();
        assert!(
            !refused.is_empty(),
            "no no-runtime-sock verdict: {:?}",
            events
                .iter()
                .map(|e| (e.rule.as_str(), e.action.as_str()))
                .collect::<Vec<_>>()
        );
        for event in &refused {
            assert_eq!(event.action.as_str(), "kill");
            assert!(
                !event.executed,
                "the agent claimed a kill this kernel refused"
            );
            let err = event
                .respond_error
                .as_deref()
                .expect("a failed signal must say so");
            assert!(
                err.contains("SIGKILL"),
                "the export does not name the syscall that failed: {err}"
            );
        }

        let reasons = agent.degraded_reasons_at(Instant::now());
        assert!(
            reasons.iter().any(|r| r == RESPOND_SIGNAL_FAILING),
            "a node that has decided {} kills and delivered none reports: {reasons:?}",
            agent.respond_failed_total()
        );
        assert!(
            !reasons
                .iter()
                .any(|r| r == TARGET_NEVER_PROVEN || r.starts_with(TARGET_CHECK_UNPROVABLE)),
            "the refused syscall is being reported under a target reason's name: {reasons:?}"
        );

        // Nothing was aimed at the probe, and nothing reached it.
        probe.assert_alive("a kill this kernel refused");
    }
}
