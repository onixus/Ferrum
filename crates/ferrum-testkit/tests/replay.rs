//! Offline replay of recorded ring bytes: the §D runtime cases run from the
//! wire format the datapath writes, not from a hand-built `SyscallEvent`.
//!
//! `tests/acceptance.rs` gates the decision layer; this file gates everything
//! between a ring record and the reaction — the decode table, the flag bits,
//! the NUL trim, unknown syscall nrs and the per-arch syscall numbering. Both
//! exist because they fail for different reasons.

mod common;

use common::wire::{syscall_nr, RecordBuilder};
use common::{
    killed_tgids, replay_agent, respond_agent, temp_lkg, wire_reaction, CGROUP_PAYMENTS,
    TGID_WORKLOAD,
};
use ferrum_agent::{pump_records, PumpStats};
use ferrum_ebpf::{SyscallArch, EVENT_WIRE_LEN, SYSCALL_UNKNOWN};
use ferrum_export::MemorySink;
use ferrum_testkit::AcceptanceCase;
use std::path::PathBuf;

const ARCHES: [SyscallArch; 2] = [SyscallArch::X86_64, SyscallArch::Aarch64];

/// The case list is `ferrum_testkit::AcceptanceCase`, shared with
/// `acceptance.rs`, not a copy in this file: a §D case added to the RFC has to
/// break this gate rather than slip past a hand-written array. Admission's
/// four cases are gated only in `acceptance.rs`; nothing here can replay them,
/// since they never produce a ring record.
struct Scenario {
    case: AcceptanceCase,
    run: fn(SyscallArch),
}

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            case: AcceptanceCase::ExecShellKill,
            run: replay_exec_shell_kill,
        },
        Scenario {
            case: AcceptanceCase::DockerSockKill,
            run: replay_docker_sock_kill,
        },
        Scenario {
            case: AcceptanceCase::BpfNotFromAgentDeny,
            run: replay_bpf_not_from_agent_deny,
        },
        Scenario {
            case: AcceptanceCase::ControlPlaneDownLkg,
            run: replay_control_plane_down_lkg,
        },
    ]
}

/// Without this the harness can cover three cases of four and still be green:
/// a missing scenario looks exactly like a passing suite.
#[test]
fn every_runtime_acceptance_case_has_a_replay_scenario() {
    let registered: Vec<AcceptanceCase> = scenarios().into_iter().map(|s| s.case).collect();
    let expected = AcceptanceCase::runtime();
    for case in &expected {
        assert_eq!(
            registered.iter().filter(|c| *c == case).count(),
            1,
            "no replay scenario registered for §D case: {}",
            case.label()
        );
    }
    assert_eq!(
        registered.len(),
        expected.len(),
        "a scenario names a case that is not a §D runtime case"
    );
}

/// Every §D runtime case, on every arch the decode table claims to serve.
#[test]
fn runtime_acceptance_cases_replay_from_recorded_bytes() {
    for arch in ARCHES {
        for scenario in scenarios() {
            (scenario.run)(arch);
        }
    }
}

fn shell_exec(syscall: &str, comm: &str) -> RecordBuilder {
    RecordBuilder::new(syscall)
        .comm(comm)
        .path("/bin/sh")
        .cgroup(CGROUP_PAYMENTS)
        .process(TGID_WORKLOAD, TGID_WORKLOAD)
}

fn open_path(syscall: &str, path: &str) -> RecordBuilder {
    RecordBuilder::new(syscall)
        .comm("curl")
        .path(path)
        .cgroup(CGROUP_PAYMENTS)
        .process(TGID_WORKLOAD, TGID_WORKLOAD)
}

fn bpf_call(comm: &str) -> RecordBuilder {
    RecordBuilder::new("bpf")
        .comm(comm)
        .cgroup(CGROUP_PAYMENTS)
        .process(TGID_WORKLOAD, TGID_WORKLOAD)
}

fn replay_exec_shell_kill(arch: SyscallArch) {
    let (agent, killed) = replay_agent(None);
    let sink = MemorySink::new();
    let records = vec![
        shell_exec("execve", "sh").build(arch),
        // The other half of the exec pair: naming one and not the other is the
        // arch-split failure the rule shape already forbids.
        shell_exec("execveat", "bash").build(arch),
        // Same record without the container flag: `containerOnly` must not
        // match, and the index/flag disagreement must be counted.
        shell_exec("execve", "sh").in_container(false).build(arch),
    ];

    let stats = pump_records(&agent, arch, records, &sink);
    assert_eq!(
        stats,
        PumpStats {
            handled: 3,
            ..PumpStats::default()
        },
        "{}",
        arch.as_str()
    );

    let events = sink.events();
    assert_eq!(events.len(), 3);
    for event in &events[..2] {
        assert_eq!(event.action, "kill", "{}", arch.as_str());
        assert_eq!(event.rule.as_str(), "no-shell");
        assert_eq!(event.namespace, "payments");
        assert_eq!(event.tgid, TGID_WORKLOAD);
        assert!(event.executed, "{:?}", event.respond_error);
    }
    assert_eq!(events[0].syscall, "execve");
    assert_eq!(events[0].comm, "sh");
    assert_eq!(events[1].syscall, "execveat");
    assert_eq!(events[2].action, "audit");
    assert_eq!(events[2].rule.as_str(), "default");
    assert!(!events[2].executed);

    assert_eq!(agent.respond_kill_total(), 2);
    assert_eq!(killed_tgids(&killed), vec![TGID_WORKLOAD, TGID_WORKLOAD]);
    assert_eq!(
        agent.container_flag_disagreement_total(),
        1,
        "a resolved pod without the container flag is a missed container_only rule"
    );
}

fn replay_docker_sock_kill(arch: SyscallArch) {
    let (agent, killed) = replay_agent(None);
    let sink = MemorySink::new();

    let mut records = vec![open_path("openat", "/var/run/docker.sock").build(arch)];
    // `open` exists only on x86_64. One signed bundle ships everywhere, so the
    // same logical access must be killed wherever the nr exists — and the arch
    // that lacks it must be missing the nr, not the enforcement.
    let plain_open = open_path("open", "/var/run/docker.sock").try_build(arch);
    assert_eq!(
        plain_open.is_some(),
        matches!(arch, SyscallArch::X86_64),
        "decode table changed which arch serves plain open"
    );
    let expected_kills = 1 + u64::from(plain_open.is_some());
    records.extend(plain_open);
    records.push(open_path("openat", "/tmp/app.sock").build(arch));

    let stats = pump_records(&agent, arch, records, &sink);
    assert_eq!(stats.handled, expected_kills + 1);
    assert_eq!(stats.decode_failed, 0);

    let events = sink.events();
    for event in &events[..expected_kills as usize] {
        assert_eq!(event.action, "kill", "{}", arch.as_str());
        assert_eq!(event.rule.as_str(), "no-runtime-sock");
        assert!(event.executed, "{:?}", event.respond_error);
    }
    let benign = events.last().expect("benign event");
    assert_eq!(benign.action, "audit");
    assert_eq!(benign.rule.as_str(), "default");

    assert_eq!(agent.respond_kill_total(), expected_kills);
    assert_eq!(killed_tgids(&killed).len(), expected_kills as usize);
}

/// §D `bpf()` not from the agent. Admission carries the deny (gated in
/// `acceptance.rs`); from recorded bytes this plane produces the audit record
/// that names the caller. `executed=false` with no `respond_error` is the
/// honest shape for an audit: nothing was refused because there was nothing to
/// carry out, and no kill is signalled off a syscall that already returned.
fn replay_bpf_not_from_agent_deny(arch: SyscallArch) {
    let (agent, killed) = replay_agent(None);
    let sink = MemorySink::new();
    let stats = pump_records(&agent, arch, vec![bpf_call("loader").build(arch)], &sink);
    assert_eq!(stats.handled, 1);

    let events = sink.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "audit");
    assert_eq!(events[0].rule.as_str(), "no-module");
    assert_eq!(events[0].comm, "loader");
    assert!(
        !events[0].executed,
        "an audit record executes nothing, and must not claim otherwise"
    );
    assert_eq!(events[0].respond_error, None);
    assert_eq!(
        agent.respond_refused_total(),
        0,
        "an executable action must not feed the refusal counter"
    );
    assert_eq!(agent.respond_kill_total(), 0);
    assert!(killed_tgids(&killed).is_empty());
}

fn replay_control_plane_down_lkg(arch: SyscallArch) {
    let dir = temp_lkg();
    let (mut agent, killed) = replay_agent(Some(dir.clone()));
    let digest = agent.last_good_digest().cloned().expect("last-known-good");

    agent.mark_control_plane_down();
    assert!(agent.control_plane_down());
    assert!(agent.is_degraded());

    let sink = MemorySink::new();
    let stats = pump_records(
        &agent,
        arch,
        vec![shell_exec("execve", "sh").build(arch)],
        &sink,
    );
    assert_eq!(stats.handled, 1);
    assert_eq!(sink.events()[0].action, "kill", "degraded is not fail-open");
    assert!(sink.events()[0].executed);
    assert_eq!(killed_tgids(&killed), vec![TGID_WORKLOAD]);

    // Restart during the outage: the bundle comes back off disk and the same
    // recorded bytes still get the same verdict.
    let mut restarted = respond_agent(Some(dir.clone()));
    assert!(restarted.using_last_known_good());
    assert_eq!(restarted.last_good_digest(), Some(&digest));
    let killed_after = wire_reaction(&mut restarted);
    let sink = MemorySink::new();
    pump_records(
        &restarted,
        arch,
        vec![shell_exec("execve", "sh").build(arch)],
        &sink,
    );
    assert_eq!(sink.events()[0].action, "kill");
    assert_eq!(killed_tgids(&killed_after), vec![TGID_WORKLOAD]);

    let _ = std::fs::remove_dir_all(&dir);
}

/// A path longer than the datapath's buffer, through the real `encode_event`:
/// the workload opened `/var/run/` + `./` * 130 + `docker.sock`, the buffer
/// kept only the head, and `ends_with("docker.sock")` is false on what
/// arrived. The builder sets the truncation flag the way the datapath does,
/// from the length alone, so the kill rule still fires and the node goes
/// Degraded.
///
/// The second half is the regression anchor: the same bytes with the flag
/// cleared are a record the kernel cannot produce, and they are then
/// indistinguishable from an honest short path — merely audited. That is the
/// bypass the flag closes, so the pair must disagree.
#[test]
fn a_truncated_docker_sock_path_still_kills_and_degrades() {
    let long = format!("/var/run/{}docker.sock", "./".repeat(130));
    for arch in ARCHES {
        let (agent, killed) = replay_agent(None);
        assert!(!agent.datapath_degraded());
        let sink = MemorySink::new();
        let record = open_path("openat", &long).build(arch);
        let stats = pump_records(&agent, arch, vec![record], &sink);
        assert_eq!(stats.handled, 1, "{}", arch.as_str());

        let events = sink.events();
        assert_eq!(events[0].action, "kill", "{}", arch.as_str());
        assert_eq!(events[0].rule.as_str(), "no-runtime-sock");
        assert!(events[0].executed, "{:?}", events[0].respond_error);
        assert_eq!(killed_tgids(&killed), vec![TGID_WORKLOAD]);
        assert_eq!(agent.path_truncated_total(), 1);
        assert!(agent.path_truncated_recent());
        assert!(
            agent.datapath_degraded(),
            "a path the buffer could not hold is not a proven verdict"
        );
        assert!(agent.is_degraded());

        let (clean, unharmed) = replay_agent(None);
        let quiet = MemorySink::new();
        let honest = open_path("openat", &long).path_truncated(false).build(arch);
        pump_records(&clean, arch, vec![honest], &quiet);
        assert_ne!(quiet.events()[0].action, "kill", "{}", arch.as_str());
        assert!(killed_tgids(&unharmed).is_empty());
        assert_eq!(clean.path_truncated_total(), 0);
        assert!(!clean.path_truncated_recent());
        assert!(!clean.datapath_degraded());
    }
}

/// The flag, not the comm string, is what keeps the agent from acting on its
/// own `bpf()` calls: a workload that names itself `ferrum-agent` gets no such
/// exemption.
#[test]
fn agent_self_bpf_is_neither_denied_nor_signalled() {
    for arch in ARCHES {
        let (agent, killed) = replay_agent(None);
        let sink = MemorySink::new();
        let records = vec![
            bpf_call("ferrum-agent").agent_self(true).build(arch),
            bpf_call("ferrum-agent").agent_self(false).build(arch),
        ];
        pump_records(&agent, arch, records, &sink);

        let events = sink.events();
        assert_eq!(events[0].action, "audit", "{}", arch.as_str());
        assert_eq!(events[0].rule.as_str(), "default");
        assert_eq!(events[1].action, "audit", "the comm alone must not exempt");
        assert_eq!(events[1].rule.as_str(), "no-module");
        assert_eq!(agent.respond_kill_total(), 0);
        assert!(killed_tgids(&killed).is_empty());
    }
}

/// A record whose cgroup the index has never resolved. The rules still run
/// (the record reaches the sink), but the namespaced selector cannot match, so
/// the verdict falls through to the spec default and the reaction is refused
/// for unknown identity. That fall-through is not an allow the policy chose,
/// so the agent counts the miss and goes Degraded until the index catches up.
#[test]
fn a_cgroup_missing_from_the_index_is_counted_and_degrades() {
    const CGROUP_UNKNOWN: u64 = 4_242_424;
    for arch in ARCHES {
        let (agent, killed) = replay_agent(None);
        assert!(agent.lookup_cgroup(CGROUP_UNKNOWN).is_err());
        let sink = MemorySink::new();
        let record = shell_exec("execve", "sh")
            .cgroup(CGROUP_UNKNOWN)
            .build(arch);
        let stats = pump_records(&agent, arch, vec![record], &sink);
        assert_eq!(stats.handled, 1, "an unresolved cgroup is still an event");

        let events = sink.events();
        assert_eq!(events.len(), 1, "the record must not vanish");
        assert_eq!(events[0].namespace, "", "{}", arch.as_str());
        assert_eq!(events[0].pod, "");
        assert_eq!(events[0].syscall, "execve");
        assert_ne!(events[0].action, "kill");
        assert!(!events[0].executed);
        assert_eq!(agent.respond_kill_total(), 0);
        assert!(killed_tgids(&killed).is_empty());
        assert!(
            agent.identity_unknown_total() >= 1,
            "an index miss must not be silent on {}",
            arch.as_str()
        );
        assert!(agent.identity_unknown_recent(), "{}", arch.as_str());
        assert!(agent.is_degraded());
    }
}

/// The mirror case, and the reason the counter is gated: a host process the
/// datapath did not flag as a container misses the index by design. Counting
/// it would pin every real node to Degraded — kubelet and containerd stream
/// openat continuously — and drown the signals that mean something.
#[test]
fn a_host_process_missing_from_the_index_is_not_a_degradation() {
    const CGROUP_HOST: u64 = 9_191_919;
    for arch in ARCHES {
        let (agent, _killed) = replay_agent(None);
        assert!(agent.lookup_cgroup(CGROUP_HOST).is_err());
        let sink = MemorySink::new();
        let record = shell_exec("execve", "sh")
            .cgroup(CGROUP_HOST)
            .in_container(false)
            .build(arch);
        let before = agent.identity_unknown_total();
        pump_records(&agent, arch, vec![record], &sink);
        assert_eq!(
            agent.identity_unknown_total(),
            before,
            "a host-process miss is legitimate on {}",
            arch.as_str()
        );
        assert!(!agent.identity_unknown_recent(), "{}", arch.as_str());
    }
}

/// The decode table and the event source disagreeing is not a decodable
/// event: enforce matching can no longer be trusted, so the agent is Degraded.
/// The record is still exported, and the loop keeps going.
#[test]
fn an_unknown_syscall_nr_degrades_the_agent_without_stopping_the_loop() {
    for arch in ARCHES {
        let unmapped = (0..1024u32)
            .find(|nr| {
                ferrum_ebpf::syscall_name(SyscallArch::X86_64, *nr).is_none()
                    && ferrum_ebpf::syscall_name(SyscallArch::Aarch64, *nr).is_none()
            })
            .expect("some nr is outside both tables");

        let (agent, killed) = replay_agent(None);
        assert!(!agent.datapath_degraded());
        let sink = MemorySink::new();
        let records = vec![
            open_path("openat", "/var/run/docker.sock").build_with_nr(unmapped),
            open_path("openat", "/var/run/docker.sock").build(arch),
        ];
        let stats = pump_records(&agent, arch, records, &sink);
        assert_eq!(
            stats,
            PumpStats {
                handled: 1,
                decode_failed: 0,
                unknown_syscall: 1,
            },
            "{}",
            arch.as_str()
        );
        assert_eq!(agent.unknown_syscall_total(), 1);
        assert!(agent.datapath_degraded());
        assert!(agent.is_degraded());

        let events = sink.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].syscall, SYSCALL_UNKNOWN);
        // `no-runtime-sock` names no syscall, so the path still matches: an
        // unnamed nr is not a hole in this particular rule.
        assert_eq!(events[1].syscall, "openat");
        assert_eq!(events[1].action, "kill");
        assert_eq!(
            killed_tgids(&killed).len(),
            agent.respond_kill_total() as usize
        );
    }
}

/// Malformed input is telemetry loss, never a reason to stop the loop and
/// never a reason to stop enforcing the records that did decode.
#[test]
fn corrupt_records_are_counted_and_the_loop_keeps_enforcing() {
    for arch in ARCHES {
        let (agent, killed) = replay_agent(None);
        let sink = MemorySink::new();

        let good = open_path("openat", "/var/run/docker.sock").build(arch);
        let mut truncated = good.clone();
        truncated.truncate(EVENT_WIRE_LEN - 1);
        let mut oversize = good.clone();
        oversize.push(0);
        // A comm the kernel copied with a non-UTF-8 tail decodes fine; the
        // tail is cut, not propagated into the export.
        let hostile_comm = open_path("openat", "/var/run/docker.sock")
            .comm_raw(b"cur\xffl")
            .build(arch);

        let stats = pump_records(
            &agent,
            arch,
            vec![truncated, oversize, hostile_comm, good],
            &sink,
        );
        assert_eq!(
            stats,
            PumpStats {
                handled: 2,
                decode_failed: 2,
                unknown_syscall: 0,
            },
            "{}",
            arch.as_str()
        );
        assert_eq!(agent.records_decode_failed_total(), 2);
        assert_eq!(
            agent.events_dropped_total(),
            0,
            "a malformed record is not an in-kernel ring drop"
        );

        let events = sink.events();
        assert_eq!(events.len(), 2, "only decodable records reach the sink");
        assert_eq!(events[0].comm, "cur");
        for event in &events {
            assert_eq!(event.action, "kill", "no fail-open after a bad record");
            assert!(event.executed);
        }
        assert_eq!(agent.respond_kill_total(), 2);
        assert_eq!(killed_tgids(&killed).len(), 2);
    }
}

/// One set of logical events, two arches, one verdict sequence. The arch split
/// lives in the syscall numbering, and nowhere else.
#[test]
fn both_arches_reach_the_same_verdicts_on_the_same_logical_events() {
    let logical = || {
        vec![
            shell_exec("execve", "sh"),
            shell_exec("execveat", "bash"),
            open_path("openat", "/var/run/docker.sock"),
            open_path("openat", "/tmp/app.sock"),
            bpf_call("loader"),
        ]
    };

    let mut per_arch = Vec::new();
    for arch in ARCHES {
        let (agent, _killed) = replay_agent(None);
        let sink = MemorySink::new();
        let records: Vec<Vec<u8>> = logical().iter().map(|r| r.build(arch)).collect();
        let stats = pump_records(&agent, arch, records, &sink);
        assert_eq!(stats.handled, 5);
        assert_eq!(stats.unknown_syscall, 0, "{}", arch.as_str());

        let verdicts: Vec<(String, String, String)> = sink
            .events()
            .iter()
            .map(|e| (e.syscall.clone(), e.action.clone(), e.rule.as_str().into()))
            .collect();
        per_arch.push((arch, verdicts));
    }

    let (first_arch, first) = &per_arch[0];
    let (second_arch, second) = &per_arch[1];
    assert_eq!(
        first,
        second,
        "{} and {} disagree on the same logical events",
        first_arch.as_str(),
        second_arch.as_str()
    );
    // The nrs themselves must differ, or the comparison above proves nothing.
    assert_ne!(
        syscall_nr(SyscallArch::X86_64, "execve"),
        syscall_nr(SyscallArch::Aarch64, "execve")
    );
}

fn fixture(arch: SyscallArch, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/replay")
        .join(arch.as_str())
        .join(name)
}

/// Recorded bytes, read from disk and replayed.
///
/// The builder looks its nrs up in the decode table, so a builder-driven
/// scenario cannot see the table itself drift. These records carry the nrs
/// written down once, per arch: they are the only thing here that fails when
/// the table stops agreeing with the kernel ABI.
///
/// The wire format is native endian by definition (`Event` is written by a
/// program on the same machine), so committed records are comparable only on
/// a little-endian host.
#[cfg(target_endian = "little")]
#[test]
fn recorded_fixture_records_still_produce_the_acceptance_verdicts() {
    for arch in ARCHES {
        let cases = [
            (
                "exec-shell.bin",
                shell_exec("execve", "sh"),
                "no-shell",
                "kill",
            ),
            (
                "docker-sock.bin",
                open_path("openat", "/var/run/docker.sock"),
                "no-runtime-sock",
                "kill",
            ),
            ("bpf-loader.bin", bpf_call("loader"), "no-module", "audit"),
        ];

        let (agent, _killed) = replay_agent(None);
        let sink = MemorySink::new();
        let mut records = Vec::new();
        for (name, builder, _, _) in &cases {
            let bytes = std::fs::read(fixture(arch, name)).expect("fixture record");
            assert_eq!(bytes.len(), EVENT_WIRE_LEN, "{name}");
            assert_eq!(
                bytes,
                builder.build(arch),
                "{}/{name}: the decode table no longer maps the recorded nr",
                arch.as_str()
            );
            records.push(bytes);
        }

        let stats = pump_records(&agent, arch, records, &sink);
        assert_eq!(stats.handled, cases.len() as u64, "{}", arch.as_str());
        for (event, (name, _, rule, action)) in sink.events().iter().zip(cases.iter()) {
            assert_eq!(event.rule.as_str(), *rule, "{name}");
            assert_eq!(event.action, *action, "{name}");
        }
    }
}
