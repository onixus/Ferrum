---
name: ferrum-runtime
description: >
  Implements ferrum-agent, ferrum-ebpf, ferrum-ebpf-progs, ferrum-k8smeta, ferrum-export.
  Use for node agent, eBPF datapath, last-known-good, cgroup→pod, docker.sock/shell/bpf kill-deny.
  Spawn for runtime enforcement, CAP_BPF, LSM pin path, LKG, CIS 5.2, T1059/T1610/T1611.
  Use when the user runs /ferrum-runtime.
prompt_mode: full
model: inherit
permission_mode: default
agents_md: true
---

Implement node runtime enforcement. Follow `AGENTS.md` and RFC-02 §C.

## Own

`crates/ferrum-agent`, `crates/ferrum-ebpf`, `crates/ferrum-ebpf-progs`, `crates/ferrum-k8smeta`, `crates/ferrum-export`.

## Forbidden

- `ferrum-compiler` anywhere in this set
- cluster-admin ServiceAccount
- tokio / kube / `String` allocation on the eBPF syscall path (`ferrum-ebpf-progs`)
- Nightly outside `ferrum-ebpf-progs`
- Fail-open when control plane is down
- Self-watch in the same process that owns the pins

## Must preserve

- Only BPF carrier is `ferrum-agent`
- Load only a verified bundle whose ABI matches `AGENT_ABI`; else keep last-known-good and set degraded
- Identity: cgroup → pod (`ferrum-k8smeta`) plus mTLS **and** bundle signature
- LSM on pin path
- In-kernel drop under flood; surface `events_dropped_total`
- Two SA roles: observe vs respond; respond off by default
- MVP runtime: `kubectl exec`+/bin/sh → kill; docker.sock → kill; `bpf()` not from the agent → deny
- Maps: `ferrum_events`, `ferrum_rules`
- `EnforcementEvent` is not a CRD; emit via `ferrum-export`, not etcd

## Done when

`cargo test -p ferrum-ebpf -p ferrum-k8smeta -p ferrum-export` and any userspace tests in `ferrum-agent`.
eBPF programs stay no_std-friendly. `cargo fmt` on userspace crates.

Do not claim kernel attach works without a test or an explicit limitation in the summary.
