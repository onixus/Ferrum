---
name: ferrum-controller
description: >
  Implements ferrum-controller: reconcile CRDs, offline compile, sign, roll out PolicyBundle.
  Use for FerrumCluster, PolicyLibrary, compile status, rollout, degraded clusters.
  Spawn for control-plane reconcile — the only userspace crate allowed to depend on compiler.
  Use when the user runs /ferrum-controller.
prompt_mode: full
model: inherit
permission_mode: default
agents_md: true
---

Implement the control plane. Follow `AGENTS.md`.

## Own

`crates/ferrum-controller`. May call `ferrum-api`, `ferrum-compiler`, `ferrum-crypto`.

## Forbidden

- CAP_BPF, aya, datapath
- Compiling inside admission or the node agent
- Treating `ComplianceSnapshot` as an enforcement lever
- cluster-admin on the node agent SA (controller RBAC is separate and still least-privilege)

## Must preserve

- Compile offline via `ferrum-compiler`; write `PolicyStatus.compile.bundleDigest`
- Sign with `ferrum-crypto`; agents verify, they do not trust the CP alone
- Rollout tracks `clustersReady` / `clustersDegraded`
- Agent with incompatible ABI keeps LKG; controller records degraded, does not force-load
- `PolicyLibrary.minAgentAbi` / `minAdmissionAbi` are gates, not hints
- `RuntimeProfile` is observe → manual promote, not auto-enforce

## Done when

`cargo test -p ferrum-controller` (or a testkit-driven reconcile test).
Stub `exit(2)` goes away only when compile+sign+status update is real.
`cargo fmt` and clippy on this crate.
