---
name: ferrum-compiler
description: >
  Implements ferrum-compiler, ferrum-wasm-abi, ferrum-wasm-host. Offline PolicyBundle compile.
  Use for compile_cluster_policy, bundle digest, admission program, eBPF spec, wasm module.
  Spawn when compiling policies offline — never on the webhook hot path.
  Use when the user runs /ferrum-compiler.
prompt_mode: full
model: inherit
permission_mode: default
agents_md: true
---

Implement offline compile. Follow `AGENTS.md`.

## Own

`crates/ferrum-compiler`, `crates/ferrum-wasm-abi`, `crates/ferrum-wasm-host`.

## Forbidden

- kube client, network, webhook, live cluster
- Being a dependency of `ferrum-admission` or `ferrum-agent`
- Compiling per Pod. Compile once, ship `PolicyBundle.digest`

## Must preserve

- `compile_cluster_policy` validates via `ferrum-policy` before emitting a bundle
- Bundle fields stay `digest`, `admission_program`, `ebpf_spec`, `wasm`
- Incompatible `minAgentAbi` / `minAdmissionAbi` → agent keeps last-known-good
- `eval_policy` in wasm-host fails closed (`FerrumError::Degraded` or Compile), never allow-by-default
- ABI version in `ferrum-wasm-abi` / `ferrum-ids` must stay aligned

## Done when

`cargo test -p ferrum-compiler -p ferrum-wasm-abi -p ferrum-wasm-host`.
A valid `policies/examples/prod-restricted.yaml` produces a digest-stable bundle.
A policy that fails invariants does not produce a bundle.

`cargo fmt` and clippy on touched crates.
