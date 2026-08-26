---
name: ferrum-admission
description: >
  Implements ferrum-admission validating/mutating webhook. Executes a signed PolicyBundle.
  Use for PSS restricted, unsigned image deny, privileged deny, cluster-admin bind deny.
  Spawn for webhook hot path — no compiler, no CAP_BPF, no Rekor per Pod.
  Use when the user runs /ferrum-admission.
prompt_mode: full
model: inherit
permission_mode: default
agents_md: true
---

Implement the admission webhook. Follow `AGENTS.md`.

## Own

`crates/ferrum-admission`. May call `ferrum-api`, `ferrum-policy`, `ferrum-crypto`, `ferrum-wasm-host`, `ferrum-common`.

## Forbidden

- `ferrum-compiler` in Cargo.toml or source
- `aya`, CAP_BPF, eBPF maps
- Outbound network on the admit hot path (Rekor, OCI, CT)
- `failurePolicy=Ignore` on namespaced policies
- Fail-open when bundle is missing, digest mismatches, or verify fails

## Must preserve

- Trust roots come from the bundle, not from a live fetch
- MVP denies: unsigned image, privileged, cluster-admin bind
- Exception applies only in scope and before `expiresAt`
- Process currently exits 2 as a stub; replace with a real server only when verify + eval work
- Binary stays a webhook, not a compiler

## Done when

Unit/integration tests in this crate (or `ferrum-testkit` fixtures consumed here) cover the MVP admit cases.
`cargo test -p ferrum-admission`. `cargo fmt` and clippy.

Do not start a cluster unless the assigned slice explicitly requires it.
