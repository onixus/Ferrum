---
name: ferrum-api-policy
description: >
  Implements ferrum-api, ferrum-policy, ferrum-ids, ferrum-proto, ferrum-common.
  Use for CRD types ferrum.io/v1, policy invariants, YAML roundtrip, deny/allow/exception rules.
  Spawn for ClusterSecurityPolicy, SecurityPolicy, PolicyException, PolicyLibrary types.
  Use when the user runs /ferrum-api-policy.
prompt_mode: full
model: inherit
permission_mode: default
agents_md: true
---

Implement API types and policy invariants. Follow `AGENTS.md`.

## Own

`crates/ferrum-api`, `crates/ferrum-policy`, `crates/ferrum-ids`, `crates/ferrum-proto`, `crates/ferrum-common`.

## Forbidden

- `aya`, `wasmtime`, `kube` client, `reqwest`, `tokio` in these crates
- `kube-derive` on rustc 1.75
- Interpreting datapath or talking to a cluster

## Must preserve

- serde YAML matches `policies/examples/` and `docs/crd/README.md`
- deny beats allow; exception beats deny only in scope until `expiresAt`
- `expiresAt` required, max 90 days; empty ticket / short reason / fourEyes without approvedBy fail
- namespaced policy cannot `failurePolicy=Ignore`
- `disabled=true` + `mode=enforce` fails
- Kill/Isolate without match fails
- `AGENT_ABI` / `ADMISSION_ABI` live in `ferrum-ids`

## Done when

```bash
cargo test -p ferrum-api -p ferrum-policy
cargo run -p ferrum-cli -- validate policies/examples/prod-restricted.yaml
cargo run -p ferrum-cli -- validate policies/examples/exception-ok.yaml
cargo run -p ferrum-cli -- validate policies/examples/exception-bad-no-ticket.yaml
```

The bad exception must fail. Do not weaken the test to make it pass.

Smallest change that satisfies the assigned slice. Run `cargo fmt` and clippy on touched crates.
