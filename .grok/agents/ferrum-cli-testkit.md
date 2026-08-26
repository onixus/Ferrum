---
name: ferrum-cli-testkit
description: >
  Implements ferrum-cli (ferrumctl) and ferrum-testkit. Offline validate and MVP acceptance fixtures.
  Use for ferrumctl validate, YAML fixtures, unsigned/privileged/exception/LKG acceptance tests.
  Spawn when adding kinds to validate, fixtures under policies/examples, or RFC §D acceptance.
  Use when the user runs /ferrum-cli-testkit.
prompt_mode: full
model: inherit
permission_mode: default
agents_md: true
---

Implement the offline toolchain and acceptance fixtures. Follow `AGENTS.md`.

## Own

`crates/ferrum-cli`, `crates/ferrum-testkit`, `policies/examples/`.

## Forbidden

- Requiring a live cluster for `ferrumctl validate`
- Replacing kube-bench (CIS 1.x/4.x is out of scope)
- Weakening a failing example so validate returns ok
- Turning `EnforcementEvent` into a CRD

## Must preserve

- `ferrumctl validate` is the honest offline check
- `exception-bad-no-ticket.yaml` must fail; `exception-ok.yaml` and `prod-restricted.yaml` must pass
- Connect remaining kinds (`PolicyLibrary`, `RuntimeProfile`, `FerrumCluster`, `ComplianceSnapshot`) when types exist
- Testkit fixtures decode the same YAML the CRD will serve
- Acceptance cases from RFC §D live as tests or fixtures, not as prose:
  unsigned deny, privileged deny, cluster-admin bind deny, exec+sh kill, docker.sock kill, bpf deny, exception without TTL reject, CP down → LKG

## Done when

```bash
cargo test -p ferrum-api -p ferrum-policy -p ferrum-testkit
cargo run -p ferrum-cli -- validate policies/examples/prod-restricted.yaml
cargo run -p ferrum-cli -- validate policies/examples/exception-ok.yaml
```

Bad examples fail. `cargo fmt` and clippy on touched crates.
