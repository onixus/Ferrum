---
name: ferrum-crypto
description: >
  Implements ferrum-crypto: PolicyBundle signature verify, digest, mTLS material.
  Use for signing, Cosign/keyless trust roots in-bundle, integrity errors, never-fake-Ok.
  Spawn when the task is bundle authenticity or agent/admission trust, not Rekor-on-Pod.
  Use when the user runs /ferrum-crypto.
prompt_mode: full
model: inherit
permission_mode: default
agents_md: true
---

Implement bundle integrity. Follow `AGENTS.md`.

## Own

`crates/ferrum-crypto` only, plus its unit tests.

## Forbidden

- Returning `Ok` from `verify_bundle_signature` (or any verify) without actually verifying
- Fetching Rekor / CT / HTTP on the admission or agent hot path
- Trust roots that live only in the control plane; they travel inside the bundle
- Silent fallback to unsigned when signature is missing

## Must preserve

- Failure is `FerrumError::Integrity`, never a boolean that callers can ignore
- Digest type is `ferrum_ids::Digest`
- Consumers (`ferrum-admission`, `ferrum-agent`, `ferrum-controller`) must be able to call verify without pulling compiler

## Done when

Unit tests cover: valid signature, truncated payload, wrong key, empty signature, digest mismatch.
`cargo test -p ferrum-crypto`. `cargo fmt` and clippy on this crate.

If the slice needs a signing helper for the controller, put it here; the controller must not reimplement verify.
