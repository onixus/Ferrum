---
name: implement-ferrum
description: >
  Orchestrate FERRUM implementation by spawning the project agents that match RFC-02 crate boundaries.
  Use when implementing Ferrum, building MVP-1, continuing the crate stubs, or the user runs /implement-ferrum.
  Triggers: "реализуй", "следующий слайс", "бери агентов", "implement ferrum", "MVP-1".
argument-hint: "[slice or crate]"
---

# Implement FERRUM

Parent session coordinates. Implementation happens in project agents under `.grok/agents/`.

Do not implement the slice yourself. Do not spawn `general-purpose` when a Ferrum agent owns the crate.

## Tool-call discipline

Emit `spawn_subagent` in the same response as any claim that an agent is launched. Past tense only after the tool result exists.

## Pick the agent

| Task | `subagent_type` | isolation |
|---|---|---|
| Sequence, PR plan, crate graph | `ferrum-architect` | none |
| CRD types, invariants, YAML | `ferrum-api-policy` | worktree |
| Bundle signature, digest, mTLS material | `ferrum-crypto` | worktree |
| Offline compile, wasm ABI/host | `ferrum-compiler` | worktree |
| Webhook, PSS, admit denies | `ferrum-admission` | worktree |
| Node agent, eBPF, LKG, cgroup→pod | `ferrum-runtime` | worktree |
| Reconcile, compile+sign+rollout | `ferrum-controller` | worktree |
| ferrumctl, fixtures, RFC §D | `ferrum-cli-testkit` | worktree |
| Threat model / Cargo.toml boundaries | `ferrum-auditor` | none |

If the user names a crate, use the row that owns it. If the user says "дальше" / "следующий слайс" and there is no plan, spawn `ferrum-architect` first (blocking), then spawn the agent it names.

Independent crates may run in parallel (separate worktrees). Do not parallelize compiler with admission/runtime that consume an unfinished bundle ABI.

## Spawn

`spawn_subagent`:

- `subagent_type`: from the table
- `background`: `true` for implementers; `false` for architect
- `isolation`: from the table
- `description`: `[<agent>] <slice>` so the pager label is the Ferrum agent
- `prompt`: assigned slice, paths, and "Follow AGENTS.md. Stay in your crate set. Stop and report if the slice needs another agent."

After an implementer completes, spawn `ferrum-auditor` with `isolation: none` against that diff unless the user said to skip review.

## After each slice

Report: agent, crates touched, tests run, remaining MVP-1 acceptance from `AGENTS.md` that is still red.

Next slice defaults to the RFC sequence in `ferrum-architect` unless the user overrides.
