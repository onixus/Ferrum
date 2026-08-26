# FERRUM — правила для агентов

Self-hosted Kubernetes enforcement plane. Не CNAPP. Не «единое окно».
Admission + runtime, подписанный PolicyBundle, last-known-good вместо fail-open.

Источник истины по архитектуре: `docs/rfc/FERRUM-RFC-02-architecture.md`.
Каталог CRD: `docs/crd/README.md`.

Репозиторий сейчас — каркас workspace и API-типов, не готовый агент.
Пустой crate не называть MVP.

## Toolchain

- Workspace: Rust 1.75, edition 2021, GPL-3.0-only (`rust-toolchain.toml`).
- `kube-derive` не подключать на 1.75: транзитивные crate требуют edition2024.
- Nightly только у `ferrum-ebpf-progs`. Userspace — stable + musl.
- Перед сдачей: `cargo fmt`, `cargo clippy -p <crate> -- -D warnings` на затронутых crate.
- Тесты точечно: `cargo test -p <crate>`. Не гонять весь workspace без нужды.
- Политики без кластера: `cargo run -p ferrum-cli -- validate policies/examples/<file>.yaml`.

## Границы crate

Что исполняется на hot path, не тащит kube client, serde_yaml и сеть.

| Crate | Можно | Нельзя |
|---|---|---|
| `ferrum-api` | serde-типы CRD `ferrum.io/v1` | aya, wasmtime, kube client |
| `ferrum-policy` | инварианты YAML/spec | kube, сеть, tokio, aya |
| `ferrum-compiler` | offline compile в bundle | живой кластер, webhook, hot path |
| `ferrum-admission` | исполнение уже собранного bundle | compiler, CAP_BPF, Rekor на каждый Pod |
| `ferrum-agent` | eBPF + last-known-good | compiler, cluster-admin SA |
| `ferrum-ebpf-progs` | aya-ebpf datapath | tokio, kube, `String` на syscall path |
| `ferrum-controller` | reconcile + compile + rollout | datapath, CAP_BPF |
| `ferrum-crypto` | подпись/проверка bundle, mTLS material | фейковый `Ok` |
| `ferrum-cli` | `ferrumctl` offline | живой кластер в MVP-1 |

Версии в проде сшиваются `PolicyBundle.digest`. Несовместимый агент bundle не грузит и остаётся на last-known-good.

Не расширяйте `Cargo.toml` чужими crate без явной нужды. Зависимости в манифесте — контракт границы.

## Инварианты политики

- deny бьёт allow;
- exception бьёт deny только в своём scope и до `expiresAt`;
- `expiresAt` обязателен, максимум 90 дней;
- namespaced `SecurityPolicy` не может `failurePolicy=Ignore`;
- trust roots едут в bundle; admission не ходит в Rekor на каждый Pod;
- `disabled=true` вместе с `mode=enforce` — ошибка валидации;
- Kill/Isolate без match (syscall/comm/path) — ошибка валидации, это kill-all;
- `verify_bundle_signature` и аналоги не возвращают фейковый `Ok`.

Секции политики: `supply` + `admit` + `runtime`.

## Threat model агента

Агент — вторая цель после kubelet. Не доверяем: workload, privileged pod, root на ноде, CP как единственный корень доверия. Root на ноде enforcement не побеждает.

- cgroup→pod + mTLS **и** подпись bundle;
- LSM на pin path; self-watch не в том же процессе;
- journal + IdP на break-glass;
- in-kernel drop, CPU cgroup, `events_dropped_total`;
- два SA: observe и respond; respond выключен по умолчанию;
- CP down ≤ 2ч → last-known-good, `Degraded=true`, не fail-open.

## MVP-1

Enforce: CIS 5.1.1 / 5.1.3 / 5.1.5 / 5.2.1–5.2.9, PSS restricted, T1610, T1609, T1059, T1611, T1525.

Вне MVP-1: CIS 1.x/4.x, шифрование etcd, WAF (T1190), облачный IAM.

Приёмка:

- unsigned image → deny
- privileged → deny
- cluster-admin bind → deny
- `kubectl exec` + `/bin/sh` → kill
- docker.sock → kill
- `bpf()` не от агента → deny
- exception без TTL → API reject
- CP down → LKG, не fail-open

## Как работать

- Менять только crate своей роли, плюс тесты этого crate.
- Не писать «заглушка Ok / TODO потом включим enforce».
- Комментарии — только ненужные-из-кода ограничения. Не пересказывать RFC.
- Не добавлять markdown/доки, пока не попросили.
- Параллельные правки — в worktree, не в общем working tree.
