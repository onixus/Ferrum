# FERRUM

Self-hosted Kubernetes enforcement plane на Rust.

Не CNAPP. Не «единое окно видимости». Admission + runtime enforcement,
подписанные policy bundle, last-known-good вместо fail-open.

Control plane собран: контроллер компилирует и раскатывает подписанный
bundle, admission исполняет его fail-closed, агент держит last-known-good
на диске. Датаплейна нет: `aya-ebpf` требует nightly, kernel attach в
userspace возвращает `Degraded`. Пока это не изменится, «runtime
enforcement» на статус-встрече называть работающим нельзя.

## Workspace

| Crate | Роль |
|---|---|
| `ferrum-api` | CRD / YAML типы `ferrum.io/v1` |
| `ferrum-policy` | инварианты (waiver без TTL не существует) |
| `ferrum-compiler` | offline compile, не hot path webhook |
| `ferrum-controller` | reconcile CRD → compile → rollout через Secret |
| `ferrum-admission` | validating/mutating webhook, fail-closed |
| `ferrum-agent` | единственный BPF-носитель, LKG на диске |
| `ferrum-ebpf` | userspace loader FEBP |
| `ferrum-ebpf-progs` | eBPF datapath (константы и layout; aya не слинкован) |
| `ferrum-crypto` | подпись bundle (Ed25519) и mTLS material (X.509) |
| `ferrum-cli` | `ferrumctl validate` |

Trust roots везде caller-supplied. Ни один crate не ходит в Rekor, CT log
или иную сеть за корнем доверия и не выпускает CA в рантайме.

## Проверка

```bash
cargo test --workspace
cargo run -p ferrum-cli -- validate policies/examples/prod-restricted.yaml
```

Вердикт по изменению даёт локальный Jenkins на :8081, джоба `ferrum`,
скрипт — `Jenkinsfile` в корне: fmt, clippy `-D warnings`, тесты, валидация
примеров политик, `cargo deny` + `cargo audit`.

Toolchain — 1.97.1 (`rust-toolchain.toml`), kube 1.x + k8s-openapi 0.25.
`kube-derive` тулчейн уже пускает, но фича `derive` не включена: типы
`ferrum-api` остаются serde-эквивалентом тех же манифестов.

## Документы

- [RFC-02](docs/rfc/FERRUM-RFC-02-architecture.md) — crate-границы, CRD, threat model агента, CIS/MITRE
- [CRD catalog](docs/crd/README.md)

## Лицензия

GPL-3.0 (как в корне репозитория). Не путать с Apache из черновика workspace.
