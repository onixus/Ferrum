# FERRUM

Self-hosted Kubernetes enforcement plane на Rust.

Не CNAPP. Не «единое окно видимости». Admission + runtime enforcement,
подписанные policy bundle, last-known-good вместо fail-open.

Репозиторий сейчас — каркас workspace и API-типов (RFC-02), а не готовый агент.
Если кто-то назовёт пустые crate MVP на статус-встрече — поправьте его
до того, как это уедет в Jira.

## Workspace

| Crate | Роль |
|---|---|
| `ferrum-api` | CRD / YAML типы `ferrum.io/v1` |
| `ferrum-policy` | инварианты (waiver без TTL не существует) |
| `ferrum-compiler` | offline compile, не hot path webhook |
| `ferrum-admission` | validating/mutating webhook |
| `ferrum-agent` | единственный BPF-носитель |
| `ferrum-ebpf-progs` | eBPF datapath |
| `ferrum-cli` | `ferrumctl validate` |

## Проверка

```bash
cargo test -p ferrum-api -p ferrum-policy
cargo run -p ferrum-cli -- validate policies/examples/prod-restricted.yaml
```

На rustc 1.75 `kube-derive` не подключён: транзитивные crate требуют edition2024.
Типы — serde-эквивалент тех же манифестов. Макрос — на toolchain >= 1.85.

## Документы

- [RFC-02](docs/rfc/FERRUM-RFC-02-architecture.md) — crate-границы, CRD, threat model агента, CIS/MITRE
- [CRD catalog](docs/crd/README.md)

## Лицензия

GPL-3.0 (как в корне репозитория). Не путать с Apache из черновика workspace.
