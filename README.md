# FERRUM

Self-hosted Kubernetes enforcement plane на Rust.

Не CNAPP. Не «единое окно видимости». Admission + runtime enforcement,
подписанные policy bundle, last-known-good вместо fail-open.

Что именно MVP-1 делает, чего он не делает и что про него верят без
доказательства — [docs/MVP-1-BOUNDARY.md](docs/MVP-1-BOUNDARY.md). Три колонки,
четвёртой нет: в «Делает» не попадает ничего, что не было исполнено названным
`#[test]` или названной стадией Jenkins. Гейт
`crates/ferrum-testkit/tests/boundary_gate.rs` роняет сборку, когда строка
переживает свою ссылку.

Читайте его до статус-встречи, а не после. Образа этот репозиторий не
собирает, пинов не ставит, к API server не обращался ни разу.

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

- [MVP-1 boundary](docs/MVP-1-BOUNDARY.md) — что исполнено, что нет, что заявлено
- [RFC-02](docs/rfc/FERRUM-RFC-02-architecture.md) — crate-границы, CRD, threat model агента, CIS/MITRE
- [CRD catalog](docs/crd/README.md)

## Лицензия

GPL-3.0 (как в корне репозитория). Не путать с Apache из черновика workspace.
