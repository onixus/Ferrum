# FERRUM

Self-hosted Kubernetes enforcement plane на Rust.

Не CNAPP. Не «единое окно видимости». Admission + runtime enforcement,
подписанные policy bundle, last-known-good вместо fail-open.

Что именно MVP-1 делает, чего он не делает и что про него верят без
доказательства — [docs/MVP-1-BOUNDARY.md](docs/MVP-1-BOUNDARY.md). Три колонки,
четвёртой нет: в «Делает» не попадает ничего, что не было исполнено названным
`#[test]` или названной стадией Jenkins. Гейт
`crates/ferrum-testkit/tests/boundary_gate.rs` роняет сборку, когда строка
переживает свою ссылку, и когда тест в `ferrum-testkit/tests` или
`ferrum-agent/tests` не процитирован ни одной строкой.

Читайте его до статус-встречи, а не после. Запись из ядра доходит до правила
подписанного bundle и до настоящего `SIGKILL` — это исполнено на настоящем
ядре (Linux 6.18.44, x86_64, один стенд). `docker build` здесь не запускался
ни разу, пинов агент не ставит, к API server не обращался никто.

## Workspace

| Crate | Роль |
|---|---|
| `ferrum-common` | общие типы ошибок и мелочь, которую тянут все |
| `ferrum-ids` | идентификаторы и набор syscall датапейса как артефакт |
| `ferrum-api` | CRD / YAML типы `ferrum.io/v1` |
| `ferrum-proto` | `EnforcementEvent`, `EventEnvelope` — формат записи наружу |
| `ferrum-crypto` | подпись bundle (Ed25519), X.509 и mTLS material, офлайн-выпуск webhook PKI |
| `ferrum-policy` | инварианты (waiver без TTL не существует) |
| `ferrum-compiler` | offline compile, не hot path webhook |
| `ferrum-wasm-abi` / `ferrum-wasm-host` | ABI и хост для будущих wasm-правил |
| `ferrum-ebpf` | userspace loader FEBP, prefilter, декодер kernel-записей |
| `ferrum-ebpf-progs` | eBPF datapath: sys_enter tracepoint, `aya-ebpf` под `target_arch = "bpf"` |
| `ferrum-k8smeta` | cgroup→pod индекс, watch Pod/Namespace/ServiceAccount, label cache |
| `ferrum-admission` | validating/mutating webhook, fail-closed, hot-reload bundle, ротация serving-сертификата |
| `ferrum-agent` | единственный BPF-носитель, LKG на диске, respond через `SIGKILL` |
| `ferrum-controller` | reconcile CRD → compile → rollout через Secret, публикация состояния |
| `ferrum-export` | JSONL-сток с ротацией и ограниченной очередью |
| `ferrum-cli` | `ferrumctl`: `validate`, `compile`, `sign`, `verify`, `lint-deploy`, `gen-webhook-pki` |
| `ferrum-testkit` | приёмка, replay записанных ring-байт, гейты границы и дерева установки |

Trust roots везде caller-supplied. Ни один crate не ходит в Rekor, CT log
или иную сеть за корнем доверия и не выпускает CA в рантайме.

## Сборки по умолчанию нет датапейса

Две фичи выключены по умолчанию, и оба выключения намеренные:

- `attach` (`ferrum-agent` → `ferrum-ebpf`) — настоящий kernel attach: нужны
  `CAP_BPF` и собранный под bpf-таргет ELF из `ferrum-ebpf-progs`;
- `apiserver` (`ferrum-agent` → `ferrum-k8smeta`) — Pod metadata по
  `spec.nodeName=$NODE`. Без неё cgroup-индекс никто не наполняет, и агент
  идёт `Degraded`, а не делает вид, что у namespaced-политик просто нет
  workload.

Продуктовая комбинация — `attach,apiserver`, она линкуется под musl. Собирается
она только на Linux: `aya` тянет netlink и `SYS_bpf` из `libc`, которых на
darwin нет, так что на маке `cargo build --features attach` падает на
`aya (lib)` — это хост, а не регрессия. Сборка по умолчанию проверяет bundle и
не имеет датапейса; так и называйте её.

## Проверка

```bash
cargo test --workspace
cargo run -p ferrum-cli -- validate policies/examples/prod-restricted.yaml
cargo run -p ferrum-cli -- lint-deploy deploy
```

Скрипт вердикта — `Jenkinsfile` в корне, джоба `ferrum` на локальном Jenkins
`:8081`. Девятнадцать стадий, разложенных по четырём исполнителям:

- на ноде — `SAST (semgrep)` и три стадии образов (`Agent image`,
  `Admission image`, `Controller image`): им нужен docker CLI, а сокет,
  проброшенный в контейнер, был бы тем самым hostPath, который правила рантайма
  убивают;
- в rust-контейнере родной архитектуры — группа `Build` (`Format`, `Clippy`,
  `Test`, `BPF ELF`), группа `Checks` (`Crate boundary`, `Validate policies`,
  `Security: policy invariants`, `Security: MVP acceptance`,
  `Security: supply chain`) и группа `Datapath` (`BPF attach`, `BPF join`,
  `BPF join mutations`) — последняя стоит в конце пайплайна: ей нужно настоящее
  ядро с tracefs, и её падение на ноде без него больше не уносит с собой
  supply chain и всё остальное, чему ядро не нужно;
- в x86_64-контейнере под эмуляцией — группа `Link` (`Agent binary`,
  `Admission binary`, `Controller binary`). Цель `x86_64-unknown-linux-musl` не
  выводится из архитектуры ноды намеренно: стенд ядра — x86_64, и бинарь,
  слинкованный под arm64, оставил бы стадию зелёной, а утверждение про
  продуктовую комбинацию — про то, чего на стенде не будет.

**Ни одна стадия этого `Jenkinsfile` в Jenkins ещё не проходила.** Билд №17
(28.08, ревизия `4abce25`) — первый прогон этого скрипта, и он упал на самой
первой стадии: `SAST (semgrep)` объявлена `agent any`, чтобы взять `docker` с
ноды, но декоратор верхнеуровневого `agent { docker { ... reuseNode true } }`
доезжает и до неё (JENKINS-30600 в логе), команда исполняется внутри
`rust:1-bookworm`, и там `docker: not found`. Все восемнадцать стадий ниже
пропущены. Пока это так, `U` на строке `Jenkinsfile::<стадия>` в границе
означает «команды стадии прогнаны руками на этом дереве», а не «стадия зелёная
в CI» — см. «Как читать колонку „Исполняется“» в
[MVP-1 boundary](docs/MVP-1-BOUNDARY.md).

Toolchain — 1.97.1 (`rust-toolchain.toml`), kube 1.x + k8s-openapi 0.25.
`kube-derive` тулчейн уже пускает, но фича `derive` не включена: типы
`ferrum-api` остаются serde-эквивалентом тех же манифестов. Nightly нужен
только `ferrum-ebpf-progs` (build-std под bpf-таргет).

## Установка

`deploy/` — дерево манифестов на три компонента: `deploy/controller`,
`deploy/admission` (Deployment, Service, ValidatingWebhookConfiguration как
шаблон), `deploy/agent` (DaemonSet observe плюс отдельный
`optional-respond.yaml` с hostPID и `CAP_KILL`). Два ServiceAccount у агента,
respond выключен по умолчанию.

Дерево не документ, а вход гейта: `ferrumctl lint-deploy` проверяет его на
инварианты threat model (приватный ключ в дереве, `caBundle`-заглушка,
hostPID без respond, спроецированный токен под apiserver-watch и прочее), а
`crates/ferrum-testkit/tests/deploy_gate.rs` роняет сборку, если дерево
перестало быть устанавливаемым. Serving PKI выпускается офлайн:
`ferrumctl gen-webhook-pki`, ротация — под тем же CA, которому кластер уже
доверяет.

Образы: `Dockerfile`, `Dockerfile.admission`, `Dockerfile.controller`. Ни один
из них ни разу не собирался — демона здесь нет.

## Документы

- [MVP-1 boundary](docs/MVP-1-BOUNDARY.md) — что исполнено, что нет, что заявлено
- [RFC-02](docs/rfc/FERRUM-RFC-02-architecture.md) — crate-границы, CRD, threat model агента, CIS/MITRE
- [CRD catalog](docs/crd/README.md)
- [deploy/admission/README](deploy/admission/README), [deploy/agent/README](deploy/agent/README) — установка и ротация

## Лицензия

GPL-3.0 (как в корне репозитория). Не путать с Apache из черновика workspace.
