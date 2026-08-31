# FERRUM — правила для агентов

Self-hosted Kubernetes enforcement plane. Не CNAPP. Не «единое окно».
Admission + runtime, подписанный PolicyBundle, last-known-good вместо fail-open.

Источник истины по архитектуре: `docs/rfc/FERRUM-RFC-02-architecture.md`.
Каталог CRD: `docs/crd/README.md`.

Control plane собран: controller → compile → Secret → admission/agent, LKG на диске.
Датаплейн есть и исполнен на настоящем ядре: запись из kernel доходит до правила
подписанного bundle и до настоящего `SIGKILL`. Стендов два, и они меряют разное:
attach идёт стадией `BPF attach` на aarch64-ноде Jenkins (6.12.76-linuxkit,
зелёная с билда #39), стык — руками на x86_64 (Linux 6.18.44, Firecracker без
`CONFIG_MODULES`), потому что стадия `BPF join` в CI не проходила ни разу.
Какая строка на каком стенде меряна — только `docs/MVP-1-BOUNDARY.md`, и
догадываться по метке `K` нельзя: она говорит «на настоящем ядре», а не «на
этом».

В сборке по умолчанию датапейса нет: фичи `attach` и `apiserver` выключены.
Продуктовая комбинация — `attach,apiserver`. Сборку без них не называть
работающим runtime enforcement; что именно исполнено, а что нет, —
`docs/MVP-1-BOUNDARY.md`, и это единственный источник, который держит гейт.

## Toolchain

- Workspace: Rust 1.97.1, edition 2021, GPL-3.0-only (`rust-toolchain.toml`).
- kube 1.x + k8s-openapi 0.25 (`v1_33`). Тулчейн поднят с 1.75 ради advisories: старый
  стек тянул rustls 0.21 с тремя CVE и пять unmaintained crate.
- Nightly только у `ferrum-ebpf-progs`. Userspace — stable + musl.
- Перед сдачей: `cargo fmt`, `cargo clippy -p <crate> -- -D warnings` на затронутых crate.
- Тесты точечно: `cargo test -p <crate>`. Не гонять весь workspace без нужды.
- Политики без кластера: `cargo run -p ferrum-cli -- validate policies/examples/<file>.yaml`.

## Тесты гоняются в локальном Jenkins

Полный прогон — только на локальном Jenkins `http://localhost:8081`, джоба `ferrum`
(собирает `main` из `/Users/onixus/Git/Ferrum`, скрипт — `Jenkinsfile` в репозитории).
Локально у себя гоняйте максимум `cargo test -p <crate>` по затронутому crate;
вердикт по изменению даёт Jenkins, а не ваша машина.

- Запуск без коммита: `curl -s --get --data-urlencode "url=/Users/onixus/Git/Ferrum" http://localhost:8081/git/notifyCommit`.
  После коммита в `main` джоба стартует сама (post-commit hook + поллинг раз в 2 минуты).
- API-токена нет, UI недоступен: лог билда читать из
  `/Users/onixus/jenkins_home/jobs/ferrum/builds/<N>/log`, артефакты — в `.../archive/`.
- Функциональные стадии: `Format`, `Clippy`, `Test`, `Validate policies` (в ней же
  негативные кейсы), `Crate boundary`, сборка бинарей (`Agent binary`,
  `Admission binary`, `Controller binary`), датапейс (`BPF ELF`,
  `Datapath tracefs`, `BPF attach`, `Datapath cgroup`, `BPF join`,
  `BPF join mutations`) и образы (`Agent image`, `Admission image`,
  `Controller image`). Разложены по исполнителям: нода (docker CLI), группы
  `Build`, `Checks` и `Datapath` в rust-контейнере родной архитектуры, группа
  `Datapath join` — на ноде, контейнер она поднимает сама, — и группа
  `Link`, где цель musl берётся кросс-компиляцией, а не эмуляцией: под QEMU
  падает сам rustc. Цель из архитектуры ноды не выводить, и после появления
  второго стенда причина стала уже, а не исчезла: нода — aarch64, стык же
  меряется на x86_64, и бинарь под arm64 оставил бы стадию зелёной, а
  утверждение про продуктовую комбинацию — про то, чего на том стенде не будет.
  Датапейсные группы стоят в конце: им нужно ядро с tracefs, права
  `CAP_BPF`/`CAP_PERFMON` и писуемая cgroup2, и на ноде без них они падают
  честно, никого за собой не унося. Ничто из трёх не свойство ядра этой
  ноды: tracefs монтирует стадия `Datapath tracefs` одноразовым привилегированным
  контейнером, права даёт `DATAPATH_DOCKER_ARGS`, запись в cgroup —
  `Datapath cgroup` тем же приёмом, и `--pid=host` там же —
  датапейс пишет pid из init-namespace, а тесты сверяют их со своим `getpid()`.
  Пропускать стадию
  по условию нельзя — гейт, умеющий себя пропустить, это тот самый дефект.
  Имена стадий цитирует `docs/MVP-1-BOUNDARY.md`, и
  `crates/ferrum-testkit/tests/boundary_gate.rs` роняет сборку на переименовании —
  стадию не переименовывать в одиночку.
- Текущий `Jenkinsfile` — двадцать пять функциональных стадий. С билда #52
  проходили все двадцать одна, что было тогда: пропусков нет,
  `Finished: SUCCESS`, первый зелёный прогон целиком. Четыре добавлены после
  того прогона и на Jenkins не исполнялись **ни разу**:
  `Security: metrics contract`, `Security: admission latency`,
  `Security: event contract` и `Security: break-glass`. На этой машине они
  проходят как `cargo test -p ferrum-testkit --test metrics_gate`,
  `cargo test --release -p ferrum-testkit --test latency_gate`,
  `cargo test -p ferrum-proto && cargo test -p ferrum-siem && cargo test -p
  ferrum-testkit --test event_contract_gate` и
  `cargo test -p ferrum-breakglass && cargo test -p ferrum-testkit --test
  break_glass_gate`, и это не то же самое. Предыдущая редакция этого пункта
  говорила «двадцать три» и называла двумя последними стадии metrics и event:
  она отстала на `Security: admission latency`, добавленную циклом раньше, —
  то самое занижение, от которого есть `docs/MVP-1-BOUNDARY.md`.
  Из того прогона: `BPF join` — шесть тестов из шести, четыре печатают
  `SIGKILL`, подтверждённый `waitpid`; `BPF join mutations` исполнилась впервые
  и убила все шесть мутаций. Красным пайплайн был с #16 по #51.
- Стык живёт в группе `Datapath join` на `agent any`, а не в docker-группе:
  ему нужен remount cgroupfs снаружи, то есть docker CLI, а вложенная в
  `agent { docker }` стадия его не получает — JENKINS-30600, билд #42 упал
  именно так и унёс за собой зелёную `BPF attach`. Контейнер эта группа
  поднимает и останавливает сама, тела стадий идут в него `docker exec`.
  `BPF attach` осталась в docker-группе намеренно.
- Пробы стыка обязаны прогревать страницы пути (`fault_in_path`) перед
  syscall: `bpf_probe_read_user_str` не фолтит, и на aarch64-ноде путь,
  который ребёнок не тронул после `fork`, приходит пустым, а тронутый на один
  байт — префиксом, если пересекает границу страницы. Правило по пути на
  нечитаемом пути совпадение **утверждает**, а не пропускает, поэтому такая
  проба ловит на себе чужие правила.
- Целиться в `pid_max + 1` как в «несуществующий pid» нельзя: на ноде
  `pid_max` равен `PID_MAX_LIMIT`, он же `MAX_TGID`, и агент такой tgid не
  сигналит по построению. Опираться на `MAX_TGID`, а не на своё число. Прежняя редакция этого пункта говорила «ни одна стадия ещё не
  проходила: билд №17 упал на `SAST (semgrep)`» — она отстала на двадцать
  четыре билда, и это то же занижение, от которого есть
  `docs/MVP-1-BOUNDARY.md`, только в файле для агентов.
- `U` на строке `Jenkinsfile::<стадия>` в границе по-прежнему **не** значит
  «зелено в CI»: гейт проверяет только то, что стадия с таким именем есть в
  файле. Что именно исполнялось и где — раздел «Как читать колонку
  „Исполняется“» в границе, и только он.
- Стадии security: `SAST (semgrep)`, `Security: policy invariants`,
  `Security: MVP acceptance` (приёмка из раздела MVP-1),
  `Security: metrics contract` (`metrics_gate.rs`: дашборд и код называют одни
  семейства в обе стороны, у каждой причины деградации есть стабильный id,
  порт метрик открыт манифестами и закрыт NetworkPolicy, эндпоинт отвечает
  только на чтение),
  `Security: event contract` (`event_contract_gate.rs`: инвентарь полей
  `EventEnvelope` выводится сериализацией самого типа и сходится с
  замороженным для заявленной версии, записи прошлых версий декодируются этой
  сборкой, у каждого листа конверта есть написанное решение «уходит наружу или
  нет», withheld отсутствует во всех трёх профилях, враждебная нагрузка не
  подделывает запись, и сток исполнён на локальном сокете),
  `Security: break-glass` (`break_glass_gate.rs`: подписанный grant
  приостанавливает review, который поставляемая политика отвергает, и перестаёт
  после `expiresAt` без единой перезагрузки; ключ подписи bundle grant'ом не
  является; бессрочного окна выразить нечем и потолок туже потолка waiver'а;
  установка по умолчанию break-glass не армирует; и `docs/runbooks/README.md`
  держится за дерево — пути, имена метрик, id причин деградации, числа радиуса
  поражения и дословная строка про внешний IdP),
  `Security: supply chain` (cargo-deny + cargo-audit).
- Новый инвариант или новый пункт приёмки — добавлять тест в security-стадию,
  а не в общий `cargo test`. Красная security-стадия не «флейк»: это нарушенный инвариант.

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
| `ferrum-ebpf` | userspace loader, prefilter, декодер kernel-записей | compiler, kube client, сеть |
| `ferrum-k8smeta` | cgroup→pod индекс, watch Pod/NS/SA, label cache | датапейс, вывод наблюдённости из пустоты |
| `ferrum-export` | JSONL-сток, ограниченная очередь, fan-out по стокам | блокирующая запись на hot path, тихая потеря записи, сеть |
| `ferrum-siem` | нормализация `EventEnvelope` в CEF/RFC 5424/ECS, неблокирующий сток на `std::net`, учтённая потеря | tokio, TLS, kube client, HTTP-клиент, растущий буфер ретраев, тихая потеря записи, поле без решения в `FIELDS` |
| `ferrum-metrics` | Prometheus-экспозиция, счётчики/гистограмма на атомиках, read-only `GET /metrics` | зависимости (их ноль), kube client, TLS, исходящая сеть, чтение тела запроса, аллокации на hot path |
| `ferrum-breakglass` | формат подписанного grant'а, потолок окна, хеш-цепочка журнала | kube client, сеть (в том числе обращение к IdP), tokio, бессрочный grant, журнал, который можно не писать |
| `ferrum-controller` | reconcile + compile + rollout | datapath, CAP_BPF |
| `ferrum-crypto` | подпись/проверка bundle, mTLS material (ring, rustls-webpki) | openssl-sys, выпуск CA, сеть, фейковый `Ok` |
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
- `verify_bundle_signature` и аналоги не возвращают фейковый `Ok`;
- `BUNDLE_SIGNATURE_CONTEXT` и `KEY_BIND_MSG` — разные домены: Ed25519-seed
  bundle не является TLS-ключом и не должен проходить проверку как он.

Секции политики: `supply` + `admit` + `runtime`.

## Threat model агента

Агент — вторая цель после kubelet. Не доверяем: workload, privileged pod, root на ноде, CP как единственный корень доверия. Root на ноде enforcement не побеждает.

- cgroup→pod + mTLS **и** подпись bundle;
- LSM на pin path; self-watch не в том же процессе;
- journal + IdP на break-glass. Половина исполнена: `ferrum-breakglass` —
  подписанный в своём домене grant (кто/когда/на какой срок/тикет), обязательный
  `expiresAt` с потолком в четыре часа и хеш-цепочка журнала, в которую пишут
  активации, истечения, отзывы и **отказы**; журнал, в который нельзя писать,
  не даёт grant'у вступить в силу, а армирование без писуемого журнала роняет
  старт процесса. Scope один — `admission`; роль `respond` у агента этим
  механизмом не снимается. Вторая половина внешняя и такой останется: проверка
  отвечает «держатель ключа K это утверждал», а что `subject` — живой
  уполномоченный человек, знает только IdP или PKI, которых в этом дереве нет
  и которые не должны быть на пути (break-glass, падающий вместе с
  недоступным IdP, падает ровно в том отказе, ради которого он есть);
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
