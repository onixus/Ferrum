# FERRUM

Self-hosted Kubernetes enforcement plane на Rust.

Не CNAPP. Не «единое окно видимости». Admission + runtime enforcement,
подписанные policy bundle, last-known-good вместо fail-open.

Что именно MVP-1 делает, чего он не делает и что про него верят без
доказательства — [docs/MVP-1-BOUNDARY.md](docs/MVP-1-BOUNDARY.md). Три колонки,
четвёртой нет: в «Делает» не попадает ничего, что не было исполнено названным
`#[test]` или названной стадией Jenkins. Гейт
`crates/ferrum-testkit/tests/boundary_gate.rs` роняет сборку, когда строка
переживает свою ссылку, и когда тест в `ferrum-testkit/tests`,
`ferrum-agent/tests`, `ferrum-admission/tests` или `ferrum-ebpf/tests` не
процитирован ни одной строкой.

Читайте его до статус-встречи, а не после. Запись из ядра доходит до правила
подписанного bundle и до настоящего `SIGKILL` — это исполнено на настоящем
ядре, и с билда #52 обеими датапейсными стадиями в CI, на aarch64-ноде.
Стендов по-прежнему два: x86_64 (Linux 6.18.44, Firecracker) остаётся тем, где
стык гоняли руками. Образы собираются на ноде в каждом
билде, но `docker push` не делал никто и ни один из них не запускали; пинов
агент не ставит, к API server не обращался никто.

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
`:8081`. Двадцать одна стадия, разложенная по пяти исполнителям:

- на ноде — `SAST (semgrep)`, три стадии образов (`Agent image`,
  `Admission image`, `Controller image`) и `Datapath tracefs`: всем нужен
  docker CLI, а сокет, проброшенный в контейнер, был бы тем самым hostPath,
  который правила рантайма убивают. `Datapath tracefs` монтирует tracefs
  одноразовым привилегированным контейнером, не исполняющим ни строки
  репозитория: изнутри сборочного контейнера это потребовало бы
  `CAP_SYS_ADMIN`, который ему не дают;
- в rust-контейнере родной архитектуры — группа `Build` (`Format`, `Clippy`,
  `Test`, `BPF ELF`), группа `Checks` (`Crate boundary`, `Validate policies`,
  `Security: policy invariants`, `Security: MVP acceptance`,
  `Security: supply chain`) и группа `Datapath` (`BPF attach`) — последняя
  стоит ближе к концу пайплайна: ей нужно настоящее ядро с tracefs, и её
  падение на ноде без него больше не уносит с собой supply chain и всё
  остальное, чему ядро не нужно;
- на ноде же — группа `Datapath join` (`Datapath cgroup`, `BPF join`,
  `BPF join mutations`), которая поднимает и останавливает свой контейнер
  сама. Стыку нужна писуемая cgroup2, а Docker монтирует cgroupfs на чтение;
  remount делает снаружи одноразовый привилегированный контейнер, и для этого
  нужен docker CLI, которого вложенная в docker-группу стадия не получает
  (JENKINS-30600). `BPF attach` осталась в группе `Datapath` намеренно: она
  зелёная, и переносить её вместе со стыком значило бы рискнуть тем, что уже
  доказано;
- группа `Link` (`Agent binary`, `Admission binary`, `Controller binary`) — тоже
  в контейнере родной архитектуры, но цель `x86_64-unknown-linux-musl` берётся
  кросс-компиляцией: `rustc` идёт нативно, C-половину `ring` компилирует
  `gcc-x86-64-linux-gnu` из штатного Debian, линкует `rust-lld` тем musl,
  который везёт rustup. Цель из архитектуры ноды не выводится намеренно:
  нода — aarch64, а стенд стыка x86_64, и бинарь под arm64 оставил бы стадию
  зелёной, а утверждение про продуктовую комбинацию — про то, чего на том
  стенде не будет.

Все двадцать одна стадия проходят на локальном Jenkins начиная с билда #52
(31.08.2026) — первый зелёный прогон целиком, пропусков нет. `BPF attach` —
девять тестов из девяти против ядра ноды; `BPF join` — шесть из шести, четыре
печатают `SIGKILL`, подтверждённый `waitpid`; `BPF join mutations` исполнилась
впервые и убила все шесть мутаций. С #16 по #51 пайплайн был красным, и чем
именно — в границе, по билдам.

`FERRUM_BPF_ELF_REQUIRED` превращает пропуск в падение, чтобы стадия не могла
пройти, не исполнившись. На машине без ядра пайплайн красный, и это не
настраивается: гейт, умеющий себя пропустить, здесь считается дефектом.

`U` на строке `Jenkinsfile::<стадия>` в границе по-прежнему не значит «зелено
в CI» — гейт проверяет только то, что стадия с таким именем есть в файле. Что
именно исполнялось и где, читайте в «Как читать колонку „Исполняется“» в
[MVP-1 boundary](docs/MVP-1-BOUNDARY.md).

### Публичный CI

`.github/workflows/ci.yml` гоняет на GitHub Actions четыре стадии из того же
`Jenkinsfile` и с теми же командами: `Format`, `Clippy`, `Test` и группу
`Checks` целиком (`Crate boundary`, `Validate policies`,
`Security: policy invariants`, `Security: MVP acceptance`,
`Security: supply chain`). Скрипты шагов совпадают со стадиями построчно, и
это держит `deploy_gate.rs::actions_parity`: два CI, гоняющие похожее, дают
два разных вердикта об одном дереве.

Датапейс там не исполняется и исполняться не будет: `BPF ELF`, `BPF attach`,
`BPF join`, `BPF join mutations`, `Datapath tracefs`, `Datapath cgroup`
требуют настоящего ядра с tracefs, прав `CAP_BPF`/`CAP_PERFMON`, писуемой
cgroup2 и pid-namespace хоста, а раннер `ubuntu-latest` не даёт ничего из
этого. Стадия с именем `BPF attach`, зелёная без исполненного attach, была бы
ровно тем гейтом, умеющим себя пропустить, от которого написан весь этот
проект. По той же причине в Actions нет стадий образов и `SAST (semgrep)`:
им нужен docker CLI ноды. Вердикт по датапейсу даёт локальный Jenkins, и
только он.

На GitHub этот воркфлоу ещё не исполнялся ни разу: поставленный файл — не
прогон, и «зелено в Actions» здесь не написано, пока прогона нет.

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

Ставится оно одной командой, и `deploy/README` — про то, что именно она делает
и чего не делает:

```
kubectl apply -k deploy
```

kustomize, а не Helm: `kubectl apply -k` не требует второго бинаря, чарта в
репозитории и ещё одной цепочки поставки через воздушный зазор, а манифесты
остаются теми же файлами, которые читают все гейты этого дерева. Умолчания —
restricted, и второй копии этой позиции нет: values-файла не существует, любое
послабление — отдельный набранный руками `apply`. Единственное, что закрытому
контуру придётся поменять, — реестр образов; для этого есть
`overlays/mirrored-registry`, четыре строки, переносящие установку в тот
реестр, который разрешает `prod-restricted`.

Вне установки по умолчанию остаются трое, и у каждого причина в
`deploy/README`: `deploy/agent` (отдельный корень — его Pod не стартует на узле
без bpffs на `/sys/fs/bpf`), `deploy/agent/optional-respond.yaml` (hostPID и
`CAP_KILL` включаются набранной командой, а не наследуются) и
`validatingwebhookconfiguration.yaml` (появляется только после
`ferrumctl gen-webhook-pki` и применяется последним — с `failurePolicy=Fail`
он начинает отказывать в Pod'ах в момент появления).

Дерево не документ, а вход трёх разных гейтов, и они утверждают разное.
`ferrumctl lint-deploy` проверяет манифесты на инварианты threat model
(приватный ключ в дереве, `caBundle`-заглушка, hostPID без respond,
спроецированный токен под apiserver-watch и прочее).
`crates/ferrum-testkit/tests/deploy_gate.rs` читает текст — какие файлы ставит
какой корень, restricted ли умолчания, — и называется читающим текст, потому
что прошлый цикл показал цену обратного: два CRD из семи проходили здесь всё и
отвергались настоящим apiserver целиком. Про устанавливаемость утверждает
только `crates/ferrum-testkit/tests/install_gate.rs`: он ставит `-k deploy` в
настоящий kind на кластер, который FERRUM не видел, и ждёт, пока workload'ы
поднимутся. Serving PKI выпускается офлайн: `ferrumctl gen-webhook-pki`,
ротация — под тем же CA, которому кластер уже доверяет.

Образы: `Dockerfile`, `Dockerfile.admission`, `Dockerfile.controller`. Собираются
они в каждом билде на ноде локального Jenkins, а публикуются — релизным
воркфлоу по тегу; чем именно и как это проверить, ниже.

## Поставка

Образы едут в `ghcr.io/onixus/` релизным воркфлоу
[.github/workflows/release.yml](.github/workflows/release.yml) — по git-тегу
вида `v0.1.0`, то есть по тому самому тегу, который закрепляют манифесты
`deploy/**`. Три образа, каждый подписан cosign и несёт аттестованный SBOM:

- `ghcr.io/onixus/ferrum-agent`
- `ghcr.io/onixus/ferrum-admission`
- `ghcr.io/onixus/ferrum-controller`

Подпись keyless: ключа нет ни в дереве, ни в секретах репозитория. Fulcio
выписывает сертификат на один запуск под OIDC-токен GitHub, приватная половина
умирает вместе с job, факт подписи уходит в Rekor. Проверяется не «ключ, который
мы вам дали», а идентичность — этот воркфлоу, этот репозиторий, этот тег.

Это **другой домен подписи**, чем у PolicyBundle, и путать их нельзя. Bundle
подписывается Ed25519-seed'ом из Secret, который монтирует контроллер, в
контексте `BUNDLE_SIGNATURE_CONTEXT`; в CI этот ключ не попадает ни в каком
виде, и ни один ключ между доменами не переиспользуется. Проверка подписи образа
не заменяет проверку подписи bundle: первая говорит, откуда взялся бинарь,
вторая — откуда взялась политика, которую он исполняет.

SBOM считается `syft` по **опубликованному образу**, а не по дереву. Образ
собран на `scratch` и несёт один статический бинарь, поэтому список зависимостей
внутри него берётся не из репозитория: бинарь слинкован `cargo-auditable`, и
`.dep-v0` в нём проверяется той же сборкой, которая его кладёт в образ. Тот же
SBOM прикладывается к GitHub Release файлом — но файл рядом с релизом не
доказательство, доказательство здесь аттестация.

### Проверка на стороне получателя

Нужны [cosign](https://github.com/sigstore/cosign) ≥ 3.1, `jq`, и для последнего
шага `cargo install cargo-audit`.

```bash
TAG=v0.1.0
IMAGE=ghcr.io/onixus/ferrum-agent   # то же для ferrum-admission и ferrum-controller
IDENTITY="https://github.com/onixus/Ferrum/.github/workflows/release.yml@refs/tags/$TAG"
ISSUER=https://token.actions.githubusercontent.com
```

**1. Подпись и происхождение.** Команда падает, если образ подписан не этим
воркфлоу, не в этом репозитории, не на этом теге — или не подписан вовсе:

```bash
cosign verify \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" \
    "$IMAGE:$TAG"
```

**2. Digest, который подписан.** Тег переставляется, digest — нет. Подписан
digest, и в кластер надо ставить его, а не тег:

```bash
DIGEST=$(cosign verify \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" \
    "$IMAGE:$TAG" 2>/dev/null \
  | jq -r '.[0].critical.image."docker-manifest-digest"')
echo "$IMAGE@$DIGEST"
```

**3. SBOM.** Аттестация подписана той же идентичностью и прикреплена к digest,
поэтому проверяется, а не принимается на слово:

```bash
cosign verify-attestation --type spdxjson \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$ISSUER" \
    "$IMAGE@$DIGEST" \
  | jq -r '.payload' | base64 -d | jq '.predicate' > sbom.spdx.json
```

**4. Что внутри бинаря — из самого бинаря.** Ответ берётся из артефакта, а не из
репозитория, которому получатель ещё ничего не должен:

```bash
docker create --name ferrum-check "$IMAGE@$DIGEST"
docker cp ferrum-check:/usr/local/bin/ferrum-agent ./ferrum-agent
docker rm ferrum-check
cargo audit bin ./ferrum-agent
```

Расхождение README с тем, что воркфлоу делает на самом деле, — тихий отказ:
инструкция с идентичностью, которой Fulcio не выпишет, не пройдёт ни у кого, и
красным от этого не станет ничего. Поэтому идентичность, издатель, тег и имена
образов сверяются с файлом воркфлоу гейтом
`deploy_gate.rs::the_documented_verification_is_the_one_the_release_performs`, а
сам релиз исполняет команды **1** и **3** на только что подписанном образе,
прежде чем закончить.

**Ни один из этих образов ещё не опубликован.** Воркфлоу на GitHub не запускался
ни разу, в `ghcr.io/onixus/` нет ни одного тега, и ни одна команда выше ещё не
проходила против настоящего опубликованного артефакта. Пока это так, раздел
описывает процедуру, а не свидетельствует о ней; в
[границе](docs/MVP-1-BOUNDARY.md) строки «опубликовано» и «подписано» нет и до
первого настоящего релиза не будет.

### Первый релиз: `v0.1.0`, ещё не выпущенный

Тега `v0.1.0` не существует. Он не проставлен, релиза под ним нет, и всё ниже —
описание того, что этим тегом будет выпущено, а не отчёт о выпуске. Тег ставит
владелец репозитория; ни один воркфлоу и ни один агент этого не делает.

Версия одна на всё дерево: `workspace.package.version = "0.1.0"`, все
восемнадцать crate берут её через `version.workspace = true`, ни один не
объявляет свою. Отсюда и имя тега: `v` + эта версия — ровно та строка, которую
закрепляют `deploy/**` (`ghcr.io/onixus/*:v0.1.0`) и которую пропускает фильтр
триггера `release.yml` (`v[0-9]+.[0-9]+.[0-9]+`). Три конца сведены гейтом
`deploy_gate.rs::the_version_this_workspace_carries_is_the_tag_its_manifests_pin`:
разойтись версии в манифесте, в `Cargo.toml` и в фильтре тега молча не могут.

Что тег произведёт, если воркфлоу отработает:

- три образа в `ghcr.io/onixus/` — `ferrum-agent`, `ferrum-admission`,
  `ferrum-controller`, тегом `v0.1.0`, собранные из `Dockerfile`,
  `Dockerfile.admission`, `Dockerfile.controller`; образ агента несёт
  датапейсный ELF, собранный тем же прогоном;
- подпись cosign на digest каждого — keyless, без ключа в дереве и в секретах;
- SBOM SPDX на каждый образ, посчитанный `syft` по опубликованному образу:
  аттестацией на digest и файлом в GitHub Release.

Что тег **не** произведёт и что в релиз не входит: датапейсные стадии остаются
на локальном Jenkins — публичный CI исполняет только userspace-половину; Helm
chart и kustomize overlay в дереве нет; e2e против настоящего apiserver не
исполнялся, поэтому релиз не является утверждением, что компоненты работают в
живом кластере. Что исполнено, а что нет, — по-прежнему только
[граница](docs/MVP-1-BOUNDARY.md), и релиз ни одной её строки не меняет.

Пока тега нет, `kubectl apply -f deploy/` даёт три `ImagePullBackOff`, и это
корректное поведение дерева, которое ничего не публиковало.

## Документы

- [MVP-1 boundary](docs/MVP-1-BOUNDARY.md) — что исполнено, что нет, что заявлено
- [RFC-02](docs/rfc/FERRUM-RFC-02-architecture.md) — crate-границы, CRD, threat model агента, CIS/MITRE
- [CRD catalog](docs/crd/README.md)
- [SECURITY.md](SECURITY.md) — куда сообщать об уязвимости, окно ответа и что здесь **вне** модели угроз
- [ROADMAP.md](ROADMAP.md) — фазы, критерии закрытия и открытые решения
- [deploy/admission/README](deploy/admission/README), [deploy/agent/README](deploy/agent/README) — установка и ротация

## Лицензия

Apache-2.0 — `LICENSE` в корне, `[workspace.package] license` в `Cargo.toml`.

Выбор сделан владельцем проекта 2026-08-31: дерево было под GPL-3.0-only, и
переход на Apache-2.0 открывает встраивание и OEM ценой отказа от защиты от
проприетарного форка. Ни одна зависимость к этому не принуждала — `deny.toml`
разрешает у зависимостей только пермиссивное, — так что смена не потребовала
ничьего согласия, кроме владельца. Разбор развилки и то, что решение
необратимо, — [ROADMAP.md](ROADMAP.md), раздел «Лицензия».
