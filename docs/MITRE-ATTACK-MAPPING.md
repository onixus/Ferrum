# Политики FERRUM и MITRE ATT&CK (Containers)

Инженерный маппинг для issue #43, 2026-11-04. Основа — матрица MITRE ATT&CK for
Containers: <https://attack.mitre.org/matrices/containers/>. Это анализ вклада
компонентов в ограничение перечисленных техник, а не заключение о «покрытии»
матрицы и не сертификация. FERRUM не EDR и не CNAPP; он исполняет подписанную
политику на admission и в runtime-плоскости узла.

Формат продолжает [RFC-02 §D](rfc/FERRUM-RFC-02-architecture.md#d-покрытие-mvp):
техника → механизм → граница. Слова «частично» ниже означают сопоставление
функций, а не полное ограничение техники. Доказательства исполнения и
конкретные стенды перечислены только в [границе MVP](MVP-1-BOUNDARY.md);
машинночитаемая форма этого маппинга —
[mitre-attack-mapping.yaml](../policies/mapping/mitre-attack-mapping.yaml),
её кросс-проверка живёт в `crates/ferrum-cli/src/validate.rs`
(`mitre_mapping_*`).

| Техника | Название | Плоскость / механизм FERRUM | Ограничение маппинга |
|---|---|---|---|
| T1610 | Deploy Container | `supply.requireSigned`/`denyUnsigned` + `selector.image.requireDigest` и `admit.deny.privileged` / `addedCapabilities` / `runAsRoot` (см. [prod-restricted](../policies/examples/prod-restricted.yaml)) | Ограничивает *что* может быть принято как Pod, а не сам факт деплоя через kubectl/API; CI/CD pipeline и доступ к kubeconfig вне зоны действия |
| T1609 · T1059 | Container Administration Command; Command and Scripting Interpreter | приёмочный случай §D «kubectl exec + /bin/sh → kill»: `runtime.rules.no-shell` (`commIn: sh/bash/ash/dash/zsh`, `containerOnly`) с действием `kill` — одно правило закрывает оба вектора | Реакция постфактум: tracepoint `execve` срабатывает после запуска процесса, SIGKILL догоняет его, не предотвращает первые инструкции; окно REFUSE_NOT_CONTAINER при ещё не опубликованном cgroup названо в границе; только контейнеры (`containerOnly`); предикат по `comm` — целое имя, поэтому `python -c 'os.system(...)'` правило не ловит |
| T1611 | Escape to Host | `runtime.rules.no-runtime-sock` (`pathSuffix: docker.sock/containerd.sock/crio.sock`, `containerOnly`, `kill`) + `admit.deny.hostPath` | Маппинг на *вектор* (доступ к runtime-сокету из контейнера), не на технику целиком: детект открытия сокета — `openat` на трейспойнтном пути, kill после факта; ядру от exec-половина правила (запуск файла с таким именем), см. строку гейта в границе; ядерные CVE-векторы эскейпа не закрываются |
| T1611 · T1059.005 | Load Kernel Module (строка §D «bpf() not from the agent -> deny») | `runtime.rules.no-module` (`init_module`/`finit_module`/`bpf`, `notAgentSelf`) — **audit**; блокирующая половина — `admit.deny.addedCapabilities: SYS_MODULE` и `privileged` | Runtime-плоскость не может отменить уже вернувшийся syscall, поэтому здесь честный audit с именем вызывающего, а не deny; `ferrum-policy` такую политику в deny не компилирует (см. границу, раздел про bpf()) |
| T1525 | Insert Host Executable into Container | `admit.deny.hostPath` + `mutate.readOnlyRootFilesystem` на admission | Поле mutate само не доказывает мутацию API-запроса (см. [FSTEC-118-MAPPING](FSTEC-118-MAPPING.md), п. 11); контроль последующей записи внутрь работающего контейнера вне этого маппинга |

Вне MVP-1 и сознательно не маппятся: T1190 (WAF), облачный IAM, CIS 1.x/4.x —
см. RFC-02 §D.

Точки проверки в дереве:

- [prod-restricted](../policies/examples/prod-restricted.yaml) — имена правил и полей, на которые ссылается таблица;
- [migrating манифест](../policies/mapping/mitre-attack-mapping.yaml) — versioned (`schemaVersion: 1`), каждая запись обязана ссылаться на существующий `id` правила или путь поля политики из примера;
- `crates/ferrum-cli/src/validate.rs` — `cargo test -p ferrum-cli mitre` гоняет кросс-валидацию манифеста против настоящего дерева политик;
- [MVP-1-BOUNDARY](MVP-1-BOUNDARY.md) — единственный источник того, что исполнено и на каком стенде; этот документ ничего не добавляет к доказательствам.

Подставлять вместо перечисленных ограничений слова «соответствует ATT&CK»
нельзя: маппинг показывает вклад механизма, а границы оставляют обязанность
владельцу среды.
