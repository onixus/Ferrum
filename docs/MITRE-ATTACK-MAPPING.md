# Политики FERRUM и MITRE ATT&CK (Containers)

Инженерный маппинг для issue #43, 2026-11-04. Основа — матрица MITRE ATT&CK for
Containers: <https://attack.mitre.org/matrices/containers/>. Это анализ вклада
компонентов в ограничение перечисленных техник, а не заключение о «покрытии»
матрицы и не сертификация. FERRUM не EDR и не CNAPP; он исполняет подписанную
политику на admission и в runtime-плоскости узла.

Формат продолжает [RFC-02 §D](rfc/FERRUM-RFC-02-architecture.md#d-покрытие-mvp):
техника → механизм → граница. Доказательства исполнения и конкретные стенды
перечислены только в [границе MVP](MVP-1-BOUNDARY.md). Машинночитаемая форма —
[mitre-attack-mapping.yaml](../policies/mapping/mitre-attack-mapping.yaml).
`ferrumctl validate` отвергает её, если `name` не совпадает с официальным
именем техники или `effect` не совпадает с тем, что
[prod-restricted](../policies/examples/prod-restricted.yaml) реально делает.
У этого примера `spec.mode` равен `audit`: admission запрос не отклоняет и
патчи не шлёт, а runtime `kill` понижается до audit.

| Техника | Название | Что делает prod-restricted | Ограничение маппинга |
|---|---|---|---|
| T1609 · T1059 | Container Administration Command; Command and Scripting Interpreter | `runtime.rules.no-shell` (`commIn: sh/bash/ash/dash/zsh`, `containerOnly`). В файле `action: kill`, эффективное действие при `mode: audit` — audit | Записанный kill не исполняется. Окно REFUSE_NOT_CONTAINER при ещё не опубликованном cgroup названо в границе. Предикат по `comm` — целое имя, поэтому `python -c` правило не ловит |
| T1611 | Escape to Host | `runtime.rules.no-runtime-sock` (в файле `kill`, эффективно audit) и `runtime.rules.no-module` (`init_module`/`finit_module`/`bpf`, `notAgentSelf`, `action: audit`) | Это не deny и не «bpf() → deny». `no-module` аудирует уже вернувшийся syscall. `admit.deny.hostPath`, `addedCapabilities` и `privileged` в этом файле заданы, но при `mode: audit` admission их не применяет |

Не маппится этим примером, потому что заявленный эффект политика не исполняет:

| Техника | Официальное имя | Почему строки нет |
|---|---|---|
| T1610 | Deploy Container | `supply.requireSigned` / `denyUnsigned` и `selector.image.requireDigest` в файле есть. При `mode: audit` admission Pod не отклоняет, так что это не ограничение деплоя |
| T1525 | Implant Internal Image | Ни `hostPath`, ни `readOnlyRootFilesystem` не про имплант во внутреннем registry. Оба поля к тому же не применяются, пока mode не enforce |
| T1059.005 | Visual Basic | Это не загрузка модуля ядра и не `bpf()`. Правило `no-module` стоит в строке T1611 и только аудирует |

Вне MVP-1 и сознательно не маппятся: T1190 (WAF), облачный IAM, CIS 1.x/4.x —
см. RFC-02 §D.

Точки проверки в дереве:

- [prod-restricted](../policies/examples/prod-restricted.yaml) — политика, против которой считается `effect`;
- [манифест](../policies/mapping/mitre-attack-mapping.yaml) — `schemaVersion: 1`, официальное имя техники, `effect` равен эффективному действию;
- `crates/ferrum-cli/src/validate.rs` — `cargo test -p ferrum-cli mitre`;
- [MVP-1-BOUNDARY](MVP-1-BOUNDARY.md) — единственный источник того, что исполнено и на каком стенде; этот документ ничего не добавляет к доказательствам.

Подставлять вместо перечисленных ограничений слова «соответствует ATT&CK»
нельзя: маппинг показывает вклад механизма, а границы оставляют обязанность
владельцу среды.
