# FERRUM MVP-1 — граница

Что MVP-1 делает, чего он не делает и что про него верят без доказательства.
Три колонки, четвёртой нет.

**Правило.** В «Делает» не попадает ничего, что не было *исполнено* чем-то
названным. Не «реализовано», не «покрыто», не «считаем корректным» —
исполнено, конкретным `#[test]` или конкретной стадией Jenkins, существующей
в этом дереве. Формулировка «покрыто приёмочным набором» — это дефект цикла 8
на уровень выше: там тест, написанный чтобы *закрыть* fail-open, начал его
*утверждать*, потому что разделял с ним ложную посылку. Документ без теста —
тот же дефект без теста вообще.

Держит это `crates/ferrum-testkit/tests/boundary_gate.rs`: он разбирает
таблицы секции «Делает», требует, чтобы каждая ссылка разрешалась в `fn` под
`crates/` или в `stage('...')` в `Jenkinsfile`, требует, чтобы список случаев
§D был ровно `AcceptanceCase::ALL`, и требует, чтобы каждая константа `DEG_*`
из `ferrum-agent` была здесь названа. Переименованный тест роняет строку,
которая на него опиралась.

## Как читать колонку «Исполняется»

Ячейка — либо `—`, либо цепочка ссылок через `·`, каждая вида
`<метка> `<файл>::<имя>``:

- `K` — исполнено на настоящем ядре (стадия `BPF attach`, Linux 6.18.44, x86_64);
- `U` — исполнено в userspace; приёмочные строки — против настоящего подписанного bundle, стадии CI — против дерева, которое поставляется;
- `—` — не исполнено ничем.

Колонка «Метка» — множество меток строки, отсортированное и слитое через `+`.
Слова «частично доказано» здесь нет намеренно: это честное слово, и это ровно
то слово, которое статус-встреча слышит как «доказано». `K+U` заставляет
посмотреть, что именно каким было.

Грамматика ячейки закрыта: проза в ней не разбирается и роняет гейт. Это
единственный fail-open, который у такого документа есть.

## Делает

### Приёмка RFC §D

| Случай §D | Плоскость | Метка | Исполняется |
|---|---|---|---|
| unsigned image -> deny | admission | U | U `acceptance.rs::unsigned_image_is_denied` |
| privileged -> deny | admission | U | U `acceptance.rs::privileged_pod_is_denied` |
| cluster-admin bind -> deny | admission | U | U `acceptance.rs::cluster_admin_bind_is_denied` |
| exception without TTL -> API reject | admission | — | — |
| kubectl exec + /bin/sh -> kill | runtime | K+U | U `acceptance.rs::exec_shell_in_container_is_killed` · U `replay.rs::replay_exec_shell_kill` · K `attach_live.rs::execve_path_comes_from_the_first_argument_slot` |
| docker.sock -> kill | runtime | K+U | U `acceptance.rs::docker_sock_access_is_killed` · U `replay.rs::replay_docker_sock_kill` · K `attach_live.rs::a_long_path_arrives_as_a_flagged_head` |
| bpf() not from the agent -> deny | runtime | K+U | U `acceptance.rs::bpf_not_from_agent_is_denied` · U `replay.rs::replay_bpf_not_from_agent_deny` · K `attach_live.rs::a_foreign_record_is_not_flagged_agent_self` |
| CP down -> last-known-good | runtime | U | U `acceptance.rs::cp_down_keeps_last_known_good_not_fail_open` |

Что эти строки не говорят, и это важнее того, что они говорят:

- **Три runtime-случая имеют по три ссылки, и эти три никогда не встречались в
  одном процессе.** `K` — производство записи ядром: аргумент, флаг усечения,
  дискриминация «свой/чужой». `U` — решение по уже собранным байтам и по
  подписанному bundle. Провода между ними в этих строках нет, и **ни одного
  `SIGKILL` не было отправлено ни разу**: `Responder` в приёмке — тестовая
  реализация, считающая вызовы. Стык «запись из ядра → подписанный bundle →
  настоящий `SIGKILL`» строит слайс B этого цикла; до его коммита он живёт
  ниже, в «Верим, но не доказано».
- **`exception without TTL` стоит `—` намеренно.** Субъект утверждения —
  API server, а API server здесь не запускался ни разу. `serde` отказывается
  декодировать объект без `expiresAt`, и CRD в дереве несёт `required` и CEL —
  это исполнено (см. следующую таблицу), но отказ библиотеки не есть отказ
  apiserver.
- **`CP down` — это `mark_control_plane_down()`.** Ни один control plane не
  падал. Проверено, что при этом состоянии подделанный FSIG не подменяет
  last-known-good, снапшот переживает рестарт с диска и `execve` `/bin/sh`
  по-прежнему `Kill`. Не проверено, что агент дойдёт до этого состояния сам.
- **`bpf() -> deny` исполняет deny только admission.** Runtime-плоскость
  пишет audit-запись с именем вызывающего: tracepoint срабатывает после того,
  как syscall уже вернулся, и runtime `deny` был бы вердиктом, который
  решается и не исполняется. `ferrum-policy` такую политику не компилирует.

### Остальное, что исполнено

| Утверждение | Метка | Исполняется |
|---|---|---|
| Подписанный bundle: FSIG-кодек в четырёх копиях (controller, agent, admission, CLI) сходится на одних байтах | U | U `acceptance.rs::controller_signed_exceptions_are_accepted_by_agent_and_admission` |
| С mount принимаются только подписанные exception | U | U `acceptance.rs::only_signed_exceptions_are_accepted_from_the_mount` |
| Exception бьёт deny только в своём scope и до `expiresAt` | U | U `acceptance.rs::docker_sock_kill_is_waived_only_in_scope` · U `acceptance.rs::exception_without_ttl_is_rejected_and_scoped_exception_waives` |
| CRD требует `expiresAt` и держит потолок 90 дней — в схеме и в `ferrum-policy` | U | U `deploy_gate.rs::exception_expires_at_is_mandatory_in_cel_and_in_decode` · U `deploy_gate.rs::exception_ttl_ceiling_is_ninety_days_in_cel_and_in_policy` |
| Kill/Isolate без match отвергается схемой и политикой (это kill-all) | U | U `deploy_gate.rs::kill_without_match_is_rejected_in_cel_and_in_policy` |
| Namespaced policy не может `failurePolicy=Ignore` | U | U `deploy_gate.rs::namespaced_policy_cannot_ignore_in_cel_and_in_policy` |
| Правило, называющее syscall, которого datapath не цепляет, не валидируется | U | U `deploy_gate.rs::a_rule_naming_an_unhooked_syscall_does_not_validate` · U `Jenkinsfile::Validate policies` |
| Действие, которого runtime-плоскость не исполняет, не валидируется — и в схеме тоже | U | U `deploy_gate.rs::a_rule_whose_action_the_runtime_plane_cannot_execute_does_not_validate` · U `deploy_gate.rs::every_runtime_action_ferrum_policy_refuses_is_refused_by_the_cel_copy` |
| Половина пары open/openat — мёртвое или обходимое правило, и оно отвергается | U | U `Jenkinsfile::Validate policies` |
| `lint-deploy` проходит на поставляемом дереве, и плохие фикстуры падают | U | U `Jenkinsfile::Validate policies` |
| `gen-webhook-pki` выпускает PKI офлайн и отказывается перезаписать выпущенное | U | U `Jenkinsfile::Validate policies` |
| BPF ELF несёт все программы, карты и счётчики, которые связывает loader | U | U `Jenkinsfile::BPF ELF` |
| Datapath в настоящем ядре: одна декодируемая запись на syscall, путь из первого слота, нечитаемый указатель помечен пустым буфером | K | K `attach_live.rs::openat_produces_one_decodable_record` · K `attach_live.rs::a_syscall_without_a_path_argument_is_not_flagged` · K `attach_live.rs::unreadable_path_pointer_is_flagged_with_an_empty_buffer` |
| Карта `ferrum_cgroups` живёт на настоящем handle | K | K `attach_live.rs::cgroup_map_round_trips_on_a_live_handle` |
| Единственная стадия, трогающая ядро, не может пройти, не исполнившись | K+U | K `attach_live.rs::the_gate_must_not_be_compiled_out` · U `Jenkinsfile::BPF attach` |
| `rcgen` и `x509-parser` не попадают в графы admission и agent, и детектор доказан на `ferrum-cli` | U | U `Jenkinsfile::Crate boundary` |
| Оба arch дают один вердикт на одних логических событиях, из записанных байтов | U | U `replay.rs::both_arches_reach_the_same_verdicts_on_the_same_logical_events` · U `replay.rs::recorded_fixture_records_still_produce_the_acceptance_verdicts` |
| Prefilter-образ поставляемой политики — тот, который утверждает ручная копия в `ferrum-ebpf` | U | U `deploy_gate.rs::the_prefilter_image_of_the_shipped_policy_is_the_one_its_unit_test_asserts` |
| `status.json` пишется целиком, переживает сбой записи и не держит замок на агенте | U | U `ferrum-agent/src/lib.rs::the_poll_tick_publishes_a_whole_status_file_and_logs_transitions` · U `ferrum-agent/src/lib.rs::a_failed_status_write_removes_the_file_rather_than_leave_it_lying` · U `ferrum-agent/src/lib.rs::the_status_write_holds_no_lock_on_the_shared_agent` |

### Сигналы деградации

Каждая причина, по которой узел объявляет себя Degraded. `is_degraded()` —
это ровно непустота этого списка: сигнал, которого здесь нет, деградировать
узел не может. Ни один из них не заведён на probe: все они либо
восстановимые, либо терминальные, а liveness-probe рестартует на обоих.

| Сигнал | Метка | Исполняется |
|---|---|---|
| `DEG_CONTROL_PLANE_DOWN` — CP недоступен, работает last-known-good | U | U `acceptance.rs::cp_down_keeps_last_known_good_not_fail_open` |
| `DEG_LOADER` — bundle не загружен, ABI или подпись | U | U `ferrum-agent/src/lib.rs::abi_too_new_is_degraded` |
| `DEG_NOT_ATTACHED` — attach не живой, решающий путь ничем не питается | U | U `ferrum-agent/src/lib.rs::attach_pins_does_not_pretend` |
| `DEG_DATAPATH` — datapath, чью каждую запись отвергают | U | U `ferrum-agent/src/lib.rs::a_datapath_whose_every_record_is_refused_is_degraded_without_more_traffic` |
| `DEG_CGROUP_INDEX_EMPTY` — пустой индекс cgroup: каждый namespaced-селектор молча не матчится | U | U `ferrum-agent/src/lib.rs::an_empty_cgroup_index_is_degraded` |
| `DEG_CONTAINER_MAP` — cgroup не доехали в `ferrum_cgroups`, и `containerOnly` не матчится | U | U `ferrum-agent/src/lib.rs::an_unsynced_container_map_is_degraded` |
| `DEG_EXPORT_DEAD` — writer мёртв: enforcement идёт и не записывается | U | U `ferrum-agent/src/lib.rs::a_dead_export_writer_degrades_the_agent` |
| `DEG_EXPORT_LOSSY` — экспорт терял события: kill мог не оставить записи | U | U `ferrum-agent/src/lib.rs::a_lossy_export_degrades_and_then_recovers` |
| `DEG_DECODE_FAILURES` — записи не декодировались: их не видело ни одно правило | U | U `ferrum-agent/src/lib.rs::a_run_of_records_that_all_fail_to_decode_is_degraded_without_more_traffic` |
| `DEG_LABELS_UNKNOWN` — неразрешённые label: правила применены fail-closed | U | U `ferrum-agent/src/lib.rs::unobserved_namespace_labels_do_not_skip_a_rule` |
| `DEG_RING_DROPS` — дропы в ядре: записи, которых не видело ни одно правило | U | U `ferrum-agent/src/lib.rs::ring_drops_degrade_and_then_recover` |
| `DEG_PATH_TRUNCATED` — путь не поместился: suffix-правило решено без байтов, которые называет | K+U | U `ferrum-agent/src/lib.rs::path_truncation_degrades_and_then_recovers` · U `replay.rs::a_truncated_docker_sock_path_still_kills_and_degrades` · K `attach_live.rs::a_long_path_arrives_as_a_flagged_head` |
| `DEG_IDENTITY_UNKNOWN` — cgroup, которую индекс не может назвать | U | U `replay.rs::a_cgroup_missing_from_the_index_is_counted_and_degrades` |
| `DEG_LKG_PARTIAL` — узел энфорсит меньше, чем восстановленный подписанный снапшот | U | U `ferrum-agent/src/lib.rs::lkg_restore_drops_an_unmatchable_rule_instead_of_the_whole_snapshot` |
| `DEG_CONTAINER_FLAG` — флаг контейнера расходится с индексом дольше окна старта пода | U | U `ferrum-agent/src/lib.rs::the_pod_start_window_does_not_latch_degraded` |
| `DEG_STATUS_UNWRITABLE` — сама поверхность отчётности лежит | U | U `ferrum-agent/src/lib.rs::an_unwritable_status_dir_does_not_stop_the_tick` · U `ferrum-agent/src/lib.rs::a_failed_status_write_removes_the_file_rather_than_leave_it_lying` |

`DEG_STATUS_UNWRITABLE` по устройству отстаёт на один тик: запись, которая
не удалась, не может нести запись о собственном провале. Первый провалившийся
тик всё ещё оставляет `degraded=false` на конвертах.

## Не делает

Плоские утверждения. Каждое проверено по дереву на этом коммите.

- **Этот репозиторий не собирает ни одного образа контейнера.** `Dockerfile`
  нет. `deploy/**` ссылается на `ghcr.io/ferrum/*:v0.1.0`, которых никто не
  публиковал.
- **Продуктовая комбинация фич `attach,apiserver` ни разу не линковалась.**
  В `Jenkinsfile` она встречается только на строке clippy, которая
  check-only (`.rmeta`), и в `cargo tree` стадии `Crate boundary`. Бинаря с
  этой комбинацией не существовало.
- **Поставляемый DaemonSet не монтирует tracefs.** `deploy/agent/daemonset.yaml`
  монтирует `/sys/fs/bpf/ferrum`, `/sys/fs/cgroup`, `/var/log/ferrum`,
  `/var/lib/ferrum/lkg` и bundle — и всё. Без `/sys/kernel/tracing` на нём
  падает каждый attach tracepoint, и агент паркуется Degraded с
  `DEG_NOT_ATTACHED`. Лимит memlock тоже не поднимается.
- **Ничего никогда не пинится.** `Loader::attach_pins` возвращает `Degraded`
  по построению. **Строка Tampering из RFC-02 §C отсутствует целиком, а не
  частично**: нет pin, нет LSM на pin path, нет self-watch вне процесса. Это
  единственный класс threat model, у которого нет ни одной контрмеры.
- **У `FerrumClusterStatus.degraded` нет ни одного писателя во всём
  workspace**, при том что `deploy/controller/rbac.yaml` выдаёт права на
  `ferrumclusters` и `ferrumclusters/status` — API, к которому никто не
  обращается.
- **`.status.rollout` на любой настоящей установке навсегда сообщает
  `clustersReady: 0`**: `deploy/controller/deployment.yaml` не передаёт
  `--cluster`, и `plan_rollout` всегда получает пустой срез. `deliver` и
  `keep_lkg` вычисляются и не читаются никем, кроме тестов.
- **`MAP_RULES` называет карту, которую не объявляет ни одна программа.**
  `ferrum_rules` есть в константах и в тестах и нет в ELF.
- **У `ferrum-wasm-host` нет ни одной точки вызова в workspace**, при том что
  `ferrum-agent` держит его в зависимостях, а 9-байтовый placeholder-модуль
  входит в дайджест каждого подписанного bundle.
- **In-kernel prefilter инертен и поставляемую политику сузить не может.**
  Ничто не вызывает `prefilter_image` из агента; карты нет. Даже если бы
  была: флаги образа требуют, чтобы признак несло *каждое* правило, а
  `defaultAction: audit` сам по себе ставит полную маску syscall.
- **`aarch64` и ветка «tracefs нет вообще» покрыты только unit-тестами.**
  Каждое измерение на ядре в этом репозитории — x86_64.
- **Ничто и никогда не обращалось к API server.** Ни webhook под нагрузкой
  admission, ни watch, ни запись status.

## Верим, но не доказано

Механизм, который это закроет, назван для каждого. Для тех, которые останутся
незакрытыми, назван регистр цикла 8: *заявлено, не закрыто*.

| Утверждение | Чем закрывается | Статус |
|---|---|---|
| Запись из ядра доходит до правила из подписанного bundle и приводит к настоящему `SIGKILL` | Стык в одном процессе: `attach_live` → `Agent::handle_event` → `Responder` с `CAP_KILL`; плюс закоммиченные mutation-артефакты | Строит слайс B этого цикла. Промоутит свои строки своим коммитом |
| Образ собирается, продуктовые фичи линкуются, DaemonSet монтирует tracefs и поднимает memlock | `Dockerfile`, стадия продуктовой сборки, правка `deploy/agent/daemonset.yaml` | Строит слайс A этого цикла. Промоутит свои строки своим коммитом |
| API server отвергает `PolicyException` без `expiresAt` | envtest или kind с применённым CRD: применить объект и потребовать отказ | Не начато. Ближайшее исполненное — `deploy_gate.rs::exception_expires_at_is_mandatory_in_cel_and_in_decode`: он читает CRD из дерева, а не ответ apiserver |
| Агент сам обнаруживает падение CP и переходит на last-known-good | Тест на watch-клиент с оборванным соединением, не `mark_control_plane_down()` | Не начато |
| `--policy-name` действительно джойнит waiver с политикой | Имя политики в FRMB — смена формата, бамп ABI и bundle, который откажется грузить каждый развёрнутый агент | **Заявлено, не закрыто.** Агент объявляет себя Degraded, если держит waiver, ни один из которых не называет его политику, а FD024 проверяет развёрнутые объекты. Джойн в рантайме остаётся недоказанным |
| `parse_flags` в `ferrum-agent` и `ferrum-admission` — одна и та же функция, а читатель в `lint_deploy` читает то же самое | Поднять в `ferrum-common` и оставить одну копию | **Заявлено, не закрыто.** Функция троирована: две копии дословные, третья повторяет их doc-комментарием и табличным тестом, механической связи нет. Архитектор оценил, что подъём в `ferrum-common` стоит зависимости в графе каждого crate ради связи, которую FD025 и так делает видимой как находку лита раньше |
| Пинов нет — и это заметно тому, кто снимет enforcement | LSM на pin path и self-watch вне процесса (RFC-02 §C, Tampering) | Не начато. Строка threat model закрыта нулём контрмер, и ни один сигнал `DEG_*` этого не назовёт |
| `status.json` кто-то читает | Scrape config или acceptance-прогон, который делает `cat` | Файл — контракт, читателя в дереве нет |
| Поведение на `aarch64` совпадает с измеренным на x86_64 | Стадия `BPF attach` на arm64-раннере | Не начато. Реплей обоих arch идёт из записанных байтов, не из ядра |

## Что этот документ не гарантирует

Гейт проверяет, что процитированный `fn` существует, — не то, что он
утверждает написанное в строке, и не то, что он вообще `#[test]`. Метка
`K`/`U` — слово автора о том, где тест исполнялся. Ни то, ни другое grep не
закрывает, и делать вид, что закрывает, было бы тем же дефектом этого
проекта уровнем выше.
