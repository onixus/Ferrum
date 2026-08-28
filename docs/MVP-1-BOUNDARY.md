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

**Гейт проверяет только одно направление.** Он требует, чтобы процитированное
существовало; он не требует, чтобы существующее было процитировано. Это ровно
то направление, в котором документ гниёт молча: слайс, который что-то доказал
и не переписал свою строку, оставляет документ *занижающим* дерево, и ни одна
сборка от этого не покраснеет. Цикл 9 наступил на это дважды — два слайса
закрыли то, что здесь стояло в «Верим, но не доказано», и строки остались
лежать. Единственный читатель этого направления — человек с `git log`, и он
обязан быть таким же подозрительным к занижению, как к завышению: документ,
который врёт в меньшую сторону, учит не верить документу.

## Как читать колонку «Исполняется»

Ячейка — либо `—`, либо цепочка ссылок через `·`, каждая вида
`<метка> `<файл>::<имя>``:

- `K` — исполнено на настоящем ядре (стадии `BPF attach` и `BPF join`, Linux 6.18.44, x86_64);
- `U` — исполнено в userspace; приёмочные строки — против настоящего подписанного bundle, стадии CI — против дерева, которое поставляется;
- `—` — не исполнено ничем.

`K` наследует свой единственный стенд, и это не мелочь: один хост, Linux
6.18.44, x86_64, Firecracker microVM, собранный без `CONFIG_MODULES` — там нет
ни `init_module`, ни `finit_module`, ни tracepoint для них, и attach честно
сообщает их незацепленными вместо того, чтобы цепляться. Всё, что здесь стоит
`K`, измерено там и больше нигде.

Ссылка `Jenkinsfile::<стадия>` утверждает ровно одно: стадия с таким именем
есть в поставляемом `Jenkinsfile`. Это единственное, что проверяет гейт, и
это меньше, чем читается. Она **не** утверждает, что стадию исполнял Jenkins:
ни один Jenkins этот файл не запускал ни разу. `U` на такой строке — слово
автора о том, что команды стадии были прогнаны руками на этом дереве. Поэтому
`Agent image` в «Делает» не цитируется нигде: её собственная команда —
`docker build`, а демона здесь нет, и она не исполнялась ни Jenkins, ни руками.

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
| kubectl exec + /bin/sh -> kill | runtime | K+U | U `acceptance.rs::exec_shell_in_container_is_killed` · U `replay.rs::replay_exec_shell_kill` · K `attach_live.rs::execve_path_comes_from_the_first_argument_slot` · K `attach_join.rs::a_kernel_execve_of_a_shell_is_killed_by_the_signed_bundle` |
| docker.sock -> kill | runtime | K+U | U `acceptance.rs::docker_sock_access_is_killed` · U `replay.rs::replay_docker_sock_kill` · K `attach_live.rs::a_long_path_arrives_as_a_flagged_head` · K `attach_join.rs::a_kernel_openat_of_docker_sock_is_killed_by_the_signed_bundle` · K `attach_join.rs::a_truncated_docker_sock_path_still_kills_and_says_the_match_was_asserted` |
| bpf() not from the agent -> deny | runtime | K+U | U `acceptance.rs::bpf_not_from_agent_is_denied` · U `replay.rs::replay_bpf_not_from_agent_deny` · K `attach_live.rs::a_foreign_record_is_not_flagged_agent_self` |
| CP down -> last-known-good | runtime | U | U `acceptance.rs::cp_down_keeps_last_known_good_not_fail_open` |

Что эти строки не говорят, и это важнее того, что они говорят:

- **Два из трёх runtime-случаев стык прошли, третий не пройдёт никогда.**
  `attach_join.rs` берёт запись, которую **это ядро** положило в
  `ferrum_events`, сливает её `RingReader`'ом как байты (ни одного
  сконструированного `SyscallEvent` в файле нет), решает против
  скомпилированного и FSIG-подписанного `prod_restricted()` и убивает
  форкнутый probe настоящим `SIGKILL` — подтверждённым не словом агента
  (`executed=true`), а `waitpid`: `WIFSIGNALED` и `WTERMSIG == SIGKILL`. До
  цикла 9 здесь стояло, что три ссылки строки не встречались в одном процессе
  и что ни одного `SIGKILL` не было отправлено ни разу; оба утверждения теперь
  ложны, и `SignalResponder::kill` — единственный `unsafe` вызов агента —
  впервые вернул `Ok`, потому что syscall прошёл. Что **не** изменилось:
  `acceptance.rs` и `replay.rs` по-прежнему считают вызовы фейковым
  `Responder`. Стык доказан отдельным файлом, а не ими, и вклад каждой ссылки
  надо читать по отдельности.
- **Стык проверяет и отказ.** Probe, ушедший из cgroup, которая породила
  запись, сигнала не получает: `REFUSE_STALE_TARGET`, `respond_kill_total()`
  ноль, probe жив. `ProcCgroupCheck` там настоящий и читает настоящий `/proc`
  — это разница между «убить workload» и «убить того, кто унаследовал его
  pid».
- **Набор измерен, а не только код.** `crates/ferrum-agent/tests/mutations/`
  — четыре патча и `run.sh`, каждый обязан уронить стык. Три роняют: `react`,
  сообщающий `executed` без сигнала (внутри агента этого не видит ничто —
  экспорт и счётчики совпадают со здоровым узлом); `SignalResponder::kill`,
  возвращающий `Ok` без syscall — при этом **все unit-тесты `respond.rs`
  продолжают проходить**, что и есть замеренная дыра; снятый guard устаревшей
  цели — падает ровно четвёртый тест и только он.
- **Четвёртая мутация выжила намеренно, и это результат, а не стыд.**
  `04-emit-never-flags-a-truncated-path` стык не роняет: вывод усечения из
  байтов на стороне декодера, сделанный в цикле 8 ради уже развёрнутых
  pre-fix ELF, покрывает пропавший флаг полностью — kill на переросшем
  `PATH_LEN` пути всё ещё срабатывает, всё ещё помечается `path_unknown`, и
  probe всё ещё умирает. Ловит регрессию единственное утверждение, читающее
  сырой флаг записи, и оно в файле ровно за этим: молчаливый fallback — это
  дефект, ждущий следующего производителя, у которого fallback нет.
  Ни один из четырёх прогонов Jenkins не делал: стадии `BPF join` и
  `BPF join mutations` существуют, а прогонялись руками.
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
| Цель, покинувшая cgroup, которая породила запись, сигнала не получает: `REFUSE_STALE_TARGET`, probe жив | K | K `attach_join.rs::a_target_that_left_the_cgroup_is_refused_and_survives` |
| Ни стадия, трогающая ядро, ни стадия стыка не могут пройти, не исполнившись | K+U | K `attach_live.rs::the_gate_must_not_be_compiled_out` · U `Jenkinsfile::BPF attach` · U `attach_join.rs::the_gate_must_not_be_compiled_out` · U `Jenkinsfile::BPF join` |
| Продуктовая комбинация `attach,apiserver` линкуется под musl и не несёт program interpreter | U | U `Jenkinsfile::Agent binary` |
| Оба поставляемых DaemonSet монтируют tracefs, и attach-манифест без него — находка FD026, а не предупреждение | U | U `lint_deploy.rs::an_attach_build_without_tracefs_is_a_finding` · U `lint_deploy.rs::an_emptydir_where_tracefs_belongs_is_still_a_finding` · U `lint_deploy.rs::the_tracefs_fixture_fails_on_that_rule_and_no_other` |
| Манифест, называющий корень доверия дважды, — находка, а не молчаливое last-wins | U | U `lint_deploy.rs::a_trust_root_named_twice_is_a_finding` |
| Soft `RLIMIT_MEMLOCK` поднимается до hard внутри самого `Bpf::load`, лимита не понижает и сообщает числа, а не вердикт | K+U | K `kernel.rs::raise_memlock_never_lowers_the_limit_and_reports_what_it_left` · U `kernel.rs::memlock_describe_reports_the_numbers_not_a_verdict` |
| `libc` есть в графе `ferrum-ebpf` только под `attach`, и детектор доказан в обе стороны | U | U `Jenkinsfile::Crate boundary` |
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

- **Ни одного образа контейнера здесь не собиралось.** `Dockerfile` и стадия
  `Agent image` теперь есть, но `docker build` не запускался ни разу: демона
  в этом контейнере нет, а достать его снаружи означало бы смонтировать
  `/var/run/docker.sock` — тот самый hostPath, на который FD006 даёт находку,
  а runtime-правила убивают. Каждая команда *внутри* `Dockerfile` прогонялась
  руками по отдельности; «образ собирается» — не то утверждение, которое это
  дерево может сделать. `deploy/**` по-прежнему ссылается на
  `ghcr.io/ferrum/*:v0.1.0`, которых никто не публиковал.
- **`ProcCgroupCheck::new()` зашивает корень cgroup2.** На гибридном узле
  (cgroup2 в `/sys/fs/cgroup/unified` — как здесь) inode не сойдётся ни разу,
  и **каждая** реакция откажет как по устаревшей цели, при том что
  `is_degraded()` останется `false`: `REFUSE_STALE_TARGET` — не сигнал
  деградации, потому что в здоровом случае он и есть правильное поведение.
  Узел молча не энфорсит и способа это заметить у агента нет.
  `attach_join.rs` читает точку монтирования из `mountinfo`; продакшн — нет.
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
  Каждое измерение на ядре в этом репозитории — x86_64, на одном хосте, в
  Firecracker microVM без `CONFIG_MODULES`: `init_module` и `finit_module`
  там сообщаются незацепленными, потому что tracepoint для них не существует,
  а не потому, что attach проверен и отказал. Второго ядра здесь не было.
- **Ничто и никогда не обращалось к API server.** Ни webhook под нагрузкой
  admission, ни watch, ни запись status.

## Верим, но не доказано

Механизм, который это закроет, назван для каждого. Для тех, которые останутся
незакрытыми, назван регистр цикла 8: *заявлено, не закрыто*.

| Утверждение | Чем закрывается | Статус |
|---|---|---|
| Образ действительно собирается из этого `Dockerfile` | `docker build` с настоящим демоном — то есть стадия `Agent image` на узле | Не исполнено. `Dockerfile` и стадия есть, команды внутри `Dockerfile` прогонялись руками поштучно, сам `docker build` — ни разу |
| Собранный продуктовый бинарь аттачится на узле, а не только линкуется | Стадия, которая запускает слинкованный musl-бинарь и читает его `status.json` | В слайсе A это делали руками: бинарь написал `"attached": true`, а на испорченной релокации — причину в `containerMapError` и `degradedReasons`. В дереве нет ничего, что бы это повторило |
| Поднятие memlock что-то решает на ядрах, куда это едет | Измерение на 5.8–5.10, где лимит ещё считает BPF-память | Не начато, и на этом хосте невозможно: soft = hard = 8 MiB, а с 5.11 память учитывается memcg. Манифест объявляет пол «ядро >= 5.8», и 5.8–5.10 — ровно тот диапазон, где лимит решает, загрузится ли datapath |
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
