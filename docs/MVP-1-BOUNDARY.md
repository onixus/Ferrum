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
§D был ровно `AcceptanceCase::ALL`, и требует, чтобы каждая причина, которую
агент может объявить деградацией, была здесь названа — и по префиксу `DEG_`
по всему crate, и по телу `degraded_reasons_at`, какими бы именами константы
там ни звались. Переименованный тест роняет строку, которая на него
опиралась. Ссылка разрешается в *определение* `fn`, а не в упоминание: до
этого цикла хватало подстроки, и строку держал живой комментарий об удалённом
тесте. `—` в «Делает» разрешён только тем строкам, что перечислены в
`NOT_EXECUTED_SUBJECTS`; иначе вся секция могла бы состоять из прочерков при
двух зелёных гейтах.

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
| docker.sock -> kill | runtime | K+U | U `acceptance.rs::docker_sock_access_is_killed` · U `replay.rs::replay_docker_sock_kill` · K `attach_live.rs::a_long_path_arrives_as_a_flagged_head` · K `attach_join.rs::a_kernel_openat_of_docker_sock_is_killed_by_the_signed_bundle` · K `attach_join.rs::a_truncated_docker_sock_path_still_kills_and_says_the_match_was_asserted` · K `attach_join.rs::a_kernel_record_stripped_of_the_flag_is_still_read_as_truncated` |
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
  — шесть патчей и `run.sh`, каждый обязан уронить стык. Сколько именно их
  должно быть, стоит в `tests/mutation_manifest.rs`, а не в этой прозе:
  `run.sh` перебирал `*.patch` и о количестве не утверждал ничего, так что
  удаление пяти из шести оставляло одну измеренную мутацию, ноль выживших
  и зелёную стадию. Ронять обязаны все
  шесть, и все шесть роняют — измерено прогоном harness на Linux 6.18.44,
  не прочтением кода: `react`, сообщающий `executed` без сигнала (внутри
  агента этого не видит ничто — экспорт и счётчики совпадают со здоровым
  узлом); `SignalResponder::kill`, возвращающий `Ok` без
  syscall — при этом **все unit-тесты `respond.rs` продолжают проходить**, что
  и есть замеренная дыра; снятый guard устаревшей цели; `emit()`, не ставящий
  `EVENT_FLAG_PATH_TRUNCATED`, — падает утверждение, читающее сырой флаг записи;
  декодер, верящий флагу (05); и снятая причина `RESPOND_SIGNAL_FAILING` (06) —
  узел, который решает kill и ни разу не смог его послать, снова сообщает
  о себе здоровым.
- **Четвёртая мутация не выживает, и один цикл здесь стояло обратное.**
  Документ, комментарий стадии и заголовок самого патча утверждали, что
  `04-emit-never-flags-a-truncated-path` стык проходит намеренно; `run.sh` при
  этом любого выжившего считал жёсткой ошибкой, так что стадия
  `BPF join mutations` по этому описанию не могла пройти никогда. Разрешено
  измерением: `FAILED. 3 passed; 1 failed`. Утверждение писалось по чтению
  кода и по отдельному ручному прогону, и было неверно в обе стороны.
- **Свойство, которое та мутация описывала, живо — и теперь показано на
  ядре.** Вывод усечения из байтов на стороне декодера, сделанный в цикле 8
  ради уже развёрнутых pre-fix ELF, покрывает пропавший флаг.
  `event.rs::a_buffer_filling_path_is_read_as_truncated_without_the_flag` делает
  это на синтезированной записи; цикл 10 добавил ядерное доказательство —
  `attach_join.rs::a_kernel_record_stripped_of_the_flag_is_still_read_as_truncated`
  берёт запись, которую написало это ядро, и гасит в байтах один бит.
  Строка «На ядре это не показано ни разу» стояла здесь цикл после того,
  как перестала быть верной, — ровно то занижение, о котором предупреждает
  шапка этого файла. Диагноз же, почему мутация 04 туда не добирается,
  остался верным: утверждение о сыром флаге стоит в том тесте **раньше**
  утверждений о вердикте, поэтому с патчем прогон останавливается на нём и
  до kill, `path_unknown` и SIGKILL не доходит; потребительскую половину
  ловит мутация 05, и обе нужны.
  Ни один из прогонов Jenkins не делал: стадии `BPF join` и
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
| Корень cgroup2 выводится из `mountinfo`, а не зашит: неоднозначность и нечитаемый `mountinfo` — `Degraded`, а не догадка, и fallback на константу нет ни у guard, ни у индекса | K+U | U `ferrum-agent/src/lib.rs::a_refused_cgroup_root_is_a_named_fault_and_not_a_scan_of_the_default` · U `ferrum-agent/src/lib.rs::the_carrier_has_no_fallback_to_the_hardcoded_cgroup_root` · K `attach_join.rs::a_target_that_left_the_cgroup_is_refused_and_survives` · U `cgroupfs.rs::hybrid_node_resolves_to_the_unified_mount_not_the_tmpfs` · U `cgroupfs.rs::an_ambiguous_or_absent_hierarchy_is_degraded_never_the_default` · U `cgroupfs.rs::several_views_of_one_hierarchy_pick_one_deterministically` · U `cgroupfs.rs::the_derivation_agrees_with_this_node_if_it_has_a_cgroup2_mount` |
| Стык проходит через продакшн-конструктор `ProcCgroupCheck::new()`, а не через свой вывод корня, и требует, чтобы выведённый корень совпал с тем, в котором создан probe | K | K `attach_join.rs::a_kernel_execve_of_a_shell_is_killed_by_the_signed_bundle` · K `attach_join.rs::a_kernel_openat_of_docker_sock_is_killed_by_the_signed_bundle` · K `attach_join.rs::a_truncated_docker_sock_path_still_kills_and_says_the_match_was_asserted` · K `attach_join.rs::a_target_that_left_the_cgroup_is_refused_and_survives` · K `attach_join.rs::a_kernel_record_stripped_of_the_flag_is_still_read_as_truncated` · K `attach_join.rs::a_kill_this_kernel_refuses_is_degraded_and_named` |
| Ни стадия, трогающая ядро, ни стадия стыка не могут пройти, не исполнившись: обе требуют строку-доказательство с дальнего конца attach и SIGKILL, а не только ненулевой счётчик passed | U | U `attach_live.rs::the_gate_must_not_be_compiled_out` · U `Jenkinsfile::BPF attach` · U `attach_join.rs::the_gate_must_not_be_compiled_out` · U `Jenkinsfile::BPF join` |
| Набор строк-доказательств, которых требует стадия стыка, задан вне файла, который она читает: выпотрошенная kill-половина любого §D-теста — падение, а не молчаливо укоротившийся набор | U | U `join_evidence.rs::every_required_kill_still_reaches_a_confirmed_sigkill` · U `join_evidence.rs::the_join_prints_exactly_the_evidence_lines_this_file_requires` · U `join_evidence.rs::every_required_kill_is_a_row_the_boundary_document_cites` · U `join_evidence.rs::the_body_reader_finds_one_test_and_notices_a_gutted_one` · U `Jenkinsfile::BPF join` |
| Мутаций ровно шесть, и harness отказывается измерять набор, который не совпадает с этим списком: удалить пять из шести — падение под обычным `cargo test`, а не зелёная стадия, измерившая одну | U | U `mutation_manifest.rs::the_mutation_set_is_the_one_the_gate_is_measured_against` · U `mutation_manifest.rs::every_mutation_targets_a_file_that_still_exists` · U `mutation_manifest.rs::the_runner_derives_its_floor_from_this_file` · U `Jenkinsfile::BPF join mutations` |
| Каждый образ, который называет манифест, собирается этим pipeline, собирается из Dockerfile, который линкует одноимённый crate, и содержит именно его бинарь: `COPY --from` в финальной стадии прослежен до `cargo build`, а комментарии обоих языков не считаются сборкой | U | U `deploy_gate.rs::every_image_a_manifest_names_is_built_by_the_pipeline` · U `deploy_gate.rs::each_image_is_built_from_a_dockerfile_that_links_its_own_crate` · U `deploy_gate.rs::the_payload_trace_refuses_an_image_that_ships_another_crates_binary` · U `deploy_gate.rs::a_groovy_block_comment_is_a_comment_and_a_shell_glob_is_not` · U `deploy_gate.rs::the_scan_counts_a_link_and_refuses_to_count_a_clippy_run` |
| Продуктовая комбинация `attach,apiserver` линкуется под musl и не несёт program interpreter | U | U `Jenkinsfile::Agent binary` |
| Оба поставляемых DaemonSet монтируют tracefs как hostPath типа `Directory`, и attach-манифест без такого монтирования — находка FD026, а не предупреждение | U | U `Jenkinsfile::Validate policies` · U `lint_deploy.rs::an_attach_build_without_tracefs_is_a_finding` · U `lint_deploy.rs::an_emptydir_where_tracefs_belongs_is_still_a_finding` · U `lint_deploy.rs::a_tracefs_hostpath_kubelet_would_create_is_still_a_finding` · U `lint_deploy.rs::the_tracefs_fixture_fails_on_that_rule_and_no_other` |
| Манифест, называющий корень доверия дважды, — находка, а не молчаливое last-wins | U | U `lint_deploy.rs::a_trust_root_named_twice_is_a_finding` |
| `attach_for_arch` поднимает soft `RLIMIT_MEMLOCK` до hard перед самим `Bpf::load` — это проверено на живом attach, а не только у функции: лимита не понижает и сообщает числа, а не вердикт | K+U | K `attach_live.rs::attach_raises_the_soft_memlock_it_loads_under` · K `kernel.rs::raise_memlock_never_lowers_the_limit_and_reports_what_it_left` · U `kernel.rs::memlock_describe_reports_the_numbers_not_a_verdict` |
| `libc` есть в графе `ferrum-ebpf` только под `attach`, и детектор доказан в обе стороны | U | U `Jenkinsfile::Crate boundary` |
| `rcgen` и `x509-parser` не попадают в графы admission и agent, и детектор доказан на `ferrum-cli` | U | U `Jenkinsfile::Crate boundary` |
| Оба arch дают один вердикт на одних логических событиях, из записанных байтов | U | U `replay.rs::both_arches_reach_the_same_verdicts_on_the_same_logical_events` · U `replay.rs::recorded_fixture_records_still_produce_the_acceptance_verdicts` |
| Prefilter-образ поставляемой политики — тот, который утверждает ручная копия в `ferrum-ebpf` | U | U `deploy_gate.rs::the_prefilter_image_of_the_shipped_policy_is_the_one_its_unit_test_asserts` |
| Контейнер, называющий apiserver-watch, и спроецированный SA-токен — одна связка, и обе её половины читает FD027; поставляемое дерево падало на этом правиле до правки манифестов | U | U `lint_deploy.rs::an_apiserver_watch_without_a_projected_token_is_a_finding` · U `lint_deploy.rs::the_agents_pod_watch_needs_the_same_token` · U `lint_deploy.rs::a_selector_bearing_policy_with_no_label_source_is_a_finding` · U `lint_deploy.rs::a_policy_without_a_selector_needs_no_label_source` · U `lint_deploy.rs::the_token_fixture_fails_on_that_rule_and_no_other` · U `lint_deploy.rs::deploy_tree_is_clean` |
| FD027 читает токен по пути, а не по факту automount: явная `projected` проекция, смонтированная туда, откуда её читает код, — не находка, а смонтированная в другое место — находка | U | U `lint_deploy.rs::a_projected_token_where_the_code_reads_it_is_not_a_finding` · U `lint_deploy.rs::a_projected_token_mounted_somewhere_else_is_still_a_finding` · U `lint_deploy.rs::a_projected_token_no_container_mounts_is_still_a_finding` |
| Под, чьему ServiceAccount это дерево выдало RBAC, обязан нести токен, даже если не называет ни одного флага watch — иначе он аутентифицируется как `system:anonymous`, а выданный грант описывает личность, которую никто не предъявляет | U | U `lint_deploy.rs::a_granted_service_account_with_no_projected_token_is_a_finding` · U `lint_deploy.rs::a_service_account_this_tree_grants_nothing_needs_no_token` · U `lint_deploy.rs::a_binding_to_a_ruleless_role_is_not_a_grant` |
| `ApiserverConfig` без спроецированного токена — ошибка старта, называющая файл, а не бесконечный backoff | U | U `ferrum-k8smeta/src/watch.rs::a_config_without_a_projected_token_is_an_error_that_names_the_file` |
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
| `DEG_PATH_TRUNCATED` — путь не поместился: suffix-правило решено без байтов, которые называет | U | U `ferrum-agent/src/lib.rs::path_truncation_degrades_and_then_recovers` · U `replay.rs::a_truncated_docker_sock_path_still_kills_and_degrades` |
| `DEG_IDENTITY_UNKNOWN` — cgroup, которую индекс не может назвать | U | U `replay.rs::a_cgroup_missing_from_the_index_is_counted_and_degrades` |
| `DEG_LKG_PARTIAL` — узел энфорсит меньше, чем восстановленный подписанный снапшот | U | U `ferrum-agent/src/lib.rs::lkg_restore_drops_an_unmatchable_rule_instead_of_the_whole_snapshot` |
| `DEG_CONTAINER_FLAG` — флаг контейнера расходится с индексом дольше окна старта пода | U | U `ferrum-agent/src/lib.rs::the_pod_start_window_does_not_latch_degraded` |
| `DEG_STATUS_UNWRITABLE` — сама поверхность отчётности лежит | U | U `ferrum-agent/src/lib.rs::an_unwritable_status_dir_does_not_stop_the_tick` · U `ferrum-agent/src/lib.rs::a_failed_status_write_removes_the_file_rather_than_leave_it_lying` |
| `SELF_TGID_UNPUBLISHED` — процесс не в host pid namespace, `notAgentSelf` не соблюсти; Degraded только под respond | U | U `ferrum-agent/src/lib.rs::a_namespaced_pid_is_not_published_as_the_agent_self` · U `ferrum-agent/src/lib.rs::the_shipped_observe_install_is_not_degraded_without_host_pid` |
| `TARGET_CHECK_UNPROVABLE` — guard устаревшей цели вообще не построился: ни одна реакция на узле не может проверить цель | U | U `ferrum-agent/src/lib.rs::a_guard_that_cannot_be_computed_is_a_refusal_of_its_own_and_degrades` · U `ferrum-agent/src/lib.rs::an_observe_node_is_not_degraded_by_a_guard_it_never_reaches` |
| `TARGET_NEVER_PROVEN` — respond включён и ни одна реакция ни разу не нашла цель в породившей запись cgroup | U | U `ferrum-agent/src/lib.rs::refusals_degrade_only_when_no_target_was_ever_proven` |
| `RESPOND_SIGNAL_FAILING` — respond включён, guard пройден, syscall сделан и отказал, и ни один сигнал на этом узле никогда не доходил | K+U | K `attach_join.rs::a_kill_this_kernel_refuses_is_degraded_and_named` · U `ferrum-agent/src/lib.rs::a_node_that_can_decide_kills_and_never_send_one_is_degraded` · U `ferrum-agent/src/lib.rs::a_node_that_has_delivered_one_signal_is_not_degraded_by_later_failures` · U `ferrum-agent/src/lib.rs::an_observe_node_is_not_degraded_by_a_signal_it_never_sends` |
| `DEG_WAIVERS_DROPPED` — таблица исключений не загрузилась, и все одобренные waiver отброшены | U | U `ferrum-agent/src/lib.rs::losing_every_waiver_is_a_reason_and_a_reload_that_works_clears_it` · U `ferrum-agent/src/lib.rs::a_secret_with_no_exceptions_file_is_not_a_node_that_lost_them` |
| `WAIVERS_UNJOINED` — waiver подписаны, проверены, в scope и не могут ничего здесь демотировать | U | U `ferrum-agent/src/lib.rs::waivers_that_name_another_policy_are_reported_not_silently_ignored` · U `ferrum-agent/src/lib.rs::one_live_waiver_does_not_excuse_the_dead_ones` |
| `CGROUP_ROOT_UNDERIVABLE` — корень cgroup2 не выведен: индекс не сканируется, а не ключуется на иерархии, которую никто не выбирал | U | U `ferrum-agent/src/lib.rs::a_refused_cgroup_root_is_a_named_fault_and_not_a_scan_of_the_default` · U `ferrum-agent/src/lib.rs::the_carrier_has_no_fallback_to_the_hardcoded_cgroup_root` |
| `DATAPATH_UNDECODABLE` — подряд идущие записи не декодируются: терминальная, не затухающая | U | U `ferrum-agent/src/lib.rs::a_run_of_records_that_all_fail_to_decode_is_degraded_without_more_traffic` |
| `DATAPATH_ABI_MISMATCH` — прицепленный ELF штампует записи ABI, который этот декодер не читает | U | U `ferrum-agent/src/lib.rs::a_datapath_whose_every_record_is_refused_is_degraded_without_more_traffic` · U `ferrum-agent/src/lib.rs::a_degraded_node_that_changes_why_says_so` |
| `RECORD_CHANNEL_GONE` — записи вычерпываются из ring и выбрасываются, не дойдя ни до одного правила | U | U `ferrum-agent/src/lib.rs::a_disconnected_record_channel_latches` |

`DEG_STATUS_UNWRITABLE` по устройству отстаёт на один тик: запись, которая
не удалась, не может нести запись о собственном провале. Первый провалившийся
тик всё ещё оставляет `degraded=false` на конвертах.

Последние три причины намеренно не в семействе `DEG_*`: под observe guard,
о котором они говорят, не достигается вовсе — отказ по роли возвращается
раньше, — так что на поставляемой установке по умолчанию они были бы верны на
каждом узле и не значили бы ни на одном ничего. `DEG_*` — это множество
причин, верных при любой роли. Именование защитимо, а вот gate за ним не
следовал: сканер читал только `lib.rs` и только префикс `DEG_`, поэтому эти
три (и `SELF_TGID_UNPUBLISHED`, живущий здесь с цикла 7) были ему невидимы, а
порог `>= 16` всё равно проходил. Теперь сканируется весь crate по префиксу и
отдельно — тело `degraded_reasons_at` по константам, которые оно
действительно кладёт в список, как бы они ни назывались. Третий скан читает аргументы `mark_terminal_fault`: терминальная причина попадает в список как *текст, который уже держит* — арм читает `terminal_fault()`, — поэтому константа, называющая её, не стоит ни в теле, ни в семействе `DEG_*`. За обоими прежними сканами так прожили незадокументированными `DATAPATH_UNDECODABLE`, `DATAPATH_ABI_MISMATCH` и `RECORD_CHANNEL_GONE`; `WAIVERS_UNJOINED` не видел ни один из трёх, потому что арм кладёт строку, которую собрал `waivers_unjoined()`, — эта строка теперь названа здесь, а дыру за ней закрывает не гейт, а тот же человек с `git log`.

У `DEG_PATH_TRUNCATED` метка `K` снята. Стояла ссылка на
`attach_live.rs::a_long_path_arrives_as_a_flagged_head`, но `ferrum-ebpf` не
может сослаться ни на `Agent`, ни на `DEG_PATH_TRUNCATED`: тот тест measures
запись, а не причину деградации. То же возражение уже было применено к
цитате стыка и цитата откачена; здесь оно было пропущено. Само ядерное
измерение усечённого пути никуда не делось — оно стоит строкой выше, в
§D-строке `docker.sock -> kill`, где утверждение о нём и есть.

## Не делает

Плоские утверждения. Каждое проверено по дереву на этом коммите.

- **Ни одного образа контейнера здесь не собиралось.** `Dockerfile` и стадия
  `Agent image` теперь есть, но `docker build` не запускался ни разу: демона
  в этом контейнере нет, а достать его снаружи означало бы смонтировать
  `/var/run/docker.sock` — тот самый hostPath, на который FD006 даёт находку,
  а runtime-правила убивают. Команды *внутри* `Dockerfile` прогонялись руками
  по отдельности — кроме проверки интерпретатора на `/ferrum-agent`,
  добавленной в этом цикле: она читает бинарь, который существует только
  внутри `docker build`. «Образ собирается» — не то утверждение, которое это
  дерево может сделать. `deploy/**` по-прежнему ссылается на
  `ghcr.io/ferrum/*:v0.1.0`, которых никто не публиковал.
- **Замыкание «манифест ↔ pipeline» закрыто по репозиторию и открыто по
  тегу.** `every_image_a_manifest_names_is_built_by_the_pipeline` сравнивает
  только репозиторий, потому что стадии тегируют
  `dev-$BUILD_NUMBER`, а манифесты закрепляют `v0.1.0`: два непересекающихся
  пространства тегов, которые нельзя сравнить, читая их внимательнее.
  Закрыть теговую половину в этом репозитории нечестно — ничто не делает
  `docker push`, так что тег, который придумывает CI, существует только в
  локальном сторе одного узла, а манифест, закреплённый на таком теге, —
  отдельный дефект, а не починка. Поэтому это сказано здесь, а не спрятано
  в doc-комментарии, который описывал весь класс отказа целиком:
  `the_tag_half_of_the_closure_is_open_and_says_why` держит обе посылки —
  ничто не публикует образ, и ни один манифест не называет плавающий тег —
  и падает в тот день, когда первая перестанет быть верной.
- **Заархивированный `dist/ferrum-agent` — не тот бинарь, что в образе.**
  Стадия `Agent binary` линкует и фингерпринтит один; `docker build` линкует
  внутри себя второй, из застэшенных исходников. Фингерпринт на артефакте про
  второй не говорит ничего, поэтому проверка «musl без program interpreter»
  теперь стоит в обоих местах, а не в одном. И `elf_inspect` в `Dockerfile`
  никогда не открывал `/ferrum-agent` — заголовок файла год утверждал, что он
  проверяет «две поставляемые файла»; он проверяет map layout ELF.
  `.dockerignore` до этого цикла не стэшился: он приезжал из `checkout scm`,
  то есть единственный файл, определяющий состав build context, приходил не из
  того дерева, которое стадии тестировали.
- **Гибридной иерархии cgroup здесь не было.** Прежний абзац на этом месте
  утверждал, что `ProcCgroupCheck::new()` зашивает корень cgroup2, что на
  гибридном узле каждая реакция откажет как по устаревшей цели при
  `is_degraded() == false`, и что `mountinfo` читает только тест. Все три
  утверждения теперь ложны, а последнее — обратно: вывод корня живёт в
  `ferrum-k8smeta` (`cgroupfs.rs`), им пользуются и `ProcCgroupCheck::new()`,
  и `spawn_cgroup_refresh` (один вывод на двоих: индекс производит те самые
  inode, которые проверяет guard); неоднозначность и нечитаемый `mountinfo`
  дают `Degraded`, а не догадку, и отката на константу нет; `is_degraded()`
  больше не молчит — `TARGET_CHECK_UNPROVABLE` и `TARGET_NEVER_PROVEN`
  разделяют «guard не построился» и «guard построился и ни разу не
  подтвердился»; частная копия чтения `mountinfo` из `attach_join.rs` удалена.
  «Отката на константу нет» цикл держалось только у guard: второй потребитель,
  `spawn_cgroup_refresh`, ловил отказавший вывод и всё равно сканировал
  `DEFAULT_CGROUP_ROOT`, так что на узле с неоднозначной иерархией индекс
  наполнялся inode с файловой системы, которую никто не выбирал, а под
  `observe` — поставляемым умолчанием — единственным сигналом оставался
  `DEG_IDENTITY_UNKNOWN`, читающийся как «cgroup, которую индекс не может
  назвать», а не как «индекс ключуется на не той иерархии». Теперь оба
  утверждения этого абзаца верны об обоих потребителях: отказавший вывод —
  `CGROUP_ROOT_UNDERIVABLE`, и индекс не сканируется вовсе.
  Строки об этом стоят в «Делает». **Не проверено** ровно одно: сам гибридный
  узел. Здесь cgroup2 — единственная иерархия, поэтому на ядре измерен только
  unified-случай, а гибридный, разные суперблоки и нечитаемый `mountinfo` —
  unit-тесты над синтетическим `mountinfo`.
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
