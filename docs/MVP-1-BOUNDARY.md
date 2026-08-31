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

**Второе направление закрыто наполовину, и это первый цикл, когда оно вообще
закрыто.** Гейт требовал, чтобы процитированное существовало, и не требовал,
чтобы существующее было процитировано, — ровно то направление, в котором
документ гниёт молча: слайс, который что-то доказал и не переписал свою строку,
оставляет документ *занижающим* дерево, и ни одна сборка от этого не
покраснеет. Цикл 9 наступил на это дважды.

Механическую форму имеет один случай этого направления, и теперь он держится
гейтом: каждый `#[test]` в `crates/ferrum-testkit/tests`,
`crates/ferrum-agent/tests`, `crates/ferrum-admission/tests` и
`crates/ferrum-ebpf/tests` обязан быть процитирован строкой «Делает» или
назван в списке исключений с причиной. Эти каталоги выбраны не наугад: в
них нет ничего, кроме гейтов и приёмки, поэтому каждый тест там — утверждение о
продукте, а не о функции. Тридцать пять тестов оказались непроцитированными в
момент, когда гейт написали, и на все тридцать пять написаны строки. Каталоги
при этом добавлялись по одному, и каждый добавленный находил ещё: семьдесят два
теста в `ferrum-admission`, шесть в `ferrum-ebpf`. Пока каталог вне списка,
цитируется он или нет — вопрос прилежания автора строки, и ни одна сборка на
этот вопрос не отвечает. Список исключений
приземлился пустым и должен таким оставаться — засеять его тем, что не сходится,
значит получить зелёное, ничего не проверив.

Всё остальное в этом направлении по-прежнему не закрыто: «всё верное про этот
продукт записано» механической формы не имеет. Единственный его читатель —
человек с `git log`, и он обязан быть таким же подозрительным к занижению, как
к завышению: документ, который врёт в меньшую сторону, учит не верить
документу.

## Как читать колонку «Исполняется»

Ячейка — либо `—`, либо цепочка ссылок через `·`, каждая вида
`<метка> `<файл>::<имя>``:

- `K` — исполнено на настоящем ядре. Какое это ядро, зависит от строки, и
  поэтому названо не здесь, а двумя абзацами ниже: стендов два, они разной
  архитектуры, и с билда #52 обе датапейсные стадии — `BPF attach` и
  `BPF join` — проходят в CI на aarch64-ноде. До #52 стык не проходил в CI ни
  разу, и всё, что цитирует `attach_join.rs`, было меряно только руками на
  x86_64-стенде;
- `U` — исполнено в userspace; приёмочные строки — против настоящего подписанного bundle, стадии CI — против дерева, которое поставляется;
- `A` — исполнено против **настоящего apiserver**: объект подан
  `kubectl apply`, решение приняла установка из `deploy/`, и доказательство —
  ответ apiserver, а не возврат функции. Метка новая, и появилась она потому,
  что `U` тянула два разных утверждения. «Исполнено в userspace» значило и «мы
  позвали `admit()` со структурой, которую сами собрали», и — до этого цикла
  никогда — «кластер отказал в Pod». Первый же прогон `e2e_cluster.rs` показал,
  насколько это разные вещи: два CRD из семи проходили каждый читающий текст
  гейт этого дерева и отвергались apiserver целиком. Стенд один — kind
  v1.36.1 (kindest/node) на aarch64, docker на этой машине, — и, как и с `K`,
  метка говорит «против настоящего apiserver», а не «против вашего». Кластеров
  на этом стенде два, и это не то же самое, что два стенда: `ferrum-e2e` для
  `e2e_cluster.rs` и `ferrum-install` для `install_gate.rs`. Разделены они по
  необходимости, а не для порядка: первый несёт применённую
  `ValidatingWebhookConfiguration`, то есть кластер, в котором политика уже
  действует, а гейт установки утверждает про кластер, который FERRUM не видел.
  Поэтому он требует свежести и проверяет её до первого apply. Причина этого
  разделения была шире и одной половины больше нет: до issue #20 применённый
  вебхук отказывал в ClusterRoleBinding'ах собственной установки — кеш меток
  спрашивали о пустом namespace объекта уровня кластера, он его никогда не
  наблюдал и закрывался. Это исправлено (`eval.rs::cluster_scoped_kind`,
  `webhook.rs::the_shipped_cluster_role_binding_is_not_refused_by_the_shipped_policy`)
  и проверено на живом kind: тот же apply, который отвергался, принят, а bind
  на `cluster-admin` по-прежнему отвергнут. Свежесть кластера гейт требует
  по-прежнему, но уже как утверждение о том, что он ставит с нуля, а не как
  обход дефекта;
- `—` — не исполнено ничем.

`K` больше не наследует один стенд, и это первый цикл, когда это так. Стендов
два, и они меряют разное:

- **x86_64, Linux 6.18.44, Firecracker microVM без `CONFIG_MODULES`** — руками,
  вне CI. Там нет ни `init_module`, ни `finit_module`, ни tracepoint для них, и
  attach сообщает их незацепленными вместо того, чтобы цепляться. Всё, что
  здесь цитирует `attach_join.rs`, измерено там и **по-прежнему только там**:
  стык на второй ноде не исполнялся.
- **aarch64, Linux 6.12.76-linuxkit, нода локального Jenkins** — стадией
  `BPF attach`, начиная с билда #39. Там `CONFIG_MODULES=y`, зато нет syscall
  `open`, и attach сообщает незацепленным его: `unhooked on this node:
  ["open"]`. Всё, что цитирует `attach_live.rs`, с этого цикла измерено на
  обоих ядрах и на обеих архитектурах.

Разница между ними — не формальность, и один случай уже нашёлся. Путь, который
ребёнок передаёт в `openat`, ничего не сделав после `fork`, на x86_64 читается,
а на aarch64 — нет: `bpf_probe_read_user_str` не фолтит, и страницы для него
там ещё нет. Датапейс помечает такую запись `EVENT_FLAG_PATH_TRUNCATED` с
пустым буфером, а `matched_action` на такой записи утверждает совпадение и
ставит `path_unknown` — то есть правило по пути не обходится. Держит это
`attach_live.rs::a_path_this_kernel_could_not_read_is_never_reported_as_a_short_one`,
и закрыть его из userspace нельзя: флаг ставится в ядре.

Ссылка `Jenkinsfile::<стадия>` утверждает ровно одно: стадия с таким именем
есть в поставляемом `Jenkinsfile`. Это единственное, что проверяет гейт, и
это меньше, чем читается. Она **не** утверждает, что стадию исполнял Jenkins,
и гейт этого проверить не может: между «стадия есть» и «стадия зелёная» он не
различает.

То же и с публичным воркфлоу `.github/workflows/ci.yml`: он поставляется в
дереве, его скрипты сверены с одноимёнными стадиями `Jenkinsfile` построчно,
и на этом всё. На GitHub он **не исполнялся ни разу** — на дату этой правки
прогонов нет. Ни одна строка ниже не меряна им, и до первого настоящего
прогона такой строки здесь быть не может.

То же и с релизным воркфлоу `.github/workflows/release.yml`. Он поставляется в
дереве, множество образов в нём сверено с `deploy/**` и `Jenkinsfile` на
равенство, подпись в нём keyless и без единого ключа, а процедура проверки в
README сверена с ним же, — и на этом всё. **Ни один образ не опубликован**: в
`ghcr.io/onixus/` нет ни одного тега, `docker push` не исполнялся ни разу ни
здесь, ни где-либо ещё, ни одной подписи cosign не существует, ни одного SBOM
не приложено ни к одному релизу. Слов «опубликовано» и «подписано» ниже нет и
до первого настоящего релиза быть не может; всё, что про этот файл сказано, —
про содержимое файла.

Что известно про исполнение на 2026-08-30, и известно из логов билдов, а не из
этого абзаца. Билды #31–#37 гоняли **предыдущий** `Jenkinsfile` — без стадии
`Datapath tracefs` и без `DATAPATH_DOCKER_ARGS`; в каждом из них проходили
шестнадцать стадий из девятнадцати, всё кроме группы `Datapath`, и `BPF attach`
падала восемью тестами из восьми. Текущий `Jenkinsfile` в редакции #38–#41 гонялся
четыре раза, и стадий в нём было двадцать:

- **#38** (`f6f201d`) — стадия `Datapath tracefs` появляется здесь, а не позже,
  и здесь же датапейс впервые цепляется на второй ноде: `BPF attach` даёт семь
  тестов из восьми. Проходит семнадцать стадий из двадцати;
- **#39** (`4d92ec`) — `BPF attach` впервые зелёная целиком, девять тестов из
  девяти против настоящего ядра. Проходит восемнадцать из двадцати;
- **#40** (`9fa6846`) и **#41** (`2cb044e`, текущий коммит) — тот же результат
  повторён дважды: восемнадцать из двадцати, `BPF attach` 9/9.

Падает во всех четырёх одно и то же — `BPF join`, за которой пропускается
`BPF join mutations`.

Дальше цикл добавил стадию `Datapath cgroup` и вынес стык в группу
`Datapath join`, отчего стадий стало двадцать одна, и потратил на это три
билда:

- **#42** — первая редакция правки, красная и хуже прежнего: стадию положили
  вложенной в docker-группу, где `agent any` всё равно исполняется launcher'ом
  контейнера (JENKINS-30600, `docker: not found`), и её падение унесло с собой
  зелёную `BPF attach`. Тот же дефект в своё время увёл отсюда
  `SAST (semgrep)`;
- **#43** — база без правки, повторившая #39–#41 в точности;
- **#44** (`e0ab03b`) — стык вынесен в собственную группу, `Datapath cgroup`
  зелёная, `BPF attach` по-прежнему 9/9. Проходят девятнадцать стадий из
  двадцати одной.

**Права на запись в cgroup стык держать перестали в #44, и дальше он дошёл до
ядра.** `mkdir /sys/fs/cgroup/ferrum-join-…: Read-only file system` из логов
исчез, и шесть тестов стали падать по существу. Разбор занял четыре билда, и
каждый отказ назван логом, а не догадкой:

- **#44–#48** — пять тестов не дожидались записи с ожидаемым путём, хотя запись
  `openat` от того же tgid приходила. `bpf_probe_read_user_str` не фолтит, и на
  этом ядре страница со строкой пути недостижима для него в ребёнке, который
  после `fork` ничего не сделал: запись несёт пустой путь и
  `EVENT_FLAG_PATH_TRUNCATED`. `attach_live.rs` трогает страницу явно и
  объясняет почему; у стыка, написанного на x86_64, этой строки не было;
- **#48** — шестой тест видел два убийства вместо одного, и причина оказалась
  не дефектом агента: первый `execve` пробы приходил с `path_unknown`, а
  правило по пути, не сумевшее путь прочитать, совпадение **утверждает** — тот
  самый fail-closed. Проба отдавала ядру путь, который ни одно правило не могло
  оправдать;
- **#49** — последний отказ: реакция не доходила до `kill(2)`, потому что тест
  целился в `pid_max + 1`, а на этой ноде `pid_max` равен `PID_MAX_LIMIT`, он
  же `MAX_TGID` агента. Агент отказывается сигналить такой tgid по построению,
  и тест мерил работающий guard, называя это отказом ядра;
- **#51** — один exact-match тест упал, дважды перед этим пройдя. Трогать
  первый байт пути мало: строка, попавшая на границу страницы, дочитывается до
  границы, и запись несёт префикс. Тест на префикс проходит всегда, тест на
  полное равенство — через раз, по адресу аллокации.

**#52 (`0880945`) — первый зелёный прогон целиком.** Двадцать одна стадия из
двадцати одной, пропусков нет. `BPF join` — шесть тестов из шести, четыре из
них печатают `kernel record → signed bundle → SIGKILL, confirmed by waitpid`.
Следом впервые в истории репозитория исполнилась `BPF join mutations`: все шесть
мутаций убиты, переживших нет.

Прежняя редакция этого абзаца приписывала `Datapath tracefs` и первое ядерное
измерение на второй ноде билду #39, а билд #38 не называла вовсе, и при этом
объявляла себя знанием «из логов билдов, а не из этого абзаца». Считала она
и прогоны текущего файла вместе с прогонами прежнего — девять вместо двух,
которые на тот день были.

**Прежняя редакция этого абзаца объясняла падение неверно, и объяснение
держалось четыре цикла.** Здесь стояло «ядро в LinuxKit VM без tracefs,
eBPF-карту создать нельзя» — то есть отказ приписывался ядру и стенду, а из
этого следовало, что сделать ничего нельзя, и потому никто не пробовал.
Измерено обратное: ядро ноды (6.12.76-linuxkit, aarch64) несёт
`CONFIG_BPF_SYSCALL`, `CONFIG_BPF_EVENTS`, `CONFIG_FTRACE`, `CONFIG_DEBUG_FS` и
`CONFIG_MODULES`, и все пять точек, которые цепляет датапейс —
`sys_enter_{execve,openat,bpf,init_module,finit_module}` — на ней есть.
Отказывал контейнер: агент запускается с uid 0, но с дефолтным bounding set
докера (`CapEff 00000000a80425fb`, верхние 32 бита нулевые), где нет ни
`CAP_BPF`, ни `CAP_PERFMON`; `bpf(BPF_MAP_CREATE)` в нём возвращает `EPERM`.
Вторая половина — несмонтированный tracefs, который изнутри контейнера без
`CAP_SYS_ADMIN` не смонтировать. Третья, вылезшая следом, — собственный PID
namespace: датапейс пишет pid из init-namespace, тесты сверяют их со своим
`getpid()`, и `attach_live` видел ноль своих записей при исправном датапейсе.
Все три — строки в `Jenkinsfile`: `DATAPATH_DOCKER_ARGS` и стадия
`Datapath tracefs`.

**`BPF join` остаётся красной, и по причине того же рода, но не той же
величины.** Шесть её тестов создают собственную cgroup (`mkdir
/sys/fs/cgroup/ferrum-join-…`), а Docker монтирует cgroupfs только на чтение —
суперблок `rw`, монтирование `ro`. Перемонтировать изнутри требует
`CAP_SYS_ADMIN`, а bind-mount хостового дерева даёт запись в cgroup всего узла;
ни то, ни другое сборочному контейнеру, исполняющему код репозитория, здесь не
выдано. Стык поэтому по-прежнему измерен только на x86_64-стенде, и это
записано в определении `K` выше, а не подразумевается.

Что при этом *не* изменилось: задним числом эта нода ничего не подтверждает.
Она стала вторым стендом `K` ровно для того, что на ней исполнилось начиная с
билда #39, — для `attach_live.rs`, и ни для чего больше. Строки, цитирующие
`attach_join.rs`, по-прежнему меряны на одном хосте, потому что стык здесь не
исполнялся ни разу.

Эта нода — arm64, и цель `x86_64-unknown-linux-musl` берётся
на ней кросс-компиляцией. Прошедшая стадия `Agent binary` говорит, что
продуктовая комбинация линкуется и не несёт интерпретатора; она не говорит,
что этот бинарь запускали.

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
| unsigned image -> deny | admission | A+U | U `acceptance.rs::unsigned_image_is_denied` · A `e2e_cluster.rs::an_unsigned_image_is_denied_by_the_real_apiserver` |
| privileged -> deny | admission | A+U | U `acceptance.rs::privileged_pod_is_denied` · A `e2e_cluster.rs::a_privileged_pod_is_denied_by_the_real_apiserver` |
| cluster-admin bind -> deny | admission | U | U `acceptance.rs::cluster_admin_bind_is_denied` |
| exception without TTL -> API reject | admission | — | — |
| kubectl exec + /bin/sh -> kill | runtime | K+U | U `acceptance.rs::exec_shell_in_container_is_killed` · U `replay.rs::replay_exec_shell_kill` · K `attach_live.rs::execve_path_comes_from_the_first_argument_slot` · K `attach_join.rs::a_kernel_execve_of_a_shell_is_killed_by_the_signed_bundle` |
| docker.sock -> kill | runtime | K+U | U `acceptance.rs::docker_sock_access_is_killed` · U `replay.rs::replay_docker_sock_kill` · K `attach_live.rs::a_long_path_arrives_as_a_flagged_head` · K `attach_join.rs::a_kernel_openat_of_docker_sock_is_killed_by_the_signed_bundle` · K `attach_join.rs::a_truncated_docker_sock_path_still_kills_and_says_the_match_was_asserted` · K `attach_join.rs::a_kernel_record_stripped_of_the_flag_is_still_read_as_truncated` |
| bpf() not from the agent -> deny | runtime | K+U | U `acceptance.rs::bpf_not_from_agent_is_denied` · U `replay.rs::replay_bpf_not_from_agent_deny` · K `attach_live.rs::a_foreign_record_is_not_flagged_agent_self` |
| CP down -> last-known-good | runtime | A+U | U `acceptance.rs::cp_down_keeps_last_known_good_not_fail_open` · A `e2e_cluster.rs::a_control_plane_that_is_gone_keeps_the_webhook_on_last_known_good` |

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
- **Три случая §D теперь решены настоящим apiserver, и это первый цикл, когда
  хоть один решён.** `e2e_cluster.rs` разворачивает `deploy/controller` и
  `deploy/admission` в kind, применяет `policies/examples/prod-restricted.yaml`,
  ждёт, пока **контроллер** скомпилирует и подпишет bundle (Secret пишет он, а
  не тест: `status.compile.message == "compiled and signed"`), выпускает PKI
  тем же `ferrumctl gen-webhook-pki`, который описан в README каталога, и
  подаёт Pod. Отказ читается из ответа apiserver и обязан назваться отказом
  `policy.ferrum.io` с причиной: под `failurePolicy: Fail` недоступный webhook
  отвергает Pod ровно так же, и тест, проверяющий только «Pod не создан»,
  прочитал бы мёртвый webhook как работающий. Чего эти три строки **не**
  говорят: агента в этой установке нет (см. ниже), а `A` на строке `CP down` —
  это admission-плоскость. Диск агента, LKG-снапшот и `Degraded=true`
  по-прежнему меряет только `acceptance.rs`.
- **`CP down` в кластере — это удалённый control plane, а не флаг.**
  Контроллер отмасштабирован в ноль, `ClusterSecurityPolicy` удалён из
  apiserver, Secret с bundle удалён вместе с ним; webhook продолжает отказывать
  своей причиной, и тест сверяет, что отвечают **те же Pod'ы** — по именам и
  счётчикам рестартов, а не по сумме: перезапущенный процесс перечитал бы
  монтирование на старте, и тогда прогон не сказал бы ничего о процессе,
  держащем bundle, чей источник исчез.
- **Установка нашла три дефекта, которых не видел ни один гейт этого дерева, и
  все три — в поставляемых файлах.** Два CRD apiserver отвергал целиком:
  `clustersecuritypolicy`/`securitypolicy` — по бюджету стоимости CEL
  (`estimated rule cost exceeds budget by factor of 1.344083x`), потому что
  массив `runtime.rules` не имел объявленной границы; `policyexception` — по
  `now()`, которого в CEL валидации CRD нет и не будет, так как валидация
  обязана быть детерминированной. Это значит, что PolicyException не
  устанавливался вообще, а все остальные правила того файла были инертны — и
  держал их тест, читавший те же строки из того же файла. Третий: `Dockerfile*`
  умели собирать только цель x86_64, и образ под ноду kind на arm64 собрать
  было нечем. Ни один из трёх не виден изнутри процесса.
- **`exception without TTL` стоит `—`, и с этого цикла это уже не граница, а
  долг.** Субъект утверждения — API server, и раньше здесь стояло, что API
  server не запускался ни разу; это перестало быть правдой. `serde`
  отказывается декодировать объект без `expiresAt`, CRD несёт `required` — и
  теперь установлен в настоящем apiserver, — но отказ библиотеки по-прежнему не
  есть отказ apiserver, а Pod'ов этот случай не подаёт: `e2e_cluster.rs` его не
  делает, и говорит об этом в `NOT_COVERED_HERE` своими словами. Цитировать
  здесь нечего до тех пор, пока кто-нибудь не подаст `PolicyException` без TTL
  настоящему apiserver и не прочтёт его ответ. Две CEL-строки, которые этот
  пункт раньше засчитывал себе в актив, apiserver отверг вместе со всем файлом,
  см. абзац выше.
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
| CRD требует `expiresAt`; потолок 90 дней держит `ferrum-policy`, и схема его держать не может — в CEL валидации CRD нет часов | A+U | U `deploy_gate.rs::exception_expires_at_is_mandatory_in_cel_and_in_decode` · U `deploy_gate.rs::exception_ttl_ceiling_is_ninety_days_in_policy_and_no_schema_may_claim_it` · A `e2e_cluster.rs::the_shipped_crds_are_accepted_by_a_real_apiserver` |
| Kill/Isolate без match отвергается схемой и политикой (это kill-all) | U | U `deploy_gate.rs::kill_without_match_is_rejected_in_cel_and_in_policy` |
| Namespaced policy не может `failurePolicy=Ignore` | U | U `deploy_gate.rs::namespaced_policy_cannot_ignore_in_cel_and_in_policy` |
| Правило, называющее syscall, которого datapath не цепляет, не валидируется | U | U `deploy_gate.rs::a_rule_naming_an_unhooked_syscall_does_not_validate` · U `Jenkinsfile::Validate policies` |
| Действие, которого runtime-плоскость не исполняет, не валидируется — и в схеме тоже | U | U `deploy_gate.rs::a_rule_whose_action_the_runtime_plane_cannot_execute_does_not_validate` · U `deploy_gate.rs::every_runtime_action_ferrum_policy_refuses_is_refused_by_the_cel_copy` |
| Половина пары open/openat — мёртвое или обходимое правило, и оно отвергается | U | U `Jenkinsfile::Validate policies` |
| `lint-deploy` проходит на поставляемом дереве, и плохие фикстуры падают | U | U `Jenkinsfile::Validate policies` |
| `gen-webhook-pki` выпускает PKI офлайн и отказывается перезаписать выпущенное | U | U `Jenkinsfile::Validate policies` |
| BPF ELF несёт все программы и карты, которые связывает loader: каждый символ программы стоит функцией в своей tracepoint-секции, каждая карта — объектом в `maps`, и объект проходит ту же проверку карт, которой агент отказывает в загрузке перед attach | U | U `elf_inspect.rs::elf_contains_all_tracepoints` · U `elf_inspect.rs::the_shipped_elf_passes_the_attach_time_map_check` · U `Jenkinsfile::BPF ELF` |
| Определения карт в поставляемом ELF совпадают с userspace ABI, и совпадение читают два независимых разборщика, а не один сам себя: дрейф `ferrum_cgroups` тихо гасит каждое правило `containerOnly`, дрейф `ferrum_events` роняет `take_ring` или роняет записи мимо счётчика потерь, дрейф `ferrum_self` снимает `EVENT_FLAG_AGENT_SELF` и разрешает агенту убить себя | U | U `elf_inspect.rs::cgroups_map_definition_matches_the_userspace_abi` · U `elf_inspect.rs::events_map_definition_matches_the_userspace_abi` · U `elf_inspect.rs::self_map_definition_matches_the_userspace_abi` · U `Jenkinsfile::BPF ELF` |
| Datapath в настоящем ядре: одна декодируемая запись на syscall, путь из первого слота, нечитаемый указатель помечен пустым буфером | K | K `attach_live.rs::openat_produces_one_decodable_record` · K `attach_live.rs::a_syscall_without_a_path_argument_is_not_flagged` · K `attach_live.rs::unreadable_path_pointer_is_flagged_with_an_empty_buffer` |
| Карта `ferrum_cgroups` живёт на настоящем handle | K | K `attach_live.rs::cgroup_map_round_trips_on_a_live_handle` |
| Пины настоящие: три карты и привязки этого handle переживают процесс, который их загрузил — при уничтоженном handle пин переоткрывается как объект ядра, а не как файл | K+U | K `attach_pins.rs::pins_are_kernel_objects_that_outlive_the_handle` · U `Jenkinsfile::BPF pins` |
| Отказавший пин не стоит ни одного хука: путь не на bpffs отвергается, дерева за собой не оставляет, и тот же handle после отказа пинится целиком — то есть снятая с программы привязка была возвращена | K | K `attach_pins.rs::a_pin_root_that_is_not_bpffs_is_refused_and_leaves_no_tree` |
| Занятый путь пина отвергается, а не присваивается: изнутри процесса пин прежнего экземпляра и пин, поставленный кем-то другим, — один и тот же файл | K | K `attach_pins.rs::a_pin_path_already_taken_is_refused_rather_than_adopted` |
| Путь, который это ядро не смогло прочитать, не выдаётся за короткий: запись приходит помеченной `EVENT_FLAG_PATH_TRUNCATED` с пустым буфером, а совпадение по такой записи утверждается с `path_unknown`, то есть правило по пути не обходится молчанием. Флаг ставит ядро, поэтому из userspace эта строка не закрывается | K | K `attach_live.rs::a_path_this_kernel_could_not_read_is_never_reported_as_a_short_one` |
| Цель, покинувшая cgroup, которая породила запись, сигнала не получает: `REFUSE_STALE_TARGET`, probe жив | K | K `attach_join.rs::a_target_that_left_the_cgroup_is_refused_and_survives` |
| Корень cgroup2 выводится из `mountinfo`, а не зашит: неоднозначность и нечитаемый `mountinfo` — `Degraded`, а не догадка, и fallback на константу нет ни у guard, ни у индекса | K+U | U `ferrum-agent/src/lib.rs::a_refused_cgroup_root_is_a_named_fault_and_not_a_scan_of_the_default` · U `ferrum-agent/src/lib.rs::the_carrier_has_no_fallback_to_the_hardcoded_cgroup_root` · K `attach_join.rs::a_target_that_left_the_cgroup_is_refused_and_survives` · U `cgroupfs.rs::hybrid_node_resolves_to_the_unified_mount_not_the_tmpfs` · U `cgroupfs.rs::an_ambiguous_or_absent_hierarchy_is_degraded_never_the_default` · U `cgroupfs.rs::several_views_of_one_hierarchy_pick_one_deterministically` · U `cgroupfs.rs::the_derivation_agrees_with_this_node_if_it_has_a_cgroup2_mount` |
| Стык проходит через продакшн-конструктор `ProcCgroupCheck::new()`, а не через свой вывод корня, и требует, чтобы выведённый корень совпал с тем, в котором создан probe | K | K `attach_join.rs::a_kernel_execve_of_a_shell_is_killed_by_the_signed_bundle` · K `attach_join.rs::a_kernel_openat_of_docker_sock_is_killed_by_the_signed_bundle` · K `attach_join.rs::a_truncated_docker_sock_path_still_kills_and_says_the_match_was_asserted` · K `attach_join.rs::a_target_that_left_the_cgroup_is_refused_and_survives` · K `attach_join.rs::a_kernel_record_stripped_of_the_flag_is_still_read_as_truncated` · K `attach_join.rs::a_kill_this_kernel_refuses_is_degraded_and_named` |
| cgroup2 в контейнере стыка писуема, и её корень остаётся тем, который принимает продуктовый вывод: проверяется `mkdir`/`rmdir` изнутри контейнера, а не флагом монтирования, и поле root читается оттуда же, откуда его читает `detect_cgroup2_root()` | U | U `Jenkinsfile::Datapath cgroup` |
| Ни стадия, трогающая ядро, ни стадия стыка, ни стадия пинов не могут пройти, не исполнившись: каждая требует строку-доказательство с дальнего конца attach, SIGKILL или переоткрытого пина, а не только ненулевой счётчик passed | U | U `attach_live.rs::the_gate_must_not_be_compiled_out` · U `Jenkinsfile::BPF attach` · U `attach_join.rs::the_gate_must_not_be_compiled_out` · U `Jenkinsfile::BPF join` · U `attach_pins.rs::the_gate_must_not_be_compiled_out` · U `Jenkinsfile::BPF pins` |
| Набор строк-доказательств, которых требует стадия стыка, задан вне файла, который она читает: выпотрошенная kill-половина любого §D-теста — падение, а не молчаливо укоротившийся набор | U | U `join_evidence.rs::every_required_kill_still_reaches_a_confirmed_sigkill` · U `join_evidence.rs::the_join_prints_exactly_the_evidence_lines_this_file_requires` · U `join_evidence.rs::every_required_kill_is_a_row_the_boundary_document_cites` · U `join_evidence.rs::the_body_reader_finds_one_test_and_notices_a_gutted_one` · U `Jenkinsfile::BPF join` |
| Мутаций ровно шесть, и harness отказывается измерять набор, который не совпадает с этим списком: удалить пять из шести — падение под обычным `cargo test`, а не зелёная стадия, измерившая одну | U | U `mutation_manifest.rs::the_mutation_set_is_the_one_the_gate_is_measured_against` · U `mutation_manifest.rs::every_mutation_targets_a_file_that_still_exists` · U `mutation_manifest.rs::the_runner_derives_its_floor_from_this_file` · U `Jenkinsfile::BPF join mutations` |
| Каждый образ, который называет манифест, собирается этим pipeline, собирается из Dockerfile, который линкует одноимённый crate, и содержит именно его бинарь: `COPY --from` в финальной стадии прослежен до `cargo build`, а комментарии обоих языков не считаются сборкой | U | U `deploy_gate.rs::every_image_a_manifest_names_is_built_by_the_pipeline` · U `deploy_gate.rs::each_image_is_built_from_a_dockerfile_that_links_its_own_crate` · U `deploy_gate.rs::the_payload_trace_refuses_an_image_that_ships_another_crates_binary` · U `deploy_gate.rs::a_groovy_block_comment_is_a_comment_and_a_shell_glob_is_not` · U `deploy_gate.rs::the_scan_counts_a_link_and_refuses_to_count_a_clippy_run` |
| Образ объявляет ту платформу, под которую слинковано его содержимое: сборка идёт на `$BUILDPLATFORM`, а `docker build` называет целевую платформу явно — иначе образ клеймится архитектурой ноды, а внутри лежит бинарь другой | U | U `deploy_gate.rs::every_docker_build_names_the_platform_its_binaries_are_linked_for` · U `deploy_gate.rs::every_builder_stage_compiles_on_the_machine_it_runs_on` · U `Jenkinsfile::Agent image` |
| Продуктовая комбинация `attach,apiserver` линкуется под musl и не несёт program interpreter | U | U `Jenkinsfile::Agent binary` |
| Оба поставляемых DaemonSet монтируют tracefs как hostPath типа `Directory`, и attach-манифест без такого монтирования — находка FD026, а не предупреждение; правило нормализует обе стороны, так что завершающий слэш в `mountPath` или `hostPath.path` не превращает корректный манифест в находку | U | U `Jenkinsfile::Validate policies` · U `lint_deploy.rs::an_attach_build_without_tracefs_is_a_finding` · U `lint_deploy.rs::an_emptydir_where_tracefs_belongs_is_still_a_finding` · U `lint_deploy.rs::a_tracefs_hostpath_kubelet_would_create_is_still_a_finding` · U `lint_deploy.rs::the_tracefs_fixture_fails_on_that_rule_and_no_other` · U `lint_deploy.rs::a_trailing_slash_on_the_tracefs_mount_is_not_a_missing_mount` |
| Манифест, называющий корень доверия дважды, — находка, а не молчаливое last-wins | U | U `lint_deploy.rs::a_trust_root_named_twice_is_a_finding` |
| `attach_for_arch` поднимает soft `RLIMIT_MEMLOCK` до hard перед самим `Bpf::load` — это проверено на живом attach, а не только у функции: лимита не понижает и сообщает числа, а не вердикт | K+U | K `attach_live.rs::attach_raises_the_soft_memlock_it_loads_under` · K `kernel.rs::raise_memlock_never_lowers_the_limit_and_reports_what_it_left` · U `kernel.rs::memlock_describe_reports_the_numbers_not_a_verdict` |
| `libc` есть в графе `ferrum-ebpf` только под `attach`, и детектор доказан в обе стороны | U | U `Jenkinsfile::Crate boundary` |
| `rcgen` и `x509-parser` не попадают в графы admission и agent, и детектор доказан на `ferrum-cli` | U | U `Jenkinsfile::Crate boundary` |
| Публичный воркфлоу `.github/workflows/ci.yml` исполняет ровно userspace-стадии `Jenkinsfile` и побуквенно те же скрипты: `Format`, `Clippy`, `Test` и группа `Checks` целиком, сверенные на равенство строк, а не «по духу». Датапейсной стадии и стадии образов в нём нет по именам, и ни один шаг не может себя пропустить: ни `continue-on-error`, ни условия на шаге, ни подавления кода возврата. Про исполнение на GitHub эта строка не говорит ничего — гейт, как и `Jenkinsfile::<стадия>`, читает поставляемый файл | U | U `deploy_gate.rs::every_mirrored_stage_runs_the_same_script_here_and_in_jenkins` · U `deploy_gate.rs::the_comparison_notices_a_script_that_drifted` · U `deploy_gate.rs::the_public_workflow_claims_no_stage_it_cannot_execute` · U `deploy_gate.rs::no_step_in_the_public_workflow_can_skip_itself` |
| Версия у этого дерева одна, и это та, которую называет релизный тег: `[workspace.package]` несёт `0.1.0`, все восемнадцать crate берут её через `version.workspace`, ни один не объявляет свою, и каждый `image:` под `deploy/` в `ghcr.io/onixus/` закреплён на `v` + эта версия. Про существование такого тега строка не говорит ничего: гейт читает файлы, а не `git tag` и не реестр | U | U `deploy_gate.rs::the_version_this_workspace_carries_is_the_tag_its_manifests_pin` · U `deploy_gate.rs::every_crate_takes_its_version_from_the_workspace` |
| Раздел README про первый релиз называет каждый образ, который публикует `.github/workflows/release.yml`: описание, перечисляющее меньше артефактов, чем выпускает тег, учит получателя проверить меньше подписей, чем есть | U | U `deploy_gate.rs::the_first_release_section_names_every_image_that_release_publishes` |
| `SECURITY.md` называет ровно тот канал раскрытия, который у этого репозитория есть — приватный advisory GitHub, — и не заводит ни одного, которого нет: ни почтового адреса, ни PGP-блока, ни отпечатка. Поддерживаемая линия версий в нём — та, которую несёт `[workspace.package]`, плюс `main`, пока тегов нет. Про то, включён ли приём advisory в настройках репозитория, строка не говорит: это состояние GitHub, а не дерева | U | U `deploy_gate.rs::the_security_policy_names_a_channel_this_repository_actually_has` · U `deploy_gate.rs::the_security_policy_supports_the_version_this_tree_carries` |
| Оба arch дают один вердикт на одних логических событиях, из записанных байтов | U | U `replay.rs::both_arches_reach_the_same_verdicts_on_the_same_logical_events` · U `replay.rs::recorded_fixture_records_still_produce_the_acceptance_verdicts` |
| Секретный сканер не пропускает ничего, за что не поручился гейт: исключён ровно один путь, это фикстура, чьё тело не является ключевым материалом (payload не открывается DER SEQUENCE), и FD023 по-прежнему называет её находкой | U | U `deploy_gate.rs::the_scanner_skips_exactly_the_files_this_gate_vouches_for` · U `deploy_gate.rs::every_excluded_file_is_a_fixture_that_only_looks_like_a_key` · U `deploy_gate.rs::the_excluded_fixture_is_still_a_finding_for_the_lint_that_owns_it` · U `Jenkinsfile::SAST (semgrep)` |
| Prefilter-образ поставляемой политики — тот, который утверждает ручная копия в `ferrum-ebpf` | U | U `deploy_gate.rs::the_prefilter_image_of_the_shipped_policy_is_the_one_its_unit_test_asserts` |
| Контейнер, называющий apiserver-watch, и спроецированный SA-токен — одна связка, и обе её половины читает FD027; поставляемое дерево падало на этом правиле до правки манифестов | U | U `lint_deploy.rs::an_apiserver_watch_without_a_projected_token_is_a_finding` · U `lint_deploy.rs::the_agents_pod_watch_needs_the_same_token` · U `lint_deploy.rs::a_selector_bearing_policy_with_no_label_source_is_a_finding` · U `lint_deploy.rs::a_policy_without_a_selector_needs_no_label_source` · U `lint_deploy.rs::the_token_fixture_fails_on_that_rule_and_no_other` · U `lint_deploy.rs::deploy_tree_is_clean` |
| FD027 читает токен по пути, а не по факту automount: явная `projected` проекция, смонтированная туда, откуда её читает код, — не находка, а смонтированная в другое место — находка | U | U `lint_deploy.rs::a_projected_token_where_the_code_reads_it_is_not_a_finding` · U `lint_deploy.rs::a_projected_token_mounted_somewhere_else_is_still_a_finding` · U `lint_deploy.rs::a_projected_token_no_container_mounts_is_still_a_finding` |
| Под, чьему ServiceAccount это дерево выдало RBAC, обязан нести токен, даже если не называет ни одного флага watch — иначе он аутентифицируется как `system:anonymous`, а выданный грант описывает личность, которую никто не предъявляет | U | U `lint_deploy.rs::a_granted_service_account_with_no_projected_token_is_a_finding` · U `lint_deploy.rs::a_service_account_this_tree_grants_nothing_needs_no_token` · U `lint_deploy.rs::a_binding_to_a_ruleless_role_is_not_a_grant` |
| `ApiserverConfig` без спроецированного токена — ошибка старта, называющая файл, а не бесконечный backoff | U | U `ferrum-k8smeta/src/watch.rs::a_config_without_a_projected_token_is_an_error_that_names_the_file` |
| Долг relist, поднятый нечитаемым кадром, гасится истечением hold-down на любом следующем кадре, а не приходом второго нечитаемого: одиночный плохой кадр на здоровом потоке не оставляет кэш нетёплым на всё время соединения, и при этом всплеск нечитаемых кадров не стоит переподключения на кадр | U | U `ferrum-k8smeta/src/watch.rs::one_unreadable_frame_on_an_otherwise_healthy_stream_still_relists` · U `ferrum-k8smeta/src/watch.rs::an_unreadable_pod_frame_ends_the_stream_once_its_debt_stands` · U `ferrum-k8smeta/src/watch.rs::a_rolling_stream_of_unknown_frames_is_not_a_reconnect_per_frame` |
| Несосчитанный rollout отличается на проводе от сосчитанного нуля: поставляемый манифест контроллера флота не объявляет, пустой срез даёт `null` в обоих счётчиках, объявленный вставший флот — `0`, и обе CRD принимают `null`, иначе каждый PATCH статуса отказывал бы | U | U `ferrum-controller/src/lib.rs::an_undeclared_fleet_is_absent_from_status_and_a_stuck_one_is_a_counted_zero` · U `deploy_gate.rs::the_shipped_controller_declares_no_fleet_so_its_rollout_counts_are_absent_not_zero` · U `deploy_gate.rs::both_rollout_counts_are_nullable_in_every_crd_that_carries_them` |
| Подписанный bundle, чей wasm-слот несёт модуль, которого этот бинарь не исполняет, отвергается обеими плоскостями, и агент остаётся на last-known-good; отличие от принимаемого bundle — один байт kind, подписанный тем же ключом | U | U `acceptance.rs::a_signed_bundle_whose_wasm_slot_no_plane_can_execute_is_refused_by_both` · U `ferrum-wasm-host/src/lib.rs::only_the_versioned_placeholder_is_a_loadable_slot` |
| Ни одна поставляемая CRD не объявляет status, которого никто не пишет, и ни один писатель status не остаётся без объявления в CRD; фикстура §D тоже не несёт статуса, за который никто не отвечает | U | U `boundary_gate.rs::a_status_no_subject_writes_is_not_a_status_this_tree_ships` · U `ferrum-testkit/src/lib.rs::the_cp_down_fixture_is_a_spec_no_component_answers` |
| Бюджет латентности admission заявлен числом и меряется: **p99 одного AdmissionReview внутри `handle()` — 5 мс** для release-сборки, которую несут образы, и 50 мс для отладочной, которую собирает `cargo test`. Два числа — это не два бюджета: продукт заявляет первое, второе существует потому, что в debug проверка Ed25519 у подписи образа медленнее на порядок, а держать неоптимизированный артефакт числом, объявленным про оптимизированный, значило бы утверждать про то, чего никто не поставляет. Ни одна из двух веток не умеет пропустить себя. **Измерено**, 2026-08-31, 10 000 review в четыре потока против скомпилированного и подписанного `prod-restricted`: на aarch64/macOS (Apple Silicon, 15 доступных потоков) release — среднее 34 мкс, p99 ≤ 0,1 мс; debug — среднее 289 мкс, p99 ≤ 1 мс. Отдельно, в кластере: один review в Pod'е вебхука на kind (aarch64, musl-бинарь release) — 135 мкс, прочитанный из `/metrics` этого Pod'а; это одно наблюдение, снятое руками и не держимое ни одним гейтом, а не p99, и p99 из него не выводится. Чего это число **не** покрывает: сокет, TLS-рукопожатие, очередь apiserver и сеть — то есть то, что видит `kubectl apply`, больше, и этим деревом не меряно ничем | U | U `latency_gate.rs::the_p99_of_a_review_stays_inside_the_declared_latency_budget` · U `Jenkinsfile::Security: admission latency` |
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
| `DEG_LABELS_UNKNOWN` — неразрешённые label: правила применены fail-closed; вечно-истинной эта причина быть больше не может — ветку кластера снял запрет `clusterSelector` при компиляции, ветку namespace/ServiceAccount гасит список, который доехал | U | U `ferrum-agent/src/lib.rs::unobserved_namespace_labels_do_not_skip_a_rule` · U `ferrum-policy/src/lib.rs::a_cluster_selector_is_refused_on_both_kinds` · U `ferrum-compiler/src/lib.rs::a_cluster_selector_does_not_compile` |
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
| `DEG_BUNDLE_UNREADABLE` — bundle-mount на месте и не stat-ится: политика не может доехать, и при этом ни один bundle не был отвергнут | U | U `ferrum-agent/src/lib.rs::a_bundle_mount_that_cannot_be_stat_ed_is_not_a_bundle_that_has_not_changed` |
| `DEG_CLOCK_ROLLBACK` — часы узла ушли назад под монотонный пол: срок каждого waiver считается по источнику времени, которому нельзя верить | U | U `ferrum-agent/src/lib.rs::clock_rollback_keeps_an_expired_waiver_expired` |
| `DEG_CLOCK_FLOOR_UNPERSISTED` — монотонный пол не пишется на диск: защита от отката часов живёт только до рестарта | U | U `ferrum-agent/src/lib.rs::a_clock_floor_that_cannot_be_written_is_a_reason` |

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

### Инвентарь субъектов

Не перепись. Каждое перечисление в этом дереве — скан по префиксу `DEG_`,
скан тела `degraded_reasons_at`, скан аргументов `mark_terminal_fault`,
перепись счётчиков, `status.json` и таблица деградаций выше — идёт по
`ferrum_agent::Agent`. У двух из трёх поставляемых бинарей нет ни
`is_degraded()`, ни списка причин, ни поверхности статуса, поэтому попасть в
любое из этих перечислений — в любую сторону — они не могут **по построению**.
Перепись по списку, которого нет, полна пусто: это самое опасное состояние
гейта, зелёное потому, что проверять нечего, и неотличимое от зелёного потому,
что всё сходится.

Завести `is_degraded()` у webhook, чтобы перепись стала возможной, было бы
хуже дыры: это создало бы список причин, которому этому процессу негде
публиковаться. Цикл 10 отказался ровно от этого хода, когда не стал привязывать
`COUNTERS_WITHOUT_A_REASON` к этому документу. Поэтому здесь инвентарь: по
строке на поставляемый бинарь, и ровно один канал в каждой — тот, по которому
оператор узнаёт, что этот субъект сломан.

Держат его три утверждения, а не скан: у каждого субъекта ровно один канал,
канал достижим (строка цитирует то, что исполнялось), и канал несёт причину, а
не константу — в единственной форме, которая решаема по дереву: ни один субъект
не держит право записи в `<kind>/status`, которого ничто в нём не пишет.

Третье утверждение идёт по всем трём субъектам, и цикл до этого шло по одному:
оно читало `deploy/controller/rbac.yaml` по имени и список ресурсов `ferrum.io`,
поэтому `ferrum-agent` и `ferrum-admission` его проходили ровно потому, что
назвать их в том цикле было нечем, — «зелёное, потому что проверять нечего», два
субъекта из трёх, внутри теста, docstring которого об этом же и написан. Теперь
путь идёт от `serviceAccountName` в pod spec к биндингам, от биндингов к
правилам, и грант, добавленный агенту или webhook, видит то же правило, что
видит грант контроллера. «Пишет» тоже перестало быть подстрокой: нужна ручка,
которой запись делается — `GroupVersionKind::gvk(…, "Kind")` плюс вызов
`patch_status`, — а не имя типа статуса в сигнатуре.

| Субъект | Канал | Метка | Исполняется |
|---|---|---|---|
| `ferrum-agent` | `status.json` и флаг `degraded` в конверте экспорта | U | U `ferrum-agent/src/lib.rs::the_poll_tick_publishes_a_whole_status_file_and_logs_transitions` · U `ferrum-agent/src/lib.rs::a_failed_status_write_removes_the_file_rather_than_leave_it_lying` · U `ferrum-agent/src/lib.rs::a_degraded_node_that_changes_why_says_so` |
| `ferrum-admission` | текст `message` в отказе — то, что видит человек, запустивший `kubectl` | U | U `webhook.rs::a_warm_watch_decides_and_a_cold_one_denies_with_the_cold_reason` · U `webhook.rs::unsigned_image_deny` |
| `ferrum-controller` | `status.json` в `--status-dir` плюс код выхода: до входа в watch — `error: <причина>` и выход 1; после — счётчик и причина на класс отказа в файле, а всплеск отказов одного класса без единого успеха завершает процесс | U | U `ferrum-controller/src/main.rs::a_flag_is_never_taken_as_the_value_of_the_flag_before_it` · U `health.rs::a_failure_run_is_a_burst_and_not_a_lifetime` · U `health.rs::the_file_written_after_a_failed_publish_says_the_publish_failed` · U `health.rs::a_single_failed_event_is_counted_and_the_process_keeps_running` · U `health.rs::a_run_of_status_patch_failures_with_no_success_is_terminal_and_names_the_class` · U `health.rs::a_class_that_succeeded_once_does_not_go_terminal_on_a_later_burst` · U `health.rs::the_status_file_is_written_whole_and_a_failed_write_is_its_own_reason` · U `ferrum-controller/src/watch.rs::a_reconcile_that_published_nothing_marks_no_class_as_having_worked` · U `apply.rs::a_publish_pass_over_no_secret_requests_nothing` · U `ferrum-controller/src/main.rs::the_status_dir_the_manifest_passes_is_the_one_the_watch_config_carries` · U `boundary_gate.rs::the_controllers_channel_names_every_post_start_failure_class` |

Строка контроллера — единственная, которая до этого цикла не проходила третье
утверждение, и не тем каналом, который в ней стоял: `deploy/controller/rbac.yaml`
выдавал право записи в `ferrumclusters/status`, а `FerrumCluster` не назван ни
в одном файле контроллера. Починок было две — дать `.degraded` первого писателя
или удалить грант. Удалён грант, и вместе с ним ещё два той же формы
(`policylibraries/status`, `compliancesnapshots/status`): писатель — это не
функция, а клиент к API server, которого в этом workspace не было никогда (см.
«Ничто и никогда не обращалось к API server» ниже), а грант, которым никто не
пользуется, — право без назначения, то есть цель бокового движения по threat
model этого проекта. То же самое и той же формы — `runtimeprofiles/status`:
он пережил ту прополку, потому что правило спрашивало, назван ли *тип статуса*
где-нибудь в crate, а `pub fn runtime_profile_status(…) -> RuntimeProfileStatus`
его называл. Правило стало спрашивать про ручку, которая нужна записи
(`GroupVersionKind::gvk(…, "Kind")` плюс `patch_status`), и грант удалён — та же
починка по той же причине.

**Перепись грантов теперь читает все глаголы, а не только пишущие.** Пока она
спрашивала про `<kind>/status` и `create/update/patch/delete`, грант
`get/list/watch` на `ferrum.io`-ресурс не решался ничем и ни в какую сторону —
то же самое «зелёное, потому что проверять нечего», от которого этот тест
уходил в прошлом цикле, только этажом ниже. Таких грантов у контроллера было
четыре: `runtimeprofiles`, `ferrumclusters`, `compliancesnapshots`,
`policylibraries`. Ни для одного из этих Kind в `crates/ferrum-controller/src`
нет литерала `GroupVersionKind::gvk`, значит нет `ApiResource`, значит нет
`Api<DynamicObject>`, значит ни `get`, ни `list`, ни `watch` этот бинарь по ним
никогда не выполнял и выполнить не мог. Читающий грант не бесплатен дважды: это
право без назначения — цель бокового движения, — и это ложное утверждение о
системе, потому что RBAC и есть место, где оператор читает, за чем контроллер
следит. Все четыре удалены; правило держит
`boundary_gate.rs::a_granted_resource_no_subject_can_reach_is_a_permission_with_no_purpose`,
и в этом цикле у него закрыты два обхода, каждый из которых восстанавливал
предмет находки целиком. Первый: перепись шла от `image:` к
`serviceAccountName` того же pod spec, поэтому биндинг на любой другой
ServiceAccount не разрешался ни в одно правило — `ClusterRole` с теми самыми
четырьмя ресурсами и пишущими глаголами, привязанный к
`ServiceAccount/ferrum-controller-ops`, проходил все наборы этого crate и
`lint-deploy`. Теперь каждый субъект биндинга обязан быть аккаунтом, под
которым что-то запускается: грант субъекту, которого никто не запускает, — то
же право без назначения, только ещё и невидимое для переписи. Второй: читались
все `.rs` под `crates/<субъект>/src`, включая `#[cfg(test)]`, так что один
юнит-тест с литералом `gvk` воскрешал читающий грант на Kind, которого в
поставляемом бинаре нет. Читается поставляемая половина файла — до первой
строки `#[cfg(test)]`, — и то же правило теперь применяется к
`the_controllers_channel_names_every_post_start_failure_class`, который до
этого цикла засчитывал `note_failure` из тестового модуля `watch.rs` за
отчётность реконсайл-пути.
и оно ограничено группой `ferrum.io` намеренно: ядровые ресурсы (`pods`,
`secrets`, `nodes`) адресуются типами `k8s-openapi` без единого `gvk`, так что
тот же вопрос объявил бы мёртвым каждый из них. Неиспользуемый ядровой грант —
настоящая находка, но не этим инструментом.

Той же правкой удалены `retain_policy_mode` и `runtime_profile_status`: обе
принимали спеку RuntimeProfile, игнорировали её и возвращали константу, обе
вызывались из `reconcile` на каждом проходе, и единственный читатель результата
второй — поле, которое смотрели два юнит-теста. Вместе с ними ушли вход
`runtime_profile` и выход `profile_status`, так что «RuntimeProfile не поднимает
режим политики» — теперь свойство типа, который контроллер согласует, а не
функции, которую можно отредактировать до обратного.

Строка контроллера в прошлом цикле называла одну половину канала целым.
`код выхода и error: <причина>` было верно ровно для отказов **до** входа в
watch: их возвращает `run()`, `main` печатает и выходит с 1, и цитируемый
argv-тест — про этот путь. После старта процесс — три `tokio::select!`-нутых
цикла watch; `kube::runtime::watcher` переспрашивает сам и не завершается,
поэтому каждый отказ, ради которого канал и нужен — не сошедшийся reconcile,
403 на PATCH статуса (ровно то, что даёт криво отредактированный RBAC), ошибка
watch, отказ публикации подписанных exception, — был одним `eprintln!` и
следующим витком. Ни счётчика, ни файла, ни кода выхода: субъект, у которого
нет ни `is_degraded()`, ни списка причин, а значит, ни одна перепись этого
дерева по нему не шла и вакуумно проходила.

**Это и есть то, что закрыто здесь.** `crates/ferrum-controller/src/health.rs`
— форма агентовская намеренно: счётчик на класс отказа
(`reconcile_failures`, `status_patch_failures`, `watch_errors`,
`exception_publish_failures`), прогон подряд и «был ли хоть один успех» на
каждый, `degraded_reasons()`, пустота которого и есть `is_degraded()`, и
`status.json`, публикуемый в `--status-dir` атомарной заменой через временный
файл. Класс отказа определяется местом вызова, а не текстом ошибки: разбор
сообщений — ровно тот дефект, который это дерево удаляет цикл за циклом.
Манифест даёт под это `emptyDir` на `/run/ferrum` и сохраняет
`readOnlyRootFilesystem: true`; ни одного probe на этот файл нет и быть не
может — restart на восстановимой деградации есть crash-loop, а на
невосстановимой — бесконечный цикл, который не живёт достаточно долго, чтобы
сказать почему.

Терминальное правило одно и узкое: прогон в `TERMINAL_RUN` отказов **одного
класса**, пришедших не реже чем раз в `TERMINAL_WINDOW`, в котором ни один
запрос этого класса **ни разу** не прошёл, возвращает `Err` из `run_watch` — дальше это обычный путь `main`: `error:
<причина>` и выход 1. Оба условия обязательны. Один 403 на одном объекте —
плохой объект, и процесс, который на нём уходит, и есть тот crash-loop, от
которого отказался статус агента; класс, в котором не работало **ничего**, —
это не объект, а деплой (криво отредактированный RBAC, неприменённая CRD), и
процесс, который логирует это вечно, выглядит здоровым и для Kubernetes, и для
любой панели над ним. «Ни одного успеха в этом классе» — вся защита целиком,
поэтому классы разделены по вызову, а не по слову: `status_patch` — это
запрос, который **ничем, кроме PATCH статуса, не был**: статус
PolicyException и статус политики, у плана которой нет Secret.

**И поэтому же успех класса теперь нельзя объявить, не сделав запроса.** Вся
защита стоит на флаге «хоть раз прошло», флаг необратим — а ставили его три
места, где вызов не обращался к API server ни разу. `attach_exceptions` на
плане без Secret выходит первым же `return` (план без Secret — это любая
политика с провалившейся компиляцией), `persist_exceptions` на свежей
установке не находит ни одного bundle-Secret и не патчит ничего, и оба
возвращали `Ok(())`, после которого вызыватель писал `note_success`. Одной
такой политики хватало, чтобы `exception_publish` больше никогда не дошёл до
терминального правила: тысяча отказов подряд после этого — тысяча `Ok`.
Правило, которое авторы знали, в том же файле было записано ровно один раз —
ветка «объект уже сошёлся» успеха не засчитывает, потому что запроса не было.

Теперь оно записано типом, а не дисциплиной. `note_success` принимает не
класс, а `Requested` — расписку, которую возвращает тот код, который запрос и
делал: `persist_dynamic`, `patch_status_dynamic`, `patch_secret_exceptions`,
`persist_exceptions` (по факту пропатченных Secret, а не по факту вызова).
Функция, которая не обратилась ни к чему, возвращать может только
`Requested::NONE`, а место вызова расписку выдумать не может — единственное
исключение названо в коде и в гейте: класс `watch`, чей запрос — сам watch, и
чей ответ — пришедшее событие. Заодно исчезла вторая половина того же дефекта:
запись статуса «compile failed» засчитывалась в `reconcile`, потому что успех
и отказ одного и того же вызова классифицировались по-разному. Класс у него
один — `apply.rs::persist_class`, — и читают его теперь оба направления.

Чего эта правка не делает. PATCH статуса политики, у плана которой Secret
есть, идёт одним вызовом с upsert этого Secret и потому считается в
`reconcile`, а не в `status_patch` — **в обе стороны и на любом кластере, где
политики компилируются**. Прежняя формулировка этого абзаца соседствовала с
утверждением, что мис-RBAC попадает в `status_patch` «на каждом объекте,
которого касается»; верно первое. На установке, где компиляция проходит, 403
на PATCH статуса политики приходит в `reconcile`, и `status_patch` остаётся
классом статусов PolicyException и политик с провалившейся компиляцией.
Терминальное правило от этого не страдает — оно сработает через `reconcile`, —
а диагностика страдает наполовину: заголовок скажет «reconcile», но причина в
том же сообщении и в `status.json` — это дословный текст запроса, `status
patch <имя>: 403 Forbidden`. Разносить upsert и PATCH на два независимо
считаемых запроса ради счётчика этот цикл не стал намеренно: один вызов — один
класс, а разнесённый upsert, у которого PATCH не прошёл, — это объект, чей
Secret обновлён, а статус нет, то есть частично применённое состояние, которое
пришлось бы либо откатывать, либо объявлять успехом в одном классе и отказом в
другом. `status.json` живёт ровно столько, сколько под, и о том, что было
между запусками, не сообщает ничего. И `Jenkinsfile` этот файл ни в одной
стадии не читает: всё, что здесь стоит `U`, прогнано на этом дереве руками,
как и всюду в этом документе.

**У той же расписки есть обратная сторона, и она стреляла по здоровому
процессу.** Требование «успех — только там, где был запрос» верно, а места, где
запрос *был*, оказались не размечены, и терминальное правило стало вероятнее
убить работающий контроллер, чем поймать сломанный RBAC. Три штуки, все
измерены против stub-apiserver, а не рассуждением:

- `persist_exceptions` выходила из цикла патчей первым же `?`, выбрасывая
  расписку по Secret'ам, которые уже пропатчила. Один Secret, отказывающий
  постоянно (413 на разросшемся списке, повторяющийся конфликт), — и класс, в
  котором публикация работает на всех остальных Secret, выглядит классом, где
  не работало ничего. Теперь пасс идёт до конца, отказ каждого Secret
  считается отдельно, а исключения доезжают до всех Secret, кроме сломанного.
- Сошедшийся объект возвращал `Ok(())`, не засчитав GET, которым он и решил,
  что сошёлся. На кластере в установившемся режиме — где сошлись все объекты —
  `reconcile.ever_ok` был ложен всю жизнь процесса. Расписку теперь отдаёт
  `load_bundle_secret`, то есть тот код, который запрос и сделал. Цена названа:
  этот GET — полноценный запрос класса `reconcile` (его отказ туда же и
  считается), поэтому установка, где `get secrets` разрешён, а PATCH статуса
  политики — нет, до терминального правила по `reconcile` больше не доходит.
  Симметрия здесь обязательна: класс, в котором отказ считают, а успех нет, —
  это ровно тот перекос, из-за которого правило и стреляло не туда.
- Secret с меткой владельца и без метки политики считался отказом
  `exception_publish` на **каждом** событии, а пасс, который его нашёл, ничего
  не патчил и расписки не давал. Прогон такого рода неограничен по построению:
  объект неисправен, пока его не починит человек, и десятое событие завершало
  процесс. Это причина (`note_unactionable`: список в `status.json`, строка в
  `degraded_reasons()`, самозатухающая на первом пассе, который его больше не
  видит) и никогда не прогон.

И сам прогон получил окно. «Десять подряд, и между ними ничего не прошло» без
часов означает «десятый из них, когда бы он ни пришёл»: у класса, которому
нечем поставить `ever_ok` — `exception_publish` на установке без единого
bundle-Secret ровно таков, — десять транзиентных ошибок за день завершали
процесс. `TERMINAL_WINDOW` = 580 с и выбран не за круглость: watch этого
бинаря уходит с `timeoutSeconds=290` (`kube-core`, `WatchParams`), после чего
watcher релистит и передаёт **каждый** объект заново, — значит деплойный (а не
объектный) отказ перезаваливается не реже чем раз в 290 с даже на кластере,
где ничего не редактируют и политика одна. Удвоение — запас на сам релист:
список идёт не мгновенно и может быть повторён, а один медленный релист не
должен рвать прогон. Десять отказов по-прежнему обязаны уложиться примерно в
десять минут, а не в сутки.

**Молчаливых веток в этом цикле стало на одну меньше.** `Event::Deleted`
объекта без `namespace`/`name` не удалял исключение из набора — ни класса, ни
строки: отозванный exception продолжал подписываться в Secret и раздаваться
агентам, то есть fail-open в единственном направлении, где он запрещён. Набор
ключуется `namespace/name`, применить такое удаление к нему нечем; теперь это
отказ класса `reconcile` со строкой, называющей, что именно осталось живым, —
та же трактовка, которую тот же файл уже давал тому же дефекту в
`apply_exception_object`. Так же перестали быть молчаливыми Secret с нашей
меткой `managed-by`, которым `persist_exceptions` не может отскопировать
список (нет имени или нет метки `ferrum.io/policy`): пропустить такой Secret
по-прежнему правильно — общий список расширил бы каждое исключение в нём, — но
пропускается он теперь с отказом класса `exception_publish`, а не с `Ok`.

Чего инвентарь не делает: он не утверждает, что канал субъекта достаточен.
У webhook нет ни последнего-известного-хорошего, ни списка причин; у
контроллера канал существует ровно на время процесса и ничего не сообщает о
том, что происходит между запусками. Строка «одна» здесь — это про то, что
канал один и он назван, а не про то, что его хватает.

### Гейты этого дерева

Каждый `#[test]` в `crates/ferrum-testkit/tests`, `crates/ferrum-agent/tests`,
`crates/ferrum-admission/tests` и `crates/ferrum-ebpf/tests` обязан стоять в
какой-то строке этого
документа. Это обратное направление гейта: раньше он требовал, чтобы
процитированное существовало, и не мог потребовать, чтобы существующее было
процитировано, — то направление, в котором документ гниёт молча. Оно закрыто
только для этих четырёх каталогов, и это не произвол: в них нет ничего, кроме
гейтов и приёмки, поэтому каждый тест там — утверждение о продукте, а не о
функции. Тридцать пять тестов были не процитированы в момент, когда гейт
написали; ниже — строки, которыми на них ответили.

Каталог `ferrum-admission/tests` вошёл сюда циклом позже остальных, и его
отсутствие было той же дырой, что гейт закрывает: обоснование «в них нет
ничего, кроме гейтов» держалось для него ровно так же, а семьдесят два теста —
включая три из восьми случаев §D, четыре теста кеша меток и три теста
`MountStat`, — не были видны обратному направлению вообще. Одна строка в
`CITED_TEST_DIRS`; строки ниже — то, чем за неё заплачено.

Каталог `ferrum-ebpf/tests` вошёл последним, и его отсутствие было самым
громким из трёх. Там лежит `attach_live.rs` — файл, несущий почти каждую метку
`K` в этом документе, то есть ровно тот каталог, чьи тесты дороже всего
переисполнить, был тем, которого обратное направление не видело. Процитирован
он оказался целиком, но по прилежанию тех, кто писал строки, а не потому, что
что-то покраснело бы иначе; разница между этими двумя основаниями и есть весь
смысл гейта. Соседний `elf_inspect.rs` прилежания не получил: пять тестов о
том, что поставляемый BPF-объект несёт программы и ABI карт, которые связывает
loader, не были названы ни одной строкой, а единственная строка про этот объект
цитировала стадию CI — то есть утверждала лишь, что стадия с таким именем есть
в файле. Шестым нашёлся `a_path_this_kernel_could_not_read_is_never_reported_as_a_short_one`:
находка прошлого цикла, разобранная абзацем в «Как читать колонку
„Исполняется“» и не имевшая строки в «Делает» — проза, которую тот же гейт
правилом `prose_is_not_evidence` доказательством не считает.

| Утверждение | Метка | Исполняется |
|---|---|---|
| Набор §D закрыт с обеих сторон: случай нельзя уронить, оставив его без приёмочного теста или без сценария реплея | U | U `acceptance.rs::every_acceptance_case_has_a_test` · U `replay.rs::every_runtime_acceptance_case_has_a_replay_scenario` |
| Случай §D нельзя уронить из кластерного гейта, промолчав: покрытые и непокрытые вместе обязаны быть ровно `AcceptanceCase::ALL`, и у каждого непокрытого — причина | U | U `e2e_cluster.rs::the_uncovered_cases_are_named_not_omitted` |
| Кластерный гейт нельзя обезвредить, собрав его без фичи: `FERRUM_E2E_REQUIRED` на сборке без `--features e2e` — отказ, а не пустой зелёный прогон | U | U `e2e_cluster.rs::the_cluster_gate_must_not_be_compiled_out` |
| Поставляемые CRD устанавливаются в настоящий apiserver: правило схемы, которое apiserver отвергает, делает инертным весь файл, и текстовый гейт этого не видит | A | A `e2e_cluster.rs::the_shipped_crds_are_accepted_by_a_real_apiserver` |
| Установка по умолчанию поднимается на кластере, который FERRUM никогда не видел: `kubectl apply -k deploy` принят apiserver целиком, CRD доходят до `Established`, оба Deployment — до Ready, и повторный apply тоже принят | A | A `install_gate.rs::the_default_install_comes_up_on_a_fresh_cluster` |
| Корень агента apiserver принимает: то, что его Pod не стартует на kind, — свойство узла (нет bpffs на `/sys/fs/bpf`), а не манифестов | A | A `install_gate.rs::the_agent_root_is_accepted_by_a_real_apiserver` |
| Гейт устанавливаемости нельзя обезвредить, собрав его без фичи: `FERRUM_INSTALL_REQUIRED` на сборке без `--features e2e` — отказ, а не пустой зелёный прогон | U | U `install_gate.rs::the_install_gate_must_not_be_compiled_out` |
| Объект уровня кластера доезжает до вебхука и решается политикой, а не кешем меток: `ClusterRoleBinding`, которого политика не запрещает, apiserver создаёт, а bind на `cluster-admin` тот же вебхук отвергает с `cluster-admin bind`. Обе половины нужны: вебхук, разрешающий всё, проходит первую, отвергающий всё — вторую. `namespaceSelector` вебхука здесь ни при чём и это тоже часть утверждения — apiserver к ресурсам уровня кластера его не применяет | A | A `e2e_cluster.rs::a_cluster_scoped_object_reaches_the_webhook_and_is_decided_by_the_policy` |
| Бюджет прерываний исполняется настоящим apiserver, а не только читается в манифесте: eviction первой реплики вебхука принят, второй — отвергнут по disruption budget. Первая половина не уборка: без неё вторая проходила бы и на бюджете, который отказывает всем, а это повисший навсегда `kubectl drain` | A | A `e2e_cluster.rs::the_second_eviction_of_the_webhook_pair_is_refused_by_the_disruption_budget` |
| Манифест `deploy/`, который не ставит ни один корень kustomize, либо назван неустанавливаемым с причиной, либо роняет гейт: иначе получатель просто не получает объект | U | U `deploy_gate.rs::every_manifest_in_the_deploy_tree_is_installed_by_a_root_or_excused` |
| Корень `docs/crd` ставит каждый поставляемый CRD, а не те, что вспомнили: не установленный CRD — тип, которого apiserver не знает | U | U `deploy_gate.rs::the_crd_kustomization_installs_every_crd_this_repository_ships` |
| Ни один корень kustomize не тянет respond (`hostPID` + `CAP_KILL`) и ни один — нерендеренный вебхук с заглушкой `caBundle` под `failurePolicy: Fail`; `secretGenerator` запрещён во всех | U | U `deploy_gate.rs::no_kustomization_root_installs_the_respond_variant_or_the_unrendered_webhook` |
| Умолчания установки — restricted, а не удобные: `runAsNonRoot`, `RuntimeDefault`, `readOnlyRootFilesystem`, `drop: [ALL]` без единого `add`, без host-namespace, `--policy-name prod-restricted`, вебхук в двух репликах | U | U `deploy_gate.rs::the_default_install_is_the_restricted_one` |
| Overlay зеркала меняет имена образов и ничего кроме: ни второго пина тега, ни ключа, которого не читает ни один гейт этого дерева | U | U `deploy_gate.rs::the_mirrored_overlay_changes_image_names_and_nothing_else` |
| Overlay зеркала переносит установку в тот реестр, который разрешает поставляемая `prod-restricted`, — а установка по умолчанию стоит вне него | U | U `deploy_gate.rs::the_mirrored_overlay_moves_the_install_into_the_registry_the_shipped_policy_allows` |
| Шаг публичного воркфлоу либо зеркалит одноимённую стадию `Jenkinsfile`, либо назван таким, у которого близнеца нет и не должно быть | U | U `deploy_gate.rs::every_step_here_is_mirrored_or_named_as_workflow_only` |
| Каждый runtime-случай §D переигрывается из записанных байтов на обеих arch | U | U `replay.rs::runtime_acceptance_cases_replay_from_recorded_bytes` |
| Освобождает агента от реакции на собственный `bpf()` флаг записи, а не строка `comm`: workload, назвавшийся `ferrum-agent`, освобождения не получает | U | U `replay.rs::agent_self_bpf_is_neither_denied_nor_signalled` |
| Bundle с действием, которого runtime-плоскость не исполняет, грузится, и каждый матч экспортируется как неисполненное решение с причиной; `defaultAction: deny` тоже грузится | U | U `replay.rs::a_pre_gate_deny_bundle_loads_and_every_match_is_recorded` · U `action_gate.rs::a_signed_deny_default_still_installs` |
| Хост-процесс, не помеченный контейнерным, мимо индекса cgroup — не деградация, а контейнерный — деградация | U | U `replay.rs::a_host_process_missing_from_the_index_is_not_a_degradation` · U `replay.rs::a_cgroup_missing_from_the_index_is_counted_and_degrades` |
| Незнакомый syscall nr и битые записи считаются, деградируют узел и не останавливают цикл enforcement | U | U `replay.rs::an_unknown_syscall_nr_degrades_the_agent_without_stopping_the_loop` · U `replay.rs::corrupt_records_are_counted_and_the_loop_keeps_enforcing` |
| Кодировщик bundle принимает ровно то, что принимает `ferrum-policy`, в обе стороны, и оба enum действий — одно множество | U | U `action_gate.rs::the_encoder_accepts_exactly_what_ferrum_policy_accepts` · U `action_gate.rs::the_two_action_enums_are_the_same_set` |
| Loader отвергает kill-all и на живом пути, и на восстановлении LKG, и отказ не стирает уже работающую политику | U | U `action_gate.rs::the_loader_refuses_every_kill_all_and_keeps_the_inert_deny` · U `action_gate.rs::a_kill_all_default_refuses_the_snapshot_on_the_restore_path_too` · U `action_gate.rs::a_signed_kill_all_default_does_not_install_and_keeps_last_known_good` |
| Self-approve waiver отвергают и CEL, и `ferrum-policy` | U | U `deploy_gate.rs::self_approve_is_rejected_in_cel_and_in_policy` |
| Панель дашборда не может спрашивать метрику, которой не отдаёт ни один бинарь: множество экспортируемых семейств берётся прогоном самих рендеров, а не списком | U | U `metrics_gate.rs::every_metric_this_dashboard_charts_is_one_the_binaries_export` |
| Обратное направление: семейство, которое экспортируется и не попало ни на одну панель, либо названо в `NOT_CHARTED` с причиной, либо роняет гейт — счётчик без читателя это ровно тот дефект, от которого вся задача | U | U `metrics_gate.rs::every_exported_family_is_charted_or_named_as_not_charted` |
| Контроль на сам разбор дашборда: переименованная метрика обязана быть падением, иначе оба направления выше проходят на пустом множестве | U | U `metrics_gate.rs::the_dashboard_scan_notices_a_renamed_metric` |
| Внутрикернельный счётчик потерь выведен наружу тем же значением, а не заведён вторым, и обход `status.json` не оставил ни одного ключа без метрики (`status_keys_unmapped` = 0) | U | U `metrics_gate.rs::the_agent_publishes_the_in_kernel_drop_counter_it_already_had` |
| Скрейп не съедает строку перехода в Degraded: рендер читает `degraded_snapshot_at`, и защёлка достаётся поллеру, а не тому, кто пришёл за метриками | U | U `metrics_gate.rs::a_scrape_does_not_consume_the_degraded_transition` |
| У каждой причины деградации, которую агент может поднять, есть стабильный короткий id для метки — по тем же трём сканам, что и в `boundary_gate.rs`, — и все id публикуются на каждом скрейпе, включая нулевые | U | U `metrics_gate.rs::every_degradation_reason_the_agent_can_raise_has_a_stable_metric_id` |
| Порт метрик открыт поставляемыми манифестами, назван, находим Service'ом и закрыт NetworkPolicy, которая при этом заново разрешает 8443: иначе это либо код, которого никто не собирает, либо неаутентифицированное чтение здоровья enforcement из любого Pod'а | U | U `metrics_gate.rs::the_shipped_manifests_open_and_govern_every_metrics_port` |
| Эндпоинт исполнен на настоящем сокете: `GET /metrics` отдаёт экспозицию, `POST` — 405 и тела не читает, другой путь — 404 | U | U `metrics_gate.rs::the_metrics_endpoint_answers_a_read_and_refuses_everything_else` |
| Записи, выпущенные прошлыми версиями схемы, декодируются этой сборкой: замороженные строки лежат в дереве и разбираются настоящим типом, а не описанием совместимости | U | U `event_contract_gate.rs::every_record_a_released_version_wrote_is_still_readable_by_this_build` |
| Форма записи, которую пишет эта сборка, — та, что заморожена для заявленной версии, и каждая прошлая версия того же major является её подмножеством без изменений типа, обязательности и nullable; инвентарь выводится сериализацией самого типа, а не списком | U | U `event_contract_gate.rs::this_builds_record_shape_is_the_one_frozen_for_the_version_it_claims` |
| Контроль на сам вывод инвентаря: удалённое и переименованное по типу поле обязаны быть падением, иначе сверка выше проходит на выводе, который всегда одинаков | U | U `event_contract_gate.rs::the_inventory_derivation_notices_a_removed_and_a_retyped_field` |
| У каждого листа экспортируемой записи есть написанное решение, уходит он в чужую систему или нет; поле без решения роняет сборку, а заявленная необязательность проверена декодированием записи без него | U | U `event_contract_gate.rs::every_field_that_leaves_this_product_has_a_written_disposition` |
| Withheld-поле (два человеческих имени с waiver'а) отсутствует во всех трёх профилях по значению, а не по имени ключа; контроль — тикет того же waiver'а в записи присутствует | U | U `event_contract_gate.rs::a_withheld_field_appears_in_no_profile` |
| Каждое значение, объявленное уходящим наружу, доезжает до каждого профиля: строки и числа — по значению-сентинелу, булевы — переворотом одного флага, и булево без такой пробы роняет гейт | U | U `event_contract_gate.rs::every_emitted_value_reaches_every_profile` |
| Враждебная нагрузка не подделывает запись: `comm` с переводом строки и `pod` с `"`/`]`/`[` не порождают ни второй записи, ни второго CEF-заголовка, ни второго SD-элемента, ни сломанного JSON — проверено разбором, а не подсчётом подстрок | U | U `event_contract_gate.rs::a_hostile_workload_cannot_forge_a_record_in_any_profile` |
| Приёмка §D «`exec` + `/bin/sh` → kill» доезжает до локального приёмника через поставляемую цепочку стоков (`QueueSink` → `FanoutSink` → файл + `SyslogSink`), и запись на узле и запись в приёмнике несут одну временную метку | U | U `event_contract_gate.rs::an_enforcement_decision_reaches_a_local_receiver_through_the_shipped_sink_chain` |
| Недоступный SIEM учтён существующим `export_write_failed_total` и деградирует узел `DEG_EXPORT_LOSSY`; второго счётчика не заведено | U | U `event_contract_gate.rs::an_unreachable_siem_is_counted_by_the_existing_export_loss_and_degrades_the_node` |
| Сток подключён в поставке: `overlays/siem-syslog` патчит корень агента флагами, которые бинарь действительно читает, значениями, которые его же парсеры принимают, и установка по умолчанию до него не дотягивается | U | U `event_contract_gate.rs::the_shipped_overlay_configures_the_sink_with_flags_the_binary_parses` |
| Второй апрувер обязателен независимо от `fourEyes`, а минимальная длина `reason` в схеме — константа компилятора | U | U `deploy_gate.rs::a_waiver_without_a_second_approver_is_refused_by_the_schema_too` · U `deploy_gate.rs::the_minimum_reason_length_is_the_same_in_the_schema_and_in_policy` |
| Пустой и дублированный id правила отвергает и схема: id — то, что waiver освобождает, а audit-запись обвиняет | U | U `deploy_gate.rs::a_blank_or_duplicated_rule_id_is_refused_by_the_schema_too` |
| Границы длин `commIn`/`pathPrefix`/`pathSuffix` в схеме — границы datapath | U | U `deploy_gate.rs::the_match_length_bounds_in_the_schema_are_the_datapath_bounds` |
| Ключ trust root, не являющийся 64 hex-символами Ed25519, отвергает и схема | U | U `deploy_gate.rs::a_public_key_that_is_not_ed25519_hex_is_refused_by_the_schema_too` |
| Все шесть §D-фикстур проходят инвариантную копию, и bpf-строка называет только те syscall, которые datapath действительно цепляет | U | U `deploy_gate.rs::acceptance_fixtures_agree_with_the_invariant_copy` |
| Поставляемое дерево проходит лит; плейсхолдер caBundle вне шаблона его роняет; выпущенный `gen-webhook-pki` PKI делает дерево применимым, а оставленный в нём `ca.key` — нет | U | U `deploy_gate.rs::deploy_tree_passes_the_lint` · U `deploy_gate.rs::a_committed_placeholder_ca_bundle_fails_the_lint` · U `deploy_gate.rs::issued_pki_makes_the_tree_applicable` |
| Каждый crate с бинарём линкуется стадией, которая выдаёт объектный код; `cargo clippy` доказательством не считается | U | U `deploy_gate.rs::every_crate_with_a_binary_is_linked_by_a_stage_that_emits_object_code` |
| Тег, который закрепляют манифесты, — тот, который релизный воркфлоу способен выпустить: он совпадает с фильтром тегов триггера, не плавающий и не `latest`, а `Jenkinsfile` по-прежнему не публикует, потому что его `dev-$BUILD_NUMBER` живёт в локальном сторе одной ноды. Про то, что образ опубликован, строка не говорит ничего | U | U `deploy_gate.rs::the_tag_the_manifests_pin_is_one_the_release_can_publish` · U `deploy_gate.rs::the_tag_filter_reader_accepts_and_refuses_the_right_tags` |
| Множество образов, которые публикует релиз, равно множеству, которое ставит `deploy/**`, и множеству, которое собирает `Jenkinsfile`: не подмножество, а равенство в обе стороны | U | U `deploy_gate.rs::the_release_publishes_exactly_the_images_this_tree_installs` |
| Каждый публикуемый образ подписывается и получает аттестованный SBOM, и всё это по digest, а не по тегу: подпись, привязанная к тегу, назавтра означала бы другой образ. Число SBOM в релизе равно числу образов, а не «сколько нашлось» | U | U `deploy_gate.rs::every_published_image_is_signed_and_carries_an_attested_sbom` |
| Подпись образа не заводит ключа: `id-token: write` есть, `--key`, `COSIGN_PRIVATE_KEY`, seed bundle и имена доменов `BUNDLE_SIGNATURE_CONTEXT`/`KEY_BIND_MSG` в релизном воркфлоу отсутствуют, и отсутствие проверено против настоящих имён из `ferrum-crypto`, а не против строки, которая могла бы быть опечаткой | U | U `deploy_gate.rs::the_release_signs_keyless_and_never_touches_the_bundle_signing_domain` |
| Ни один шаг релизного воркфлоу не может себя пропустить: ни `continue-on-error`, ни условие на шаге, ни подавление кода возврата. Шаг подписи, пропустивший себя, оставляет в реестре неподписанный образ под зелёным значком | U | U `deploy_gate.rs::no_step_in_the_release_workflow_can_skip_itself` |
| Процедура проверки, опубликованная получателю, — та же, которую релиз исполняет на себе: идентичность собирается из пути файла воркфлоу, издатель, тег и имена образов сверены на равенство. Переименованный воркфлоу роняет строку README, а не остаётся вопросом прилежания | U | U `deploy_gate.rs::the_documented_verification_is_the_one_the_release_performs` |
| Бинарь в каждом образе несёт список своих зависимостей: линкует `cargo auditable build` с закреплённой версией инструмента, и та же сборка проверяет получившийся файл на секцию `.dep-v0`. Без неё SBOM образа на `scratch` перечисляет ноль crate и читается как ответ на вопрос «что внутри» | U | U `deploy_gate.rs::every_shipped_binary_carries_the_dependency_list_its_sbom_is_made_of` |
| Флаг, который даёт только cargo feature, вкомпилирован в образ, которому манифест его передаёт | U | U `deploy_gate.rs::a_flag_only_a_feature_provides_is_built_into_the_image_that_is_passed_it` |
| Каждый non-default feature, который выбирает argv поставляемого манифеста, компилируется и как lint-таргет (`clippy --all-targets`), и как test-таргет: `cargo build` этого не засчитывает, потому что не компилирует ни одного тестового таргета, а `cargo tree` не компилирует вообще ничего | U | U `deploy_gate.rs::every_feature_a_manifest_selects_is_a_lint_and_test_target` · U `deploy_gate.rs::a_build_is_not_a_test_and_a_tree_is_not_a_compile` · U `Jenkinsfile::Clippy` · U `Jenkinsfile::Test` |
| То же утверждение, исполненное, а не прочитанное: гейт сам запускает `cargo clippy --features … --all-targets -- -D warnings` и `cargo test --features …` для каждой пары (crate, feature), которую выбирает поставляемый манифест, и требует успеха. Строка в Jenkinsfile присутствовала и была верна ровно в тот цикл, когда её таргеты не собирались | U | U `deploy_gate.rs::every_feature_a_manifest_selects_actually_compiles_and_passes` |
| Манифест не может объявить `optional: true` на томе, обслуживающем путь, без которого бинарь не стартует, — FD028, находка, а не предупреждение; том, который бинарь действительно терпит, находкой не является | U | U `lint_deploy.rs::a_required_mount_declared_optional_is_a_finding` · U `lint_deploy.rs::the_webhooks_bundle_mount_is_the_same_finding` · U `lint_deploy.rs::an_optional_serving_certificate_is_a_finding_too` · U `lint_deploy.rs::a_mount_the_binary_tolerates_may_be_optional` · U `lint_deploy.rs::a_file_is_served_by_the_longest_mount_that_covers_it` |
| Том, чей `defaultMode` недоступен `runAsUser` этого пода, — FD029, находка, а не предупреждение: kubelet пишет Secret-том root:root и меняет группу только под `fsGroup`, поэтому «аккуратный» 0400 под non-root — это ключ, который процесс не откроет; правило читает оба смысла литерала, потому что `0400` — это 256 для YAML 1.1, применяющего манифест, и вообще не число для 1.2, читающего его здесь | U | U `lint_deploy.rs::a_volume_mode_the_run_as_user_cannot_read_is_a_finding` · U `lint_deploy.rs::a_mode_is_readable_only_through_bits_the_uid_actually_gets` · U `lint_deploy.rs::deploy_tree_is_clean` |
| Первый `kube::Client` контроллера строится, а не паникует: провайдер rustls ставится до него, потому что `kube` ставит свой только под фичей `aws-lc-rs`, которой в этом дереве нет | U | U `ferrum-controller/src/watch.rs::the_process_has_a_crypto_provider_before_its_first_client` · U `ferrum-controller/src/watch.rs::a_converged_object_credits_the_get_it_made` |
| Прогон отказов, завершающий процесс, — всплеск, а не итог жизни процесса: отказ, пришедший позже `TERMINAL_WINDOW` после предыдущего, начинает прогон заново, а сломанный деплой, который перезаваливается раз в relist (290 с, `timeoutSeconds` каждого watch), правило по-прежнему завершает | U | U `health.rs::a_failure_run_is_a_burst_and_not_a_lifetime` |
| Объект, который нечем починить ни одним запросом, — причина в `status.json` и в `is_degraded()`, но никогда не прогон: Secret без метки политики виден на каждом событии, поэтому его прогон неограничен по построению | U | U `health.rs::an_unactionable_object_degrades_without_ending_the_process` · U `ferrum-controller/src/watch.rs::a_secret_that_cannot_be_scoped_is_a_reason_and_never_a_terminal_run` |
| Расписка переживает отказ соседнего Secret, а сошедшийся объект засчитывает GET, которым он и сошёлся: и то и другое измерено против stub-apiserver, а не смоделировано | U | U `ferrum-controller/src/watch.rs::one_secret_that_refuses_every_patch_does_not_end_a_controller_that_publishes` · U `ferrum-controller/src/watch.rs::a_converged_object_credits_the_get_it_made` |
| Неотскоупленный список исключений не публикуется ни одним из двух путей: `attach_exceptions` отказывает Secret без метки политики так же, как `exception_targets` его пропускает | U | U `ferrum-controller/src/watch.rs::attaching_to_an_unlabelled_secret_publishes_nothing` |
| Файл, записанный после неудавшейся публикации, несёт `statusWriteFailed: true` и `REASON_STATUS_UNWRITABLE`, а следующий за ним — уже нет | U | U `health.rs::the_file_written_after_a_failed_publish_says_the_publish_failed` |
| Неразрешённый селектор решает запись и не посылает сигнала: правило применено, совпадение экспортировано с `labels_unknown`, отказ назван `REFUSE_LABELS_UNKNOWN` и посчитан, `SIGKILL` не отправлен — а та же запись против наблюдённых меток убивает | U | U `ferrum-agent/src/lib.rs::an_unresolved_selector_decides_the_record_and_signals_nothing` |
| Каждая цитата «Делает» разрешается в определение `fn` или в стадию, а список §D здесь — ровно `AcceptanceCase::ALL` | U | U `boundary_gate.rs::every_claim_in_the_does_section_cites_something_that_exists` · U `boundary_gate.rs::the_document_lists_exactly_the_rfc_d_cases` |
| Каждая причина деградации, которую агент может объявить, названа здесь — по префиксу `DEG_`, по телу `degraded_reasons_at` и по аргументам `mark_terminal_fault` | U | U `boundary_gate.rs::every_degraded_reason_the_agent_can_raise_is_named_in_the_document` |
| Классы отказа контроллера перечисляются из тела `pub enum FailureClass`, а не из списка в самом гейте: у каждого варианта обязан быть аксессор счётчика, место в `ALL`, ключ в `status_json`, выведенный из `counter()`, и хотя бы одно место маршрутизации в `watch.rs`/`apply.rs`; успех класса нельзя назвать на месте вызова | U | U `boundary_gate.rs::the_controllers_channel_names_every_post_start_failure_class` |
| Обратное направление: каждый `#[test]` в `ferrum-testkit/tests`, `ferrum-agent/tests` и `ferrum-admission/tests` процитирован строкой или назван в списке исключений с причиной; само правило исключения проверено на входах, ответ на которых известен, а не только на пустом списке | U | U `boundary_gate.rs::every_gate_in_this_tree_is_cited_by_a_row` · U `boundary_gate.rs::a_test_is_found_under_its_attributes_and_a_plain_fn_is_not` · U `boundary_gate.rs::an_exemption_from_citation_is_named_one_at_a_time` |
| У каждого поставляемого бинаря ровно один канал отказа, он достижим и несёт причину, а не константу; перепись грантов читает и wildcard — `resources: ["*"]` с пишущим глаголом даёт каждый `<kind>/status` группы, а не ни одного | U | U `boundary_gate.rs::every_shipped_subject_has_one_reachable_channel_that_carries_a_cause` · U `boundary_gate.rs::a_wildcard_resource_grant_is_a_status_grant` |
| Грамматика ячейки закрыта: проза не доказательство, цитата разрешается в определение, а не в упоминание, прочерк — только у названного субъекта, а метка суммирует все цитаты строки | U | U `boundary_gate.rs::prose_is_not_evidence` · U `boundary_gate.rs::a_mention_of_a_test_is_not_a_definition_of_one` · U `boundary_gate.rs::only_a_named_subject_may_cite_nothing` · U `boundary_gate.rs::a_marker_summarises_every_citation_it_covers` |
| Решение admission зависит от режима, а не от находки: `enforce` отказывает, `observe` и `audit` пропускают тот же Pod и не роняют запрос | U | U `mvp.rs::privileged_enforce_denies` · U `mvp.rs::observe_mode_does_not_deny_privileged` · U `mvp.rs::audit_mode_does_not_deny_privileged` · U `mvp.rs::pss_restricted_observe_and_audit_do_not_fail_request` |
| Supply-часть отказывает неподписанному образу, тегу `latest` — явному и подразумеваемому, — пустому ожидаемому digest и `requireSigned` без ключей; парсер читает публичные ключи и после keyless-издателей | U | U `mvp.rs::unsigned_image_denies_when_deny_unsigned` · U `mvp.rs::latest_tag_denies_when_deny_latest_tag` · U `mvp.rs::implicit_latest_and_hostpid_and_caps_deny` · U `mvp.rs::empty_expected_digest_denies` · U `mvp.rs::require_signed_without_public_keys_denies_even_if_marked_signed` · U `mvp.rs::parser_reads_public_keys_after_keyless_issuers` |
| Совместимый Pod проходит и получает мутации, а не просто «не отказано»; подписанный `FRMB` и пара подпись+digest оцениваются как есть | U | U `mvp.rs::compliant_pod_allowed_with_mutations` · U `mvp.rs::valid_signature_and_digest_allow_compliant` · U `mvp.rs::signed_frmb_bundle_evaluates` |
| Bundle, который не проверяется, закрывает admission, а не открывает: битый, с чужим ABI, обрезанный, с лишними байтами, с плохой, пустой подписью и с несходящимся digest | U | U `mvp.rs::invalid_bundle_denies_fail_closed` · U `mvp.rs::abi_mismatch_denies_fail_closed` · U `mvp.rs::truncated_and_trailing_bytes_deny` · U `mvp.rs::bad_signature_denies_fail_closed` · U `mvp.rs::empty_signature_denies_fail_closed` · U `mvp.rs::digest_mismatch_denies_fail_closed` |
| Exception освобождает только в своём scope и до `expiresAt`: истёкший, с пустым target и namespaced против кластерного попадания не освобождают | U | U `mvp.rs::in_scope_exception_waives_privileged_before_expiry` · U `mvp.rs::expired_exception_does_not_waive` · U `mvp.rs::empty_target_exception_does_not_waive` · U `mvp.rs::namespaced_exception_does_not_waive_cluster_hit` |
| `failurePolicy: Ignore` — break-glass политики, а не обход целостности: namespaced не может им fail-open, кластерный не открывает им непроверенный bundle | U | U `mvp.rs::namespaced_ignore_does_not_fail_open` · U `mvp.rs::cluster_ignore_is_break_glass_not_integrity_bypass` |
| Bind `cluster-admin` отказывается на движке, а не только на HTTP-слое | U | U `mvp.rs::cluster_admin_bind_denies` |
| Промах селектора не применяет политику, а не применяет её мягче | U | U `mvp.rs::selector_miss_does_not_apply_policy` |
| Пустая PSS-политика — не пустое решение: `restricted` отказывает privileged, root, hostPath и capabilities, `baseline` — hostPID+hostPath и capabilities, `privileged` пропускает privileged | U | U `mvp.rs::pss_restricted_empty_deny_privileged` · U `mvp.rs::pss_restricted_empty_deny_run_as_root` · U `mvp.rs::pss_restricted_empty_deny_host_path` · U `mvp.rs::pss_restricted_empty_deny_capabilities` · U `mvp.rs::pss_baseline_empty_deny_host_pid_and_host_path` · U `mvp.rs::pss_baseline_empty_deny_capabilities` · U `mvp.rs::pss_privileged_empty_deny_allows_privileged` |
| Поставляемый пример `prod-restricted` в режиме audit записывает privileged, а не молчит | U | U `mvp.rs::prod_restricted_example_audit_records_privileged` |
| Приёмка §D на HTTP-слое webhook, а не только на движке: неподписанный образ, privileged и bind cluster-admin отказываются через `AdmissionReview`, совместимый подписанный образ проходит с патчами, а мусор в теле — отказ | U | U `webhook.rs::privileged_deny` · U `webhook.rs::cluster_admin_bind_deny` · U `webhook.rs::compliant_signed_digested_image_allow_with_enforce_patches` · U `webhook.rs::observe_privileged_allowed_no_patches` · U `webhook.rs::garbage_body_deny` · U `webhook.rs::in_scope_exception_waives_only_that_rule` |
| Замена bundle на живом webhook: подходящий `fsig` и подходящий каталог встают и решают по-новому, а обрезанный, с чужим ключом, с несошедшимся digest и с несошедшимся каталогом не подменяют last-known-good | U | U `webhook.rs::truncated_and_wrong_key_fsig_fail_closed` · U `webhook.rs::successful_second_fsig_swaps_and_handle_uses_new_program` · U `webhook.rs::digest_mismatch_truncated_wrong_pin_do_not_swap` · U `webhook.rs::dir_matching_digest_loads_and_denies_unsigned` · U `webhook.rs::dir_mismatched_digest_does_not_swap` · U `webhook.rs::failed_reload_keeps_last_good_mvp_denies` · U `webhook.rs::poll_reloads_on_mtime_len_and_keeps_lkg_if_file_vanishes` |
| Secret контроллера читается webhook как есть; пустой, отсутствующий и неподписанный `FRMB`/`FADM` в нём — целостность, а не пустая политика | U | U `webhook.rs::controller_secret_json_loads_and_denies_unsigned_pod` · U `webhook.rs::empty_or_missing_bundle_fsig_is_integrity` · U `webhook.rs::unsigned_frmb_or_fadm_in_secret_is_integrity` |
| Без bundle webhook не поднимается, а не поднимается пустым: `serve` выходит с 2 | U | U `webhook.rs::serve_missing_bundle_exits_2` |
| Монтирование исключений перечитывается и продолжает проверять scope и TTL; пропавший файл — пустой список, непроверяемый — сброс | U | U `webhook.rs::exceptions_mount_rotation_gates_scope_and_ttl` · U `webhook.rs::exceptions_reload_missing_file_is_empty_and_unverifiable_resets` |
| Кеш меток решает только по тому, что перечислил: тёплый применяет namespace-селектор в своём namespace и держит метки ServiceAccount внутри его namespace, холодный отказывает выбранной политике и не трогает невыбранную, а метки кластера приходят из флага и тёплого кеша не требуют | U | U `webhook.rs::warm_cache_applies_a_namespace_selector_to_its_own_namespace_only` · U `webhook.rs::warm_cache_keeps_service_account_labels_inside_their_namespace` · U `webhook.rs::cold_cache_denies_a_selected_policy_but_not_an_unselected_one` · U `webhook.rs::cluster_labels_come_from_the_flag_and_need_no_warm_cache` · U `webhook.rs::prod_restricted_namespace_selector_without_labels_fail_closed` · U `webhook.rs::cold_stale_and_relist_pending_deny_with_different_causes` · U `webhook.rs::a_stale_watch_says_stale_and_a_gone_watch_says_relist` |
| Кеш меток решает только по тому, что перечислил, и «перечислен без меток» — не «не перечислен»: тёплый кеш, назвавший непомеченный namespace, не отказывает выбранной политике, а namespace, которого он не называл, отказывает по-прежнему; обе плоскости отвечают на это одинаково | U | U `webhook.rs::a_warm_cache_that_listed_an_unlabelled_namespace_does_not_deny_a_selected_policy` · U `webhook.rs::a_namespace_a_warm_cache_never_listed_is_still_a_fail_closed_deny` · U `webhook.rs::a_cluster_selector_without_the_flag_is_unknown_and_not_an_empty_map` · U `resolve.rs::an_unlabelled_namespace_resolves_as_observed_and_empty_not_as_unknown` · U `ferrum-ebpf/src/eval.rs::an_observed_namespace_without_labels_is_a_non_match_not_labels_unknown` · U `acceptance.rs::both_planes_answer_an_unlabelled_namespace_the_same_way` · U `acceptance.rs::both_planes_agree_on_every_label_group_and_on_a_match` |
| Нечитаемое монтирование считается отдельно от удалённого — по bundle, по исключениям и по серверному сертификату: пустой том и пропавший том разной природы, и `MountStat` их не смешивает | U | U `webhook.rs::unreadable_bundle_mount_is_counted_and_a_deleted_one_is_not` · U `webhook.rs::absent_and_unreadable_exceptions_mounts_are_counted_apart` · U `ferrum-admission/tests/serving_cert.rs::an_unreadable_serving_mount_is_counted_and_a_deleted_one_is_not` |
| Том bundle у webhook не может быть `optional`, и это проверяется из самого манифеста, а не только линтом | U | U `webhook.rs::bundle_secret_mount_is_not_optional` |
| Пропавший ключ в смонтированном томе не молчит: webhook продолжает охранять по last-known-good и продолжает служить сертификатом, но говорит, что источника у них больше нет — счётчиком и строкой на переход, а не на каждый тик | U | U `webhook.rs::a_bundle_key_that_vanished_is_counted_not_silent` · U `ferrum-admission/tests/serving_cert.rs::a_serving_key_that_vanished_is_counted_not_silent` |
| Граница hot path webhook держится его же `Cargo.toml`: компилятор и живой кластер туда не заезжают | U | U `webhook.rs::cargo_toml_hot_path_keeps_boundary` |
| Серверный сертификат: просроченный не даёт стартовать, далёкий срок не шумит, ротация доходит до новых соединений, поллер подхватывает переписанный том, откат возможен, а негодный материал оставляет действующий сертификат | U | U `ferrum-admission/tests/serving_cert.rs::an_expired_certificate_refuses_to_start` · U `ferrum-admission/tests/serving_cert.rs::a_far_off_expiry_does_not_warn` · U `ferrum-admission/tests/serving_cert.rs::rotation_reaches_new_connections` · U `ferrum-admission/tests/serving_cert.rs::the_poller_picks_up_a_rotated_mount` · U `ferrum-admission/tests/serving_cert.rs::a_swap_can_be_undone` · U `ferrum-admission/tests/serving_cert.rs::unusable_material_keeps_the_current_certificate` |
| Читатель argv манифеста видит обе законные записи Kubernetes — `command:` и `args:`, — а таблица feature-флагов держится за сами `#[cfg(feature = …)]`-места | U | U `deploy_gate.rs::a_containers_argv_is_command_then_args_and_either_alone` · U `deploy_gate.rs::every_flag_read_under_a_cfg_feature_is_in_the_table` |
| Перепись грантов читает все глаголы, а не только пишущие: грант на `ferrum.io`-ресурс, для которого у субъекта нет литерала `GroupVersionKind::gvk` в поставляемой половине его исходников, — право без назначения; литерал внутри `#[cfg(test)]` достижимостью не считается, а биндинг на ServiceAccount, которого не запускает ни один pod spec, — субъект, о котором перепись не спрашивала ничего, и он же находка | U | U `boundary_gate.rs::a_granted_resource_no_subject_can_reach_is_a_permission_with_no_purpose` |
| Тепло кеша меток — часть join'а узла, а не украшение над ним: кеш, который протух или должен relist, отдаёт метки как ненаблюдённые, поэтому рантайм отвечает `LabelsUnknown` там, где admission отказывает, а не `Match`; каждая группа отвечает за себя | U | U `ferrum-k8smeta/src/source.rs::a_stale_label_cache_does_not_report_its_labels_as_observed` · U `ferrum-k8smeta/src/source.rs::a_label_cache_owing_a_relist_does_not_report_its_labels_as_observed` · U `ferrum-k8smeta/src/source.rs::one_cold_group_does_not_unobserve_the_other` |
| `clusterSelector` вне MVP-1 и отвергается при авторстве обеими копиями гейта — валидатором и вторым гейтом компилятора, — а остальные три группы селектора остаются авторуемыми; разбор и fail-closed обеих плоскостей остаются для байтов, которых этот компилятор не производил | U | U `ferrum-policy/src/lib.rs::a_cluster_selector_is_refused_on_both_kinds` · U `ferrum-policy/src/lib.rs::the_other_selector_groups_are_still_authorable` · U `ferrum-compiler/src/lib.rs::a_cluster_selector_does_not_compile` · U `webhook.rs::a_cluster_selector_without_the_flag_is_unknown_and_not_an_empty_map` |
| `--cluster-label`, съеденный соседним флагом, — отказ, а не заявленный кластер без меток; повторы накапливаются, а не побеждают последним; `--cluster-label ''` по-прежнему заявляет кластер без меток, а отсутствие флага по-прежнему fail-closed | U | U `ferrum-admission/src/main.rs::a_cluster_label_whose_value_was_eaten_is_refused_not_stated` · U `ferrum-admission/src/main.rs::an_explicitly_empty_cluster_label_is_still_a_stated_cluster` · U `ferrum-admission/src/main.rs::repeated_cluster_labels_accumulate_and_disagreements_are_refused` · U `ferrum-admission/src/main.rs::other_flags_keep_the_semantics_the_deploy_lint_models` |
| Переигранный поток встречает долг relist там же, где живой: нечитаемый кадр поднимает долг и поток читается дальше, а первый кадр после hold-down заканчивает поток — обе половины на обоих потоках | U | U `resolve.rs::a_replayed_stream_answers_an_unreadable_frame_the_way_the_node_does` |
| Заявленный бюджет латентности исполняется, а не декларируется: p99 одного AdmissionReview внутри `handle()` укладывается в объявленное число, и меряется это прогоном 10 000 настоящих review против скомпилированного и подписанного `prod-restricted` в четыре потока, а p99 читается из той самой гистограммы, которую вебхук отдаёт в `/metrics` | U | U `latency_gate.rs::the_p99_of_a_review_stays_inside_the_declared_latency_budget` · U `Jenkinsfile::Security: admission latency` |
| Заявленное число обязано быть границей корзины поставляемой гистограммы: между границами она не отвечает, и бюджет, проверяемый интерполяцией внутри корзины, — утверждение точнее прибора, который его держит | U | U `latency_gate.rs::the_budget_is_a_boundary_the_shipped_histogram_can_decide` |
| Контроль на читателя p99: распределение, у которого 2% наблюдений за бюджетом, обязано быть падением, иначе строка выше проходит на читателе, который всегда говорит «уложились» | U | U `latency_gate.rs::the_reader_notices_a_p99_that_is_past_the_budget` |
| Число одно на три места: код, панель дашборда и этот документ. Порог на панели сверяется с константой, и оба объявленных числа обязаны быть названы здесь — иначе оператор читает красную черту, проведённую не там, где падает сборка | U | U `latency_gate.rs::the_dashboard_and_the_boundary_state_the_budget_the_code_enforces` |
| Вебхука две реплики, и вытеснение не может забрать обе: селектор бюджета выбирает те Pod'ы, что поднимает Deployment, число из бюджета меньше числа реплик, и бюджет ставится тем же корнем kustomize, что и Deployment | U | U `deploy_gate.rs::the_webhook_is_a_pair_that_a_drain_cannot_take_at_once` |
| Реплики предпочитают разные узлы, и предпочтение не умеет оставить одну висеть: anti-affinity есть, она по `kubernetes.io/hostname`, полного веса, и она **мягкая** — `required` на одноузловом кластере (то есть на kind, куда ставят `install_gate.rs` и публичный воркфлоу) оставила бы вторую реплику в Pending навсегда | U | U `deploy_gate.rs::the_two_replicas_prefer_different_nodes_and_the_preference_cannot_strand_one` |
| Из-под вебхука исключены ровно `ferrum` и `kube-system`, и решает это `kubernetes.io/metadata.name` — ключ, который apiserver проставляет и контролирует сам. На любом другом ключе namespace выдаёт себе исключение из политики сам | U | U `deploy_gate.rs::the_webhook_exemption_is_decided_by_a_label_the_api_server_owns` |
| У каждого ресурса, который регистрирует поставляемый вебхук, есть scope, известный коду, который его решает, и обе стороны сверены: `namespaceSelector` apiserver к ресурсам уровня кластера не применяет, поэтому для них решение целиком за `ferrum-admission` | U | U `deploy_gate.rs::every_resource_the_webhook_registers_has_a_scope_this_crate_knows` |
| Поставляемый ClusterRoleBinding не отвергается поставляемой политикой на холодном кеше меток — это issue #17 как тест: объект уровня кластера не имеет namespace, чьи метки можно было бы наблюдать, и спрашивать о них кеш нельзя ни на холодном, ни на тёплом. Контроль в том же тесте: bind на `cluster-admin` тем же программой и в том же состоянии по-прежнему отвергнут | U | U `webhook.rs::the_shipped_cluster_role_binding_is_not_refused_by_the_shipped_policy` |
| Подписанный grant приостанавливает admission: review, который поставляемая политика отвергает (privileged Pod под `prod-restricted`), в окне grant'а пропускается, человек у `kubectl` видит в warning'е id grant'а и тикет, а `subject` туда не попадает. Контроль в том же тесте — тот же review до grant'а отвергнут | U | U `break_glass_gate.rs::a_signed_grant_suspends_a_review_the_shipped_policy_denies` |
| Окно закрывается само: ничего не перезагружали, grant по-прежнему лежит в mount'е, а следующий review снова отвергнут, и журнал несёт `expired` вслед за `activated`. Иначе весь довод про TTL был бы декоративным | U | U `break_glass_gate.rs::a_grant_stops_suspending_when_its_window_closes_with_nothing_reloaded` |
| Ключ подписи bundle не открывает break-glass: домены подписи разделены, поэтому grant, подписанный тем ключом, который в кластере действительно есть, ничего не приостанавливает — и попытка попадает в журнал как `rejected`, без единого поля из непроверенного документа | U | U `break_glass_gate.rs::a_grant_signed_with_the_bundle_key_suspends_nothing_and_is_journalled` |
| Бессрочного break-glass выразить нечем, и потолок окна туже потолка waiver'а: четыре часа против девяноста дней, потому что приостановление берут под давлением и без рецензии | U | U `break_glass_gate.rs::a_break_glass_window_is_bounded_and_tighter_than_a_waiver` |
| Поставляемый оверлей армирует break-glass флагами, которые бинарь действительно парсит, тремя вместе, кладёт журнал на писуемый том, а Secret grant'а делает `optional` — обязательный mount под Secret, пустой на здоровом кластере, оставил бы обе реплики в ContainerCreating | U | U `break_glass_gate.rs::the_shipped_overlay_arms_break_glass_with_flags_the_binary_parses` |
| Установка по умолчанию break-glass не армирует: ни один корень под `deploy/` его не называет, и поставляемый Deployment не несёт ни одного флага break-glass | U | U `break_glass_gate.rs::no_default_install_arms_break_glass` |
| Каждый путь, который runbook велит применить, существует в дереве: путь, который переехал, превращает вставленную команду в ошибку про каталог посреди инцидента | U | U `break_glass_gate.rs::every_path_the_runbook_tells_an_operator_to_apply_exists` |
| Каждое семейство метрик, названное в runbook'е, публикует настоящий бинарь — набор получен рендером обоих бинарей, а не списком. `grep`, который ничего не нашёл, читается точно так же, как здоровый узел | U | U `break_glass_gate.rs::every_metric_family_the_runbook_names_is_one_a_binary_publishes` |
| Runbook называет каждую причину деградации, которую агент умеет поднять, и не называет ни одной, которой нет: новая причина не может появиться без строки о том, что с ней делать | U | U `break_glass_gate.rs::the_runbook_names_every_degradation_reason_the_agent_can_raise` |
| Числа в разделе «Радиус поражения» — те, что несёт дерево: `timeoutSeconds: 5`, `replicas: 2`, `maxUnavailable: 1`, бюджет 5 мс вместе с именем константы и порт метрик. Разъехавшееся число хуже отсутствующего: по нему принимают решение | U | U `break_glass_gate.rs::the_numbers_in_the_blast_radius_section_are_the_ones_the_tree_carries` |
| Каждый объект Kubernetes, который runbook велит трогать, существует в `deploy/**` — и в обратную сторону: имя, которое установка ставит, обязано быть в runbook'е | U | U `break_glass_gate.rs::every_kubernetes_object_the_runbook_names_is_one_this_tree_installs` |
| Граница «что требует внешнего IdP» стоит в runbook'е дословно той строкой, которой её объявляет код: пересказ — это то, как ограничение смягчается, а разница между «FERRUM знает, кто снял enforce» и «FERRUM знает, что использовали ключ» меняет процесс вокруг хранения ключа | U | U `break_glass_gate.rs::the_runbook_states_the_idp_boundary_in_the_words_the_code_states_it` |
| Обе операции, которые runbook велит делать руками, поставляются и работают: `ferrumctl sign-break-glass` отвергает слишком длинное окно до подписи, а подпись, которую он выдаёт, принимает настоящий `BreakGlass`; `ferrumctl verify-journal` читает настоящую цепочку и отвергает правленую. И одна правка, которой цепочка не видит — обрезанный хвост, — утверждена как невидимая, а не обнаружена в инциденте: runbook обязан её называть | U | U `break_glass_gate.rs::the_two_break_glass_operations_the_runbook_names_are_shipped_and_work` |
| Оверлей армирования принят настоящим apiserver, и объект, который тот **сохранил бы**, несёт всё обещанное: три флага, оба пути, mount grant'а как `optional`, писуемый том под журнал, trust root и имя реплики в окружении. Это шесть JSON-патчей в чужой Deployment, и патч, приземлившийся не туда, не виден ни одному текстовому гейту этого дерева | A | A `install_gate.rs::the_break_glass_overlay_arms_the_deployment_a_real_apiserver_would_store` |
| Критерий закрытия фазы 1 как тест: настоящее решение §D «`exec` + `/bin/sh` → kill» уезжает поставляемой цепочкой стоков в сокет, и разбор «того ли убили» проходится по одной пришедшей записи — что произошло, кого убили (`tgid`, `pid`, `comm`), где (`node`, namespace, Pod), почему (`rule`, политика), по какой выкатке (дайджест bundle, тот самый, что узел проверил), насколько обоснованно (три флага) и в каком состоянии был узел (`degradedReasons`, id из таблицы самого агента). Ни `status.json`, ни `events.jsonl`, ни `/metrics` при этом не читаются | U | U `event_contract_gate.rs::the_wrong_process_investigation_is_answerable_from_one_exported_record` |

## Не делает

Плоские утверждения. Каждое проверено по дереву на этом коммите.

- **Break-glass не связывает ключ с человеком.** Проверка отвечает ровно на
  один вопрос: «держатель ключа K это утверждал». `subject`, `issuer` и
  `ticket` — строки, которые выбрал подписывающий; что за ними стоит живой
  уполномоченный человек, знает система, выдающая ключи поимённо, и её в этом
  дереве нет. Ставить её на путь нельзя намеренно: break-glass, падающий
  вместе с недоступным IdP, падает ровно в том отказе, ради которого
  существует. Это внешняя граница, а не отложенная работа.
- **Цепочка журнала доказывает согласованность файла, а не его полноту.**
  Правка, удаление и перестановка ломают ссылку; цепочка, переписанная с нуля
  тем, у кого есть доступ на запись, проверяется идеально. Нужен якорь вне
  процесса, и оба, что есть, — вне контроля этого дерева: строка на stderr,
  которую собирает лог-конвейер кластера, и голова цепочки меткой
  `ferrum_admission_break_glass_journal_info`, которую хранит Prometheus. Сам
  файл живёт в `emptyDir` и умирает с Pod'ом: hostPath дал бы Deployment'у
  control plane право писать на узел, а PVC RWO не делится между двумя
  репликами. На кластере, где не собирают ни лог контейнера, ни метрики,
  армирование break-glass даёт заметно меньше, чем выглядит.
- **Break-glass не снимает runtime-реакции.** Единственный scope, который эта
  сборка исполняет, — `admission`. Роль `respond` у агента снимается тем же
  `kubectl delete -f deploy/agent/optional-respond.yaml`, что и раньше, и этот
  акт не журналируется ничем. Scope, который дерево разбирало бы и ничем не
  исполняло, был бы рычагом, ничего не меняющим, поэтому его в перечислении
  нет.
- **Break-glass прогнан на живом кластере, руками, один раз.** kind v1.36.1
  (kindest/node, aarch64) на этой машине, 2026-08-31: установка
  `kubectl apply -k deploy`, армирование `kubectl apply -k overlays/break-glass`,
  две реплики поставляемого образа. Пройдены все четыре события журнала —
  `activated`, `revoked`, `rejected`, `expired`: privileged Pod отвергался
  fail-closed, после появления подписанного grant'а принимался с warning'ом,
  несущим id grant'а и тикет; удаление grant'а из Secret'а дало `revoked`;
  grant, подписанный **ключом подписи bundle**, не приостановил ничего и дал
  один `rejected` при шестидесяти трёх подсчитанных отказах — ровно тот обмен
  «журнал читаемый, счётчик полный», который заложен; двухминутный grant истёк
  по часам сам, без единой перезагрузки, и оставил `expired`, а потом один
  `rejected` про то, что просроченный документ так и лежит в mount'е. Цепочку
  из шести записей подтвердил `ferrumctl verify-journal`.

  Чего в том прогоне **не было**: поведения кластера, у которого вебхук
  действительно не отвечает; второго узла; и повторяемости — держится тестом
  ровно оверлей
  (`install_gate.rs::the_break_glass_overlay_arms_the_deployment_a_real_apiserver_would_store`),
  а само приостановление на живом кластере повторяется руками. Стадия
  `Security: break-glass` не исполнялась ни на Jenkins, ни на GitHub.
- **Найдено тем прогоном и починено:** процедура разбора журнала собирала
  `kubectl logs -l` в один файл, то есть две независимые цепочки, и проверка
  падала с «seq 0 where 1 was expected» — сообщением, которое посреди инцидента
  читается как «запись пропала». Журнал ведёт процесс, и каждая реплика
  начинает с генезиса; `verify-journal` теперь группирует по `component`.
  Ни один текстовый гейт этого не видел и увидеть не мог.
- **Runbook'и не проходили целиком в состоянии отказа.** `docs/runbooks/README.md`
  держится гейтом на том, что каждая команда, каждое имя объекта, каждое имя
  метрики и каждый id причины существуют в этом дереве. Что процедура помогает
  — не проверено ничем, и §7 документа говорит это первым абзацем.
- **Сток событий доезжает до сокета, а не до SIEM.** `ferrum-siem` рендерит
  CEF, RFC 5424 и ECS и отправляет их по TCP или UDP; всё, что про это
  исполнено, исполнено против приёмника, который поднял сам тест на
  `127.0.0.1`, и против бинаря агента, запущенного на этой машине с
  `--siem-address`. Ни ArcSight, ни Elastic, ни Splunk, ни rsyslog не
  получали от этого дерева ни одной записи, и ни один их парсер не говорил,
  что запись разобралась. Формат, который «должен» разбираться, и формат,
  который разобрался, — разные утверждения, и здесь сделано первое.
- **У стока нет TLS.** Транспорт — голый TCP или UDP, а запись несёт имена
  Pod'ов, namespace, имена процессов и имена политик, которые кластер
  применяет. `overlays/siem-syslog` говорит об этом прямо и отправляет
  оператора к локальному форвардеру; форвардера в этом дереве нет, и
  «поставьте коллектор в доверенную сеть» — это перекладывание, а не решение.
  Клиент TLS внутри DaemonSet'а добавил бы хранилище доверия и путь обновления
  сертификата в процесс, который threat model называет второй целью после
  kubelet, и эта сделка не заключена.
- **Наружу едут только события агента.** Вердикты admission — deny по подписи
  образа, по privileged, по cluster-admin — в SIEM не уходят: `EventEnvelope`
  штампует сток агента, а вебхук публикует только `/metrics`. Половина
  приёмки §D поэтому в SIEM не видна вообще.
- **Обрамление только LF.** RFC 6587 octet-counting не реализован, и приёмник,
  настроенный на `octet-counted`, эти записи отбросит у себя — там, где ни
  один счётчик этого дерева их не увидит.

- **Образы собираются, но никуда не едут.** Все три стадии образов проходят на
  локальном Jenkins в каждом билде начиная с 2026-08-28 и по #44 включительно
  (2026-08-30): `docker build` исполняется на ноде, а не внутри
  контейнера сборки — доставать демона оттуда означало бы смонтировать
  `/var/run/docker.sock`, тот самый hostPath, на который FD006 даёт находку, а
  runtime-правила убивают. Проверки *внутри* `Dockerfile` — интерпретатор,
  `apiserver` в бинаре вебхука, `elf_inspect` над BPF-объектом — исполняются
  вместе с ними. Чего по-прежнему нет: `docker push` не исполнялся ни разу и
  нигде, тег существует только на демоне, который его собрал, а `deploy/**`
  ссылается на `ghcr.io/onixus/*:v0.1.0`, которых никто не публиковал. И ни
  один из этих образов не запускали: то, что он собрался и объявляет
  `linux/amd64`, не утверждение о том, что он стартует на узле.
- **Поставка описана и подписана в файле, а не в реестре.** Появился
  `.github/workflows/release.yml`: `docker push` трёх образов по git-тегу,
  `cosign sign` keyless по digest, SBOM от `syft` и `cosign attest` на нём,
  SBOM файлами в GitHub Release. Ни одна строка этого предложения не
  исполнялась. Воркфлоу на GitHub не запускался, в `ghcr.io/onixus/` пусто, ни
  одной подписи не существует, ни одного SBOM никуда не приложено, и в Rekor
  нет записи об этом репозитории. Проверено здесь ровно то, что можно
  проверить на дереве: множества образов сходятся, подпись не заводит ключа,
  ни один шаг не может себя пропустить, инструкция получателю совпадает с тем,
  что воркфлоу делает. «Умеет» и «сделал» — разные слова, и второго тут нет.
- **Релиза нет.** Тега `v0.1.0` в этом репозитории не существует: он не
  проставлен, GitHub Release под ним не создан, `release.yml` по нему не
  запускался. Появилось описание того, что этим тегом будет выпущено — раздел
  README «Первый релиз» — и три конца версии сведены гейтом: `Cargo.toml`,
  `deploy/**` и фильтр триггера больше не могут разъехаться молча. Всё это —
  утверждения о файлах. Тег ставит человек, и до тех пор строки «выпущено»
  здесь нет.
- **Приватный приём сообщений об уязвимостях в настройках репозитория не
  подтверждён.** `SECURITY.md` появился и отправляет к
  `security/advisories/new`; работает эта ссылка, только если private
  vulnerability reporting включён в настройках GitHub, а настройки — не файл в
  дереве, и ни один гейт их не видит. Пока это не проверено человеком,
  единственный названный канал раскрытия остаётся непроверенным, и это ровно
  тот разрыв, ради которого в самом файле сказано «нет ответа за 14 дней —
  раскрывайте публично».
- **Замыкание «манифест ↔ pipeline» по тегу закрыто наполовину, и это первый
  цикл, когда оно закрыто хоть на сколько-то.** Прежде тег сравнивать было не с
  чем: стадии Jenkins тегируют `dev-$BUILD_NUMBER`, манифесты закрепляют
  `v0.1.0`, и два пространства не пересекались, потому что публиковать было
  нечему. Релизный воркфлоу публикует имя git-тега, поэтому вопрос «может ли
  этот манифест вообще разрешиться» стал проверяемым, и он проверяется:
  `the_tag_the_manifests_pin_is_one_the_release_can_publish` требует, чтобы
  закреплённый тег попадал в фильтр триггера и не был плавающим. Открытая
  половина осталась та же и по той же причине: ничто не подтверждает, что образ
  с этим тегом существует. Гейт читает файл, а не реестр, и до первого
  настоящего релиза `kubectl apply -f deploy/` даёт три `ImagePullBackOff`.
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
- **Поставляемый агент по-прежнему ничего не пинит, хотя пинить теперь умеет.**
  `KernelHandle::pin_at` закрепляет три карты и привязки на bpffs, и это
  измерено на настоящем ядре: при уничтоженном handle пин переоткрывается как
  объект ядра. Зовёт его только стадия `BPF pins`. `Loader::attach_pins` —
  тот, кого зовёт `ferrum-agent/src/main.rs`, — остаётся `Degraded` по
  построению, и это не забывчивость: пин, переживающий процесс, переживает и
  перезапуск DaemonSet, а `pin_at` занятый путь **отвергает**, потому что
  изнутри процесса пин прежнего экземпляра неотличим от чужого. Пока этот
  случай не решён, включение пинов в агенте означало бы узел, который после
  первого рестарта отказывается пиниться навсегда.
  **Строка Tampering из RFC-02 §C поэтому закрыта на треть, а не целиком**:
  pin есть и исполнен, LSM на pin path нет, self-watch вне процесса нет. Ни
  одна из двух оставшихся контрмер не начата, и ни один сигнал `DEG_*` их
  отсутствия не назовёт.
- **У `FerrumClusterStatus.degraded` нет ни одного писателя во всём
  workspace**, и `FerrumCluster` не назван ни в одном файле контроллера. Грант
  на `ferrumclusters/status` из `deploy/controller/rbac.yaml` убран — вместе с
  `policylibraries/status` и `compliancesnapshots/status`, у которых та же
  форма, — потому что статус, который никто не пишет, вечно сообщает нулевое
  значение своей структуры (`degraded: false` на упавшем кластере) и неотличим
  от здорового, а право, которым никто не пользуется, — цель бокового движения.
  Прав на чтение `ferrumclusters`, `compliancesnapshots`, `policylibraries` и
  `runtimeprofiles` в этом дереве больше нет. Прежняя редакция этого абзаца
  называла их «следующей находкой той же формы, названной, а не починенной», и
  была неверна: находку закрыл коммит раньше, чем абзац переписали, — ровно то
  направление гниения, о котором предупреждает заголовок этого документа
  («документ занижает дерево, и ни одна сборка от этого не краснеет»), только
  случившееся внутри «Не делает», где занижение читается как открытый дефект.
  Держат оба списка
  `boundary_gate.rs::every_shipped_subject_has_one_reachable_channel_that_carries_a_cause`
  и
  `boundary_gate.rs::a_granted_resource_no_subject_can_reach_is_a_permission_with_no_purpose`:
  грант на kind, которого не достаёт ни один `gvk`, — падение сборки, а не
  строка в документе.

  Третий слой той же находки закрыт этим циклом, и он был самым громким:
  `docs/crd/` объявлял подресурс `status`, схему статуса и printer-колонки для
  четырёх kind, которых не пишет никто — `FerrumCluster`, `ComplianceSnapshot`,
  `PolicyLibrary`, `RuntimeProfile`. Объявленный статус не пустое поле: API
  server его дефолтит, и `kubectl get` печатает нулевое значение каждой колонки
  вечно — `Degraded false` на упавшем члене флота, `Pass 0 Fail 0 Waived 0` на
  аудите, которого не было. RBAC читает тот, кто разбирается с доступом; CRD
  читает тот, кто решает, о чём эта система вообще сообщает, а колонки видит
  каждый. Подресурс, колонки и схема сняты у всех четырёх; `spec`-колонки
  остались, потому что печатают написанное оператором. Вместе с ними ушли: одно
  CEL-правило `FerrumCluster` («`degraded=true` без `lastBundleDigest` — это
  fail-open»), которое сторожило поле без писателя и потому не решило ни разу, и
  блок `status:` из фикстуры `cp-down-lkg.yaml` — вместе с тестом, который
  читал из неё `degraded: true` обратно под именем `rfc_d_*` и утверждал этим
  YAML, а не продукт. §D-случай держит `acceptance.rs`, и держал всегда.
  Механическую форму этому даёт
  `boundary_gate.rs::a_status_no_subject_writes_is_not_a_status_this_tree_ships`,
  и он двусторонний: писатель статуса, которого CRD не объявляет, — тоже
  падение, потому что такой PATCH API server срезает молча.
- **`.status.rollout` на любой настоящей установке не сообщает ничего — и
  теперь так и написано в объекте.** `deploy/controller/deployment.yaml`
  по-прежнему не передаёт `--cluster`, и `plan_rollout` по-прежнему получает
  пустой срез; изменилось то, чем это отдаётся наружу. Пока счётчики были
  `i32`, пустой срез давал `clustersReady: 0` — нулевое значение структуры,
  которую никто не заполнял, в той самой printer-колонке, по которой оператор
  решает, доехала ли политика, и неотличимое от объявленного флота, который
  встал целиком. Это та же находка, за которую отсюда удалены четыре гранта
  RBAC, полем левее: статус, которого никто не считал, хуже отсутствующего,
  потому что отсутствующий читается. Теперь оба счётчика — `Option<i32>`,
  пустой срез даёт `None`, и `None` едет явным `null`, а не пропуском ключа:
  запись статуса — merge patch, и пропущенный ключ оставил бы прежнюю цифру
  стоять навсегда. Объявленный флот, вставший целиком, по-прежнему сообщает
  `0`, потому что этот ноль сосчитан. Чего по-прежнему нет: флота в
  поставляемом манифесте, и `deliver` с `keep_lkg` не читает никто, кроме
  тестов.
- **`MAP_RULES` называет карту, которую не объявляет ни одна программа.**
  `ferrum_rules` есть в константах и в тестах и нет в ELF.
- **Wasm-модуля этот tree не исполняет — и теперь отказывается грузить bundle,
  который его несёт.** Прежняя редакция этой строки говорила, что у
  `ferrum-wasm-host` нет ни одной точки вызова, а `ferrum-agent` держит его в
  зависимостях; за этим стояла находка крупнее, чем неиспользуемый crate. Слот
  wasm лежит внутри FRMB и покрыт дайджестом, то есть подписан контроллером, а
  оба разборщика читали его длину и выбрасывали байты: `parse_frmb` в
  `ferrum-ebpf` и `extract_admission_program` в `ferrum-admission` связывали
  срез с `_`. Bundle, чей слот нёс настоящий модуль, грузился, исполнял всё,
  кроме этого модуля, и не сообщал об этом ничем — ни счётчиком, ни
  `Degraded`. Подпись такого не отмывает: она говорит, что байты написал
  контроллер, а не что этот бинарь умеет их исполнить. Теперь решение принимает
  `ferrum_wasm_host::accept_bundle_slot`, и оба разборщика его зовут: пройти
  может только версионированный placeholder на ABI этого хоста; чужой kind и
  чужой ABI — `Degraded` (плоскость остаётся на last-known-good), битые байты —
  `Compile`. Прямую зависимость `ferrum-agent` на `ferrum-wasm-host`, которую
  ничто не звало, убрали: крейт приезжает через `ferrum-ebpf`, где стоит вызов.
  Чего по-прежнему нет: исполнителя wasm. `eval_policy` отказывает на любом
  входе, который умеет разобрать, placeholder включительно, — и строка про
  9-байтовый модуль в дайджесте каждого bundle остаётся верной.
- **In-kernel prefilter инертен и поставляемую политику сузить не может.**
  Ничто не вызывает `prefilter_image` из агента; карты нет. Даже если бы
  была: флаги образа требуют, чтобы признак несло *каждое* правило, а
  `defaultAction: audit` сам по себе ставит полную маску syscall.
- **Ветка «tracefs нет вообще» покрыта только unit-тестами, а стык — одной
  архитектурой.** Про `aarch64` этот пункт стоял здесь четыре цикла в редакции
  «покрыт только unit-тестами… второго ядра здесь не было», и с билда #38 она
  ложна: второе ядро есть (6.12.76-linuxkit, aarch64, нода локального Jenkins),
  и `attach_live.rs` идёт на нём девятью тестами из девяти начиная с #39. Абзац
  противоречил секции «Как читать колонку „Исполняется“» того же файла, где это
  записано верно, — занижение ровно той формы, о которой предупреждает заголовок
  документа: ни одна сборка от него не краснеет. Что **действительно** не
  измерено ни на одном ядре, кроме x86_64-стенда, было до билда #52: стык.
  Стадия `BPF join` не проходила в CI ни разу (#31–#37 пропуск, #38–#41 — шесть
  тестов из шести падают на `mkdir /sys/fs/cgroup/ferrum-join-…: Read-only file
  system`, #44–#51 — по причинам, разобранным выше). С #52 она зелёная на
  aarch64-ноде, и `attach_join.rs` измерен на обеих архитектурах. Остаётся
  верным только одно: x86_64-стенд — Firecracker microVM без `CONFIG_MODULES`,
  где `init_module` и `finit_module` сообщаются незацепленными, потому что
  tracepoint для них не существует, а не потому, что attach проверен и
  отказал.
- **Всплеск нечитаемых кадров всё ещё запрещает каждый выбранный Pod — до
  одного hold-down.** `RELIST_DEBT_HOLDDOWN` — 5 секунд
  (`crates/ferrum-k8smeta/src/labels.rs:40`). Пока долг стоит,
  `LabelCache::is_warm` ложен, `review.rs` отказывает каждому Pod под
  namespaceSelector, а `PodCache::snapshot()` возвращает `Err`, и
  `containerOnly` не матчится. С этого цикла холодность кеша меток стоит и на
  рантайме: `snapshot()` спрашивает `is_warm_at` у обоих вложенных кешей и
  отдаёт группу как ненаблюдённую, пока она не тёплая, — то есть узел на этот
  же долг отвечает `LabelsUnknown` и Degraded, а не совпадением селектора по
  меткам, про которые уже известно, что они отстали. Раньше видна была только
  холодность: протухший и должный relist кеш держал записи от прежнего листа,
  `labels_of` отвечал `Some`, и одно состояние кеша давало admission отказ, а
  агенту — `Match`. Ограниченно, не навсегда, но не ноль. На
  молчащем потоке hold-down не срабатывает вовсе — гасит долг не он, а
  read-дедлайн сокета: `IO_TIMEOUT` = `POD_WATCH_BUDGET / 2` = 150 секунд
  (`crates/ferrum-k8smeta/src/watch.rs:1161`), после которых `read` возвращает
  ошибку, `watch_once` — `Err`, и `watch_loop` переподключается и делает
  relist. Отдельного таймаута «долг просрочен, кадров нет» этот слайс не
  добавлял: он был бы вторым дедлайном на том же сокете. Значит окно отказов
  на молчащем потоке — до 150 секунд, а не до 5.

  **Но на рантайме это окно больше не окно убийств.** Радиус тут другой, чем в
  admission, и это не деталь: тепло кеша — свойство узла и группы, а не пода,
  поэтому один 410 на watch namespace помечает ненаблюдённым **каждый** pod
  узла разом. `decide_with` программу применяет — пропуск правил был бы
  молчаливым fail-open, и обе плоскости обязаны отвечать на это состояние
  одинаково, — но *применить* и *исполнить* здесь не одно и то же.
  Fail-closed в admission отказывает Pod, и следующая попытка это отменяет;
  fail-closed на рантайме — это `SIGKILL`, которого не отменяет ничто, и
  выдавался бы он workload'ам, про которых никто не установил, что политика их
  выбирает. Поэтому `react` отказывается сигналить, пока scope не разрешён:
  `REFUSE_LABELS_UNKNOWN`, `executed=false`, запись с `labels_unknown` и
  сработавшим правилом, `respond_refused_total`, `DEG_LABELS_UNKNOWN`. Ровно
  та же форма, что и у отказа по неизвестной identity, шагом раньше: «какой
  это workload» и «покрывает ли его эта политика» — два вопроса, и сигналу
  нужны оба ответа. Цена названа и принята: на время холодного кеша (до 5 с
  hold-down на живом потоке, до 150 с на молчащем) `Kill`/`Isolate` под
  `namespaceSelector` не исполняются — совпадение экспортируется, узел
  Degraded, а `Deny` и `Audit` не затронуты, потому что ни один из них процесс
  не завершает.

- **Меток кластера у узла нет и не заведено.** `PodRecord::identity` зашивает
  `cluster_labels_observed: false`, и это честно: объекта «кластер» Kubernetes
  не отдаёт, а `--cluster-label` — заявление оператора, которое доезжает
  только до admission. Разошлось это в разные стороны на обеих плоскостях
  сразу: `selector_match` возвращал `LabelsUnknown` на любой `clusterSelector`
  — и на подходящий, и на заведомо чужой, — `decide_with` на `LabelsUnknown`
  программу применяет, поэтому политика матчилась на каждый workload каждого
  узла и держала `DEG_LABELS_UNKNOWN` истинной, пока лежала в bundle; в
  admission та же политика отказывала каждому Pod, потому что отгружаемая
  установка флага не передаёт. Закрыто отказом при авторстве, а не доставкой:
  метка кластера, заявляемая каждым узлом отдельно, — новое непроверяемое
  утверждение, которому понадобился бы собственный гейт. Разбор и fail-closed
  обеих плоскостей остались для байтов, которых этот компилятор не
  производил.
- **Обращение к API server перестало быть нулём, и это первый цикл, когда так.**
  Здесь стояло «ничто и никогда не обращалось к API server» — про webhook под
  нагрузкой admission, про watch и про запись status. Первого больше нет:
  `e2e_cluster.rs` подаёт Pod настоящему apiserver, тот зовёт webhook, и
  webhook отказывает своей причиной. Второе тоже: контроллер в kind поднимает
  watch на три Kind и по нему компилирует и подписывает bundle — Secret в
  кластере написал он. Что **не** изменилось: нагрузки не было (счёт Pod'ов
  здесь идёт на единицы), запись `status` меряна только тем, что тест прочитал
  `status.compile.message` у одного объекта, а агент к apiserver в кластере не
  обращался ни разу — его DaemonSet на этом рантайме не стартует, см. строку в
  «Верим, но не доказано».

## Верим, но не доказано

Механизм, который это закроет, назван для каждого. Для тех, которые останутся
незакрытыми, назван регистр цикла 8: *заявлено, не закрыто*.

| Утверждение | Чем закрывается | Статус |
|---|---|---|
| Собранный образ стартует на узле | запуск контейнера из этого образа на настоящем узле | **Исполнено для двух образов из трёх, и опровергнуто для третьего.** `ferrum-controller` и `ferrum-admission` стартуют на узле kind и делают работу: `e2e_cluster.rs` доводит оба Deployment до Ready и читает их результат. Образ агента там же не стартует, и не по своей вине — см. следующую строку. `docker push` по-прежнему не делал никто, а сборка под arm64 до этого цикла была невозможна: `Dockerfile*` знали одну цель |
| `deploy/agent/daemonset.yaml` разворачивается на настоящем узле | DaemonSet, дошедший до Ready на узле с tracefs и `CAP_BPF` | **Механизм исполнен, и утверждение им опровергнуто.** На containerd (kind, aarch64) Pod не стартует: манифест монтирует hostPath в `/sys/fs/bpf/ferrum`, runc обязан создать эту точку монтирования внутри собственного sysfs контейнера, а sysfs только для чтения — `mkdirat …/rootfs/sys/fs/bpf/ferrum: no such file or directory`. Образ, ELF и права тут ни при чём: ELF собран из этого дерева и все одиннадцать символов на месте. Починка — правка монтирования pin path, и в ней сидит вопрос threat model: смонтировать `/sys/fs/bpf` целиком значит отдать агенту весь bpffs узла. Пока этой строки нет, ни один runtime-случай §D в кластере не исполняется. Этот цикл измерил тот же отказ на слой раньше и назвал его причину точнее: на kind v1.36.1 `/sys/fs/bpf` — это каталог sysfs только для чтения, bpffs на нём не смонтирована, поэтому hostPath типа `DirectoryOrCreate` не создаётся вовсе и до runc дело не доходит — `MountVolume.SetUp failed for volume "bpf-pins": mkdir /sys/fs/bpf/ferrum: no such file or directory`. Это и есть причина, по которой `deploy/agent` — отдельный корень kustomize и не часть установки по умолчанию: гейт устанавливаемости, вынужденный делать исключение для собственного ресурса, перестал бы быть гейтом |
| Собранный продуктовый бинарь аттачится на узле, а не только линкуется | Стадия, которая запускает слинкованный musl-бинарь и читает его `status.json` | В слайсе A это делали руками: бинарь написал `"attached": true`, а на испорченной релокации — причину в `containerMapError` и `degradedReasons`. В дереве нет ничего, что бы это повторило |
| Поднятие memlock что-то решает на ядрах, куда это едет | Измерение на 5.8–5.10, где лимит ещё считает BPF-память | Не начато, и на этом хосте невозможно: soft = hard = 8 MiB, а с 5.11 память учитывается memcg. Манифест объявляет пол «ядро >= 5.8», и 5.8–5.10 — ровно тот диапазон, где лимит решает, загрузится ли datapath |
| API server отвергает `PolicyException` без `expiresAt` | kind с применённым CRD: применить объект и потребовать отказ | Не исполнено, но механизм с этого цикла есть и стоит в дереве: `e2e_cluster.rs` разворачивает kind и применяет `docs/crd/`, где CRD с `required: expiresAt` теперь устанавливается (до этого цикла он не устанавливался вовсе). Не хватает ровно одного `kubectl apply` объекта без TTL и чтения ответа; `NOT_COVERED_HERE` в том файле называет это своими словами |
| Агент сам обнаруживает падение CP и переходит на last-known-good | Тест на watch-клиент с оборванным соединением, не `mark_control_plane_down()` | Не начато |
| `--policy-name` действительно джойнит waiver с политикой | Имя политики в FRMB — смена формата, бамп ABI и bundle, который откажется грузить каждый развёрнутый агент | **Заявлено, не закрыто.** Агент объявляет себя Degraded, если держит waiver, ни один из которых не называет его политику, а FD024 проверяет развёрнутые объекты. Джойн в рантайме остаётся недоказанным |
| Разбор argv в этом дереве — одна грамматика | Поднять разбор в `ferrum-common` и оставить одну копию | **Заявлено, не закрыто, и прежняя формулировка этой строки была неверна в трёх местах.** (1) «Стоит зависимости в графе каждого crate» — платить нечем: `ferrum-common` уже существует и уже стоит в зависимостях `ferrum-agent`, `ferrum-admission` **и** `ferrum-controller`. (2) «Две копии дословные» — нет: admission собирает позиционные аргументы для `review <file>` и несёт второе поле в `Flags`; совпадает только ветка флагов. (3) Грамматик не три, а четыре: `ferrum-controller/src/main.rs::parse_run` — не last-wins вовсе (`--cluster` накапливается, флаг на месте значения — ошибка, а не пустая строка, разбор возвращает `Result`, а не карту), при этом FD027 читает argv контроллера через `container_flag`, то есть семантикой агента. Сам рефакторинг всё равно не работа этого цикла: за ним не стоит дефекта, FD025 делает удвоенный флаг находкой раньше, а копия, которая имела бы значение, — в `ferrum-cli`, который от `ferrum-common` не зависит |
| NetworkPolicy перед портом метрик что-то закрывает на кластере получателя | Тест, который поднимает Pod в непомеченном namespace и требует отказа | **Исполнено руками, в дереве не повторяется.** На `kind-ferrum-install` (`kindest/kindnetd:v20260528-9350166c`, движок `kube-network-policies`) 2026-08-31: из непомеченного namespace `http://ferrum-admission.ferrum.svc:9102/metrics` не соединяется вовсе (curl `000`), из namespace с меткой `ferrum.io/metrics-scrape=true` отдаёт `200` и экспозицию с настоящим `bundle_info{digest=...}`, `POST` — `405`, `/healthz` — `404`, а порт 8443 отвечает из обоих. Гейтом это не стало намеренно: тест зависел бы от того, несёт ли CNI кластера движок политик, и на кластере без него был бы красным по причине, о которой утверждение не делается. Про сборки kindnetd без движка — комментарий в самом манифесте |
| Снятие enforcement заметно тому, кто за ним смотрит | LSM на pin path и self-watch вне процесса (RFC-02 §C, Tampering) | Не начато, и это ровно та половина, которую пины не закрывают. Пин теперь есть и измерен на ядре, но он делает объект, который *можно* защищать и чьё исчезновение *можно* заметить, — и не делает ни того, ни другого сам. Ни один сигнал `DEG_*` пропажу пина не назовёт |
| `status.json` кто-то читает | Scrape config или acceptance-прогон, который делает `cat` | **Закрыто наполовину, и вторая половина никуда не делась.** Читатель в дереве появился: `/metrics` агента строится обходом того самого объекта, который печатает `status_json`, и `metrics_gate.rs::the_agent_publishes_the_in_kernel_drop_counter_it_already_had` требует, чтобы ни один ключ не остался неразмещённым. Но это читатель *объекта*, а не *файла*: порт читает ту же функцию в памяти, а `status.json` на диске по-прежнему не читает никто, и там живёт всё, что наружу сознательно не отдаётся — имя политики, текст терминального отказа, ошибка cgroup-карты, строка о неприсоединённых waiver'ах |
| Поведение на `aarch64` совпадает с измеренным на x86_64 | Стадия `BPF attach` на arm64-раннере | **Механизм исполнен, и утверждение им опровергнуто.** Стадия идёт на arm64-ноде с билда #38 и зелёная с #39. Совпадения не оказалось: путь, переданный в `openat` ребёнком, ничего не сделавшим после `fork`, на x86_64 читается, а на aarch64 — нет. Расхождение закрыто не сближением ядер, а тем, что нечитаемое перестало выдаваться за короткое (`attach_live.rs::a_path_this_kernel_could_not_read_is_never_reported_as_a_short_one`). Строка остаётся здесь, потому что закрыт один найденный случай, а не класс |
| Стык `attach_join.rs` ведёт себя на второй ноде так же, как на x86_64-стенде | Зелёная стадия `BPF join` на этой ноде | **Механизм исполнен, и утверждение подтвердилось — но не раньше, чем разошлось трижды.** С билда #52 стадия зелёная: шесть тестов из шести, четыре с `SIGKILL`, подтверждённым `waitpid`. Разошлись при этом не продукт, а пробы: они отдавали ядру непрочитанную страницу пути, целились в tgid, который агент не сигналит по построению, и трогали один байт там, где строка занимает две страницы. Агент на этой ноде повёл себя так же, как на x86_64, во всех шести случаях — включая тот, где нечитаемый путь заставил правило по пути **утвердить** совпадение |

## Что этот документ не гарантирует

Гейт проверяет, что процитированный `fn` существует, — не то, что он
утверждает написанное в строке, и не то, что он вообще `#[test]`. Метка
`K`/`U` — слово автора о том, где тест исполнялся. Ни то, ни другое grep не
закрывает, и делать вид, что закрывает, было бы тем же дефектом этого
проекта уровнем выше.
