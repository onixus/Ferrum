# FERRUM RFC-02 — Каркас, CRD, threat model агента, покрытие CIS/MITRE

Статус: черновик внутреннего RFC  
База: self-hosted K8s enforcement plane на Rust  
Покрытие: CIS Kubernetes v1.10/v1.11 секция 5, MITRE ATT&CK Containers

## A. Границы crate

Один monorepo. Версии в проде сшиваются `PolicyBundle.digest`. Несовместимый агент bundle не грузит и остаётся на last-known-good.

Правило: что исполняется на hot path, не тащит kube client, serde_yaml и сеть.

| Crate | Можно | Нельзя |
|---|---|---|
| ferrum-api | serde-типы CRD | aya, wasmtime |
| ferrum-policy | инварианты | kube, сеть |
| ferrum-compiler | offline compile | живой кластер, webhook |
| ferrum-admission | исполнение bundle | compiler, CAP_BPF |
| ferrum-agent | eBPF + LKG | compiler |
| ferrum-ebpf-progs | aya-ebpf | tokio, kube, String на syscall |
| ferrum-controller | reconcile + compile + rollout | datapath, CAP_BPF |
| ferrum-crypto | подпись bundle, mTLS material | openssl-sys, выпуск CA, сеть |

Userspace: stable + musl. Nightly только у eBPF-progs.

## B. CRD `ferrum.io/v1`

Kind: `ClusterSecurityPolicy`, `SecurityPolicy`, `PolicyException`, `PolicyLibrary`, `RuntimeProfile`, `FerrumCluster`, `ComplianceSnapshot`.

`EnforcementEvent` как CRD в MVP нет: etcd не SIEM.

Инварианты:

- deny бьёт allow;
- exception бьёт deny только в своём scope и до `expiresAt`;
- `expiresAt` обязателен, максимум 90 дней;
- namespaced policy не может `failurePolicy=Ignore`;
- trust roots едут в bundle, admission не ходит в Rekor на каждый Pod.

Секции политики: `supply` + `admit` + `runtime`.

## C. Threat model агента

Агент — вторая цель после kubelet.

Не доверяем: workload, privileged pod, root на ноде, CP как единственный корень доверия.
Root на ноде enforcement не побеждает.

| Класс | Атака | Контрмера |
|---|---|---|
| Spoofing | чужой pod в событии, фейковый CP | cgroup→pod + mTLS **и** подпись bundle |
| Tampering | detach eBPF, rewrite pin | LSM на pin path; self-watch не в том же процессе |
| Repudiation | «я не снимал enforce» | journal + IdP на break-glass |
| DoS | syscall flood | in-kernel drop, CPU cgroup, `events_dropped_total` |
| EoP | SA агента с delete pods | два SA: observe и respond; respond выключен |

CP down ≤ 2ч → last-known-good, `Degraded=true`, не fail-open.

Состояние контрмер: подпись bundle и mTLS material — `ferrum-crypto`, trust
roots caller-supplied, домены `BUNDLE_SIGNATURE_CONTEXT`, `KEY_BIND_MSG` и
`BREAK_GLASS_CONTEXT` разделены. LKG у агента и fail-closed admission — есть.
Пины реализованы и измерены на настоящем ядре (`KernelHandle::pin_at`,
стадия `BPF pins`): карты и привязки переживают процесс. Зовёт их пока только
стадия, не агент. LSM на pin path и in-kernel drop не реализованы, и прежняя
причина здесь — «aya-ebpf требует nightly, attach отдаёт `Degraded`» — больше
не та: nightly в дереве уже используется (`ferrum-ebpf-progs` собирается им),
attach давно не `Degraded`, а нода CI сообщает `CONFIG_BPF_LSM=y` и активные
LSM `capability,bpf,landlock`. Не сделано — значит не начато, а не заблокировано. Spoofing закрыт только на уровне подписи и
TLS-идентичности, не на уровне ядра.

Строка Repudiation исполнена наполовину, и половины разные по природе.

Журнал есть: `ferrum-breakglass`. Приостановить admission можно только
подписанным grant'ом, который называет `subject`, `issuer`, `ticket`, `reason`,
`issuedAt` и обязательный `expiresAt` не дальше четырёх часов; активация,
истечение, отзыв и **отказ** пишутся в хеш-цепочку, где правка, удаление и
перестановка ломают ссылку. Журнал, в который нельзя писать, не даёт grant'у
вступить в силу, а армирование без писуемого журнала роняет старт процесса:
приостановление, которое некому потом объяснить, хуже отсутствия
приостановления. Само по себе это не новая возможность — снять enforcement
можно было и раньше, `kubectl delete validatingwebhookconfiguration`, — новым
является след.

Чего цепочка не доказывает: она доказывает согласованность файла с самим собой.
Переписанная с нуля цепочка проверяется идеально, поэтому нужен якорь вне
процесса: каждая запись дублируется строкой на stderr, а голова цепочки —
меткой `ferrum_admission_break_glass_journal_info`. Оба вне контроля этого
дерева и названы требованием, а не свойством. Сам файл живёт в `emptyDir` и
умирает с Pod'ом: hostPath дал бы Deployment'у control plane право писать на
узел, а PVC RWO не делится между репликами.

IdP — внешний, и это не откладывание. Проверка отвечает «держатель ключа K это
утверждал»; что `subject` — живой уполномоченный человек, знает только система,
которая выдаёт ключи поимённо и отзывает их. Ставить её на путь нельзя:
break-glass, падающий вместе с недоступным IdP, падает ровно в том отказе, ради
которого существует.

Scope один — `admission`. Роль `respond` у агента этим grant'ом не снимается, и
scope, который дерево разбирало бы и ничем не исполняло, был бы рычагом,
ничего не меняющим.

## D. Покрытие MVP

FERRUM не закрывает CIS целиком. Секции 1–4 — kube-bench и дистрибутив.

MVP-1 enforce: CIS 5.1.1/5.1.3/5.1.5/5.2.1–5.2.9, PSS restricted, T1610, T1609, T1059, T1611, T1525.

Out of scope MVP-1: CIS 1.x/4.x, шифрование etcd, WAF (T1190), облачный IAM.

Приёмка: unsigned image deny; privileged deny; cluster-admin bind deny; `kubectl exec`+/bin/sh → kill; docker.sock → kill; bpf() → deny; exception без TTL → API reject; CP down → LKG.
