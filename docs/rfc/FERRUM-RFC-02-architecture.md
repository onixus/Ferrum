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

## D. Покрытие MVP

FERRUM не закрывает CIS целиком. Секции 1–4 — kube-bench и дистрибутив.

MVP-1 enforce: CIS 5.1.1/5.1.3/5.1.5/5.2.1–5.2.9, PSS restricted, T1610, T1609, T1059, T1611, T1525.

Out of scope MVP-1: CIS 1.x/4.x, шифрование etcd, WAF (T1190), облачный IAM.

Приёмка: unsigned image deny; privileged deny; cluster-admin bind deny; `kubectl exec`+/bin/sh → kill; docker.sock → kill; bpf() → deny; exception без TTL → API reject; CP down → LKG.
