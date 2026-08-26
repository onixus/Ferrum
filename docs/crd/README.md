# CRD ferrum.io/v1

Kind и зачем:

- ClusterSecurityPolicy — политика ИБ на кластер
- SecurityPolicy — namespaced, не может Ignore на webhook
- PolicyException — только с expiresAt <= 90 дней
- PolicyLibrary — подписанный bundle + minAgentAbi
- RuntimeProfile — observe → ручной promote
- FerrumCluster — член флота
- ComplianceSnapshot — отчёт, не рычаг

kube-derive включается на rustc >= 1.85 отдельной фичей. На 1.75 типы — serde-эквивалент тех же YAML.
