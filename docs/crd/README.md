# CRD ferrum.io/v1

- ClusterSecurityPolicy — политика ИБ на кластер
- SecurityPolicy — namespaced, не может Ignore на webhook
- PolicyException — только с expiresAt <= 90 дней
- PolicyLibrary — подписанный bundle + minAgentAbi
- RuntimeProfile — observe → ручной promote
- FerrumCluster — член флота
- ComplianceSnapshot — отчёт, не рычаг
