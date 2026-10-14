# APEX deployment contract 1.0 — ferrum

The root `apex-deploy.json` declares the installation method and required parameter names.
The common schema is `apex-contract/deployment/apex-deploy.schema.json`.
APEX reserves one dedicated server for one product, archives the selected Git SHA,
and only reports Docker readiness after the declared service's real healthcheck.

Mode: **kubernetes**. Required parameters: KUBECONFIG, FERRUM_NAMESPACE.
Also provide `APEX_GATEWAY_URL` and `APEX_SERVICE_URL`. They declare the integration
addresses; domain-specific adapters and credentials still require operator configuration.
Secrets must never be committed. The platform's `deployment/install.py` asks for SSH
key paths and lets OpenSSH request passwords/passphrases in the terminal.
Environment values are entered with hidden input and written to a protected
`/etc/apex/ferrum.env` on the target only on explicit first-time setup.

No standalone Docker installation is advertised. Follow `docs/runbooks/README.md`
with server/cluster access. CI Dockerfiles and Ferrum's node-specific BPF image are
not substitutes for native host inventory or Kubernetes enforcement.
APEX will detect new Docker/Compose files on subsequent repository version checks;
change deployment_mode to docker only when a supported recipe and healthcheck exist.
