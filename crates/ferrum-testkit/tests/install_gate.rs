//! `kubectl apply -k deploy` against a real API server.
//!
//! This file answers one question and refuses to answer any other: **does the
//! installation this repository ships come up on a cluster that has never seen
//! it?** Not "do the manifests lint" (`ferrumctl lint-deploy`), not "do the
//! kustomization roots name the right files" (`deploy_gate.rs::kustomize_roots`,
//! which reads YAML and is honest about reading YAML), and not "does the
//! webhook deny what the policy denies" (`e2e_cluster.rs`, which installs the
//! same tree file by file and would not notice a kustomization root that names
//! nothing).
//!
//! The distinction is the whole reason this file exists. Last cycle two of the
//! seven CRDs in `docs/crd` passed every text-reading gate here and were
//! rejected outright by an API server; a gate that reads the YAML it is
//! asserting about can hold a manifest that does not install. So nothing below
//! parses a manifest to decide anything. The inputs are `kubectl apply -k` and
//! the outputs are the API server's own answers.
//!
//! ## What it needs
//!
//! A cluster with **nothing of FERRUM on it**, named by `FERRUM_INSTALL_CONTEXT`,
//! and the two control-plane images already on its nodes:
//!
//! ```text
//! kind create cluster --name ferrum-install
//! docker build --platform linux/arm64 --build-arg TARGET=aarch64-unknown-linux-musl \
//!     -f Dockerfile.controller -t ghcr.io/onixus/ferrum-controller:v0.1.0 .
//! docker build --platform linux/arm64 --build-arg TARGET=aarch64-unknown-linux-musl \
//!     -f Dockerfile.admission  -t ghcr.io/onixus/ferrum-admission:v0.1.0 .
//! kind load docker-image --name ferrum-install \
//!     ghcr.io/onixus/ferrum-controller:v0.1.0 ghcr.io/onixus/ferrum-admission:v0.1.0
//! FERRUM_INSTALL_REQUIRED=1 FERRUM_INSTALL_CONTEXT=kind-ferrum-install \
//!     cargo test -p ferrum-testkit --features e2e --test install_gate
//! ```
//!
//! Freshness is checked, not hoped for: an existing `ferrum` namespace, an
//! existing `ferrum.io` CRD or an existing `ferrum-admission`
//! ValidatingWebhookConfiguration is a failure before anything is applied. That
//! is not tidiness: this file's whole claim is about a cluster that has never
//! seen FERRUM, and a half-installed one would decide the verdict by being a
//! different cluster from the one the claim is about.
//!
//! One reason for it is gone, and it is worth saying which. Until issue #20 a
//! cluster carrying the applied webhook refused the ClusterRoleBindings of its
//! own install: the label cache was asked about the empty namespace of a
//! cluster-scoped object, had never observed it, and failed closed. That is
//! fixed (`eval.rs::cluster_scoped_kind`), so re-applying over a running FERRUM
//! is no longer refused for that reason — but freshness is still required here,
//! because "it installs" and "it re-applies" are two claims and this file makes
//! the first.
//!
//! Its own context and not `FERRUM_E2E_CONTEXT` for that same reason: the
//! cluster `e2e_cluster.rs` leaves behind has a webhook on it, and pointing
//! this file at it would either fail for the wrong reason or pass by having
//! nothing left to create.
//!
//! There is no skip. An unset context is a failure, an unreachable cluster is a
//! failure, a workload that never becomes Ready is a failure carrying the
//! Deployment's own events. The one way not to run these is not to build them,
//! and the test outside the `cfg` below is what closes that.
//!
//! ## What it does not claim
//!
//! Nothing about the node agent coming up. `deploy/agent` is a kustomization
//! root of its own and is deliberately not part of the default install: its
//! pin-path hostPath needs bpffs mounted at /sys/fs/bpf, which a kind node does
//! not have, so kubelet answers `mkdir /sys/fs/bpf/ferrum: no such file or
//! directory` and the Pod never leaves ContainerCreating. What is claimed for
//! that root here is the half that can be: a real API server accepts every
//! object in it.
//!
//! Nothing about enforcement either. This install ends where
//! `deploy/admission/README` ends its step 2 — everything running, nothing
//! gating — because the ValidatingWebhookConfiguration is a rendered file with
//! a real CA in it and is applied deliberately, last. `e2e_cluster.rs` is where
//! a Pod gets refused.

/// The gate, compiled out.
///
/// `FERRUM_INSTALL_REQUIRED` is the caller's statement that this run *is* the
/// install gate. Without the `e2e` feature there is nothing left in this binary
/// to honour it, so this is the only place that can refuse, and it sits outside
/// the `cfg` that would remove it. A default `cargo test -p ferrum-testkit`
/// sets no such variable and still passes.
#[cfg(not(feature = "e2e"))]
#[test]
fn the_install_gate_must_not_be_compiled_out() {
    assert!(
        std::env::var_os("FERRUM_INSTALL_REQUIRED").is_none(),
        "FERRUM_INSTALL_REQUIRED is set, but this binary was built without \
         --features e2e: every test in install_gate.rs is compiled out, so this \
         run installed nothing anywhere and proves nothing about `kubectl apply \
         -k deploy`. Add --features e2e."
    );
}

#[cfg(feature = "e2e")]
mod gate {
    use ferrum_cli::gen_pki::{gen_webhook_pki, GenPkiArgs};
    use ferrum_crypto::public_key_from_secret;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::{Duration, Instant};

    /// RFC 8032 §7.1 test-1 seed. The controller's `--seed-file` here; the trust
    /// root the webhook pins is derived from it below rather than written twice.
    const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    /// The kustomization root that is the product's default install.
    const DEFAULT_INSTALL: &str = "deploy";
    /// The node agent's own root, applied separately. See the header.
    const AGENT_INSTALL: &str = "deploy/agent";

    const ROLLOUT_TIMEOUT: Duration = Duration::from_secs(240);
    const RECONCILE_TIMEOUT: Duration = Duration::from_secs(120);

    /// Both tests below touch the same cluster and one of them installs it.
    fn serialized() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crates/<crate> has two ancestors")
            .to_path_buf()
    }

    /// The kubectl context. Unset is a failure and not a skip: a run asked for
    /// the install gate that silently spoke to no cluster is the fail-open this
    /// file exists to refuse.
    fn context() -> String {
        std::env::var("FERRUM_INSTALL_CONTEXT").unwrap_or_else(|_| {
            panic!(
                "FERRUM_INSTALL_CONTEXT is unset: this binary was built with \
                 --features e2e, so it is the install gate, and it has no \
                 cluster to install into. Name a kubectl context for a cluster \
                 that carries no FERRUM (e.g. \
                 FERRUM_INSTALL_CONTEXT=kind-ferrum-install). There is no \
                 default and no skip."
            )
        })
    }

    struct Run {
        status: i32,
        stdout: String,
        stderr: String,
    }

    impl Run {
        fn ok(&self) -> bool {
            self.status == 0
        }
        fn output(&self) -> String {
            format!("{}{}", self.stdout, self.stderr)
        }
    }

    fn kubectl(args: &[&str]) -> Run {
        let ctx = context();
        let mut cmd = Command::new("kubectl");
        cmd.arg("--context").arg(&ctx).args(args);
        cmd.current_dir(repo_root());
        let out = cmd.output().unwrap_or_else(|e| {
            panic!("kubectl {args:?}: {e} — kubectl must be on PATH for the install gate")
        });
        Run {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn kubectl_ok(args: &[&str]) -> String {
        let run = kubectl(args);
        assert!(
            run.ok(),
            "kubectl {args:?} failed ({}):\n{}",
            run.status,
            run.output()
        );
        run.output()
    }

    fn wait_until(what: &str, timeout: Duration, mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        loop {
            if ready() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out after {timeout:?} waiting for {what}"
            );
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    fn scratch_dir() -> PathBuf {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!(
                "ferrum-install-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time")
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).expect("scratch dir");
            dir
        })
        .clone()
    }

    fn apply_stdin(manifest: &str, what: &str) {
        let path = scratch_dir().join(format!("{what}.yaml"));
        std::fs::write(&path, manifest).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        kubectl_ok(&["apply", "-f", path.to_str().expect("utf-8 path")]);
    }

    fn trust_root_hex() -> String {
        let seed: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&SEED_HEX[i * 2..i * 2 + 2], 16).expect("seed hex"))
            .collect();
        public_key_from_secret(&seed)
            .expect("public key from seed")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The cluster carries no FERRUM at all.
    ///
    /// Checked rather than assumed, and checked before the first apply, because
    /// every assertion below is about a first install. A cluster that already
    /// has this product also has its webhook, and that webhook refuses the
    /// ClusterRoleBindings this install creates; a run against one would fail
    /// for a reason that is not the claim, and a run against a half-installed
    /// one would pass by having little left to do.
    fn assert_cluster_is_fresh() {
        // Reachability first, so an unreachable cluster fails here rather than
        // as a puzzling apply error further down.
        kubectl_ok(&["version", "--output=json"]);

        let namespaces = kubectl_ok(&["get", "namespace", "-o", "name"]);
        assert!(
            !namespaces.lines().any(|l| l.trim() == "namespace/ferrum"),
            "the cluster named by FERRUM_INSTALL_CONTEXT already has a `ferrum` \
             namespace. This gate is about a first install on a cluster that \
             has never seen this product; point it at a fresh one (`kind create \
             cluster --name ferrum-install`) rather than at whatever \
             e2e_cluster.rs left behind."
        );
        let crds = kubectl_ok(&["get", "crd", "-o", "name"]);
        let ferrum_crds: Vec<&str> = crds
            .lines()
            .map(str::trim)
            .filter(|l| l.ends_with(".ferrum.io"))
            .collect();
        assert!(
            ferrum_crds.is_empty(),
            "the cluster already carries FERRUM CRDs: {ferrum_crds:?}. The \
             install below would be an update, and `kubectl apply` on an object \
             that already exists is not the question this file asks."
        );
        let webhooks = kubectl_ok(&["get", "validatingwebhookconfiguration", "-o", "name"]);
        assert!(
            !webhooks
                .lines()
                .any(|l| l.trim().ends_with("/ferrum-admission")),
            "the cluster already carries the ferrum-admission \
             ValidatingWebhookConfiguration. With failurePolicy=Fail it refuses \
             the cluster-scoped RoleBindings this install creates — the label \
             cache is asked about the empty namespace of a ClusterRoleBinding, \
             has never observed it and fails closed — so this run would measure \
             that defect instead of the install."
        );
    }

    /// The three things an operator supplies that are not manifests.
    ///
    /// None of them can live in a kustomization root: a signing seed and a
    /// serving key in git are the two ways this product stops being one, and a
    /// generator would mint a new key on every apply. So the install root
    /// installs everything except these, and this is the operator's half of
    /// `deploy/README`, done here exactly as that file describes it.
    fn supply_the_operator_half() {
        apply_stdin(
            &format!(
                "apiVersion: v1\nkind: Secret\nmetadata:\n  name: ferrum-signing-key\n  \
                 namespace: ferrum\ntype: Opaque\nstringData:\n  seed: {SEED_HEX}\n"
            ),
            "signing-key",
        );
        apply_stdin(
            &format!(
                "apiVersion: v1\nkind: Secret\nmetadata:\n  name: ferrum-trust-root\n  \
                 namespace: ferrum\ntype: Opaque\nstringData:\n  trustRoot: {}\n",
                trust_root_hex()
            ),
            "trust-root",
        );
        let pki = scratch_dir().join("pki");
        std::fs::create_dir_all(&pki).expect("pki dir");
        gen_webhook_pki(&GenPkiArgs {
            service: "ferrum-admission".into(),
            namespace: "ferrum".into(),
            days: 365,
            out_dir: Some(pki.clone()),
            template: Some(
                repo_root().join("deploy/admission/validatingwebhookconfiguration.tmpl.yaml"),
            ),
            ca_cert: None,
            ca_key: None,
            webhook_config: None,
        })
        .expect("ferrumctl gen-webhook-pki");
        kubectl_ok(&[
            "apply",
            "-f",
            pki.join("ferrum-admission-tls.secret.yaml")
                .to_str()
                .expect("utf-8 path"),
        ]);
    }

    fn rollout_ready(target: &str) {
        let run = kubectl(&[
            "-n",
            "ferrum",
            "rollout",
            "status",
            target,
            &format!("--timeout={}s", ROLLOUT_TIMEOUT.as_secs()),
        ]);
        assert!(
            run.ok(),
            "{target} never became Ready after `kubectl apply -k {DEFAULT_INSTALL}`. \
             The install this repository tells an operator to run does not come \
             up:\n{}\n--- pods ---\n{}\n--- events ---\n{}",
            run.output(),
            kubectl(&["-n", "ferrum", "get", "pods", "-o", "wide"]).output(),
            kubectl(&["-n", "ferrum", "get", "events", "--sort-by=.lastTimestamp"]).output()
        );
    }

    /// The install itself, once per test binary.
    ///
    /// Every step is one an operator performs, in the order `deploy/README`
    /// gives them, and every assertion is the API server's answer rather than a
    /// reading of the files that produced it:
    ///
    ///  1. the root applies — every object it renders is accepted;
    ///  2. the CRDs reach `Established`, which is the API server saying the
    ///     types exist and not this tree saying the files do;
    ///  3. the operator's half — signing seed, trust root, serving certificate;
    ///  4. the controller rolls out and compiles the shipped policy into a
    ///     signed bundle Secret;
    ///  5. the webhook rolls out on that bundle.
    ///
    /// The policy applied in step 4 is `policies/examples/prod-restricted.yaml`
    /// exactly as it ships, `mode: audit` included. `e2e_cluster.rs` flips that
    /// field because it is asking whether a Pod gets denied; this file is asking
    /// whether the install comes up, and an install that only came up under a
    /// modified policy would not be the shipped one.
    ///
    /// Once, and not once per test: the freshness precondition is true of a
    /// cluster exactly until this runs, so whichever test reaches it first has
    /// to be the one that installs. `cargo test` picks that order and nothing
    /// here may depend on which it picked.
    fn install() {
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(install_once);
    }

    fn install_once() {
        assert_cluster_is_fresh();

        let applied = kubectl(&["apply", "-k", DEFAULT_INSTALL]);
        assert!(
            applied.ok(),
            "`kubectl apply -k {DEFAULT_INSTALL}` was refused. This is the one \
             command deploy/README tells an operator to run:\n{}",
            applied.output()
        );

        for crd in [
            "clustersecuritypolicies.ferrum.io",
            "securitypolicies.ferrum.io",
            "policyexceptions.ferrum.io",
        ] {
            let established = kubectl_ok(&[
                "get",
                "crd",
                crd,
                "-o",
                "jsonpath={.status.conditions[?(@.type=='Established')].status}",
            ]);
            assert_eq!(
                established.trim(),
                "True",
                "{crd} was applied but the API server did not establish it, so \
                 an operator's first object of that kind is still an unknown type"
            );
        }

        supply_the_operator_half();
        rollout_ready("deployment/ferrum-controller");

        kubectl_ok(&["apply", "-f", "policies/examples/prod-restricted.yaml"]);
        wait_until(
            "the controller to compile and sign a bundle Secret",
            RECONCILE_TIMEOUT,
            || {
                kubectl(&[
                    "-n",
                    "ferrum",
                    "get",
                    "secret",
                    "ferrum-bundle-cluster-prod-restricted",
                ])
                .ok()
            },
        );
        let compile = kubectl_ok(&[
            "get",
            "clustersecuritypolicy",
            "prod-restricted",
            "-o",
            "jsonpath={.status.compile.message}",
        ]);
        assert_eq!(
            compile, "compiled and signed",
            "the controller installed by this root wrote a bundle Secret but did \
             not report a clean compile of the policy this repository ships"
        );

        rollout_ready("deployment/ferrum-admission");
    }

    /// `kubectl apply -k deploy` on a cluster that has never seen FERRUM brings
    /// the control plane up, and can then be applied again.
    ///
    /// The install is in `install()` above, with every assertion it makes; what
    /// is left here is the half that only means anything afterwards. The first
    /// thing an operator does after installing is install again — a changed
    /// manifest, a bumped tag, a re-run of the same command — and a root that
    /// applies only into an empty cluster is one you can adopt and never update.
    #[test]
    fn the_default_install_comes_up_on_a_fresh_cluster() {
        let _lock = serialized();
        install();

        let again = kubectl(&["apply", "-k", DEFAULT_INSTALL]);
        assert!(
            again.ok(),
            "the second `kubectl apply -k {DEFAULT_INSTALL}` was refused, so this \
             install can be performed once and never updated:\n{}",
            again.output()
        );
    }

    /// The node agent's root is accepted by a real API server.
    ///
    /// The narrow half, and it is narrow on purpose. `deploy/agent` is not part
    /// of the default install because its Pod does not start on a kind node —
    /// the pin-path hostPath wants bpffs at /sys/fs/bpf and kubelet answers
    /// `mkdir /sys/fs/bpf/ferrum: no such file or directory`. That is a fact
    /// about the node, and no assertion here can turn it into a fact about the
    /// manifest. What can be established is everything up to the node: the root
    /// renders, and every object in it is one the API server accepts.
    ///
    /// `--dry-run=server` rather than an apply, so this stays a question and
    /// does not leave a DaemonSet the test above would then have to reason
    /// about. The install still has to have happened: every namespaced object
    /// in this root lives in `ferrum`, and a dry run against a cluster without
    /// that namespace is refused for a reason that has nothing to do with the
    /// manifests.
    #[test]
    fn the_agent_root_is_accepted_by_a_real_apiserver() {
        let _lock = serialized();
        install();
        let run = kubectl(&["apply", "--dry-run=server", "-k", AGENT_INSTALL]);
        assert!(
            run.ok(),
            "the API server refused an object in `{AGENT_INSTALL}`. Whatever else \
             keeps this root out of the default install, it is supposed to be \
             the node and not the manifests:\n{}",
            run.output()
        );
    }
}
