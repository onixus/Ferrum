//! RFC §D against a real API server.
//!
//! `acceptance.rs` runs the same pipeline in-process: it builds an
//! `AdmissionSubject` by hand, calls `admit()` and reads the answer. Everything
//! between a `kubectl apply` and that call is absent from it — the CRDs, the
//! controller's watch, the Secret it writes, the kubelet mount the webhook
//! reads, the TLS the API server dials, the `ValidatingWebhookConfiguration`
//! that decides whether the webhook is asked at all. Each of those was
//! *reviewed* and none of them was executed, and the first run of this file
//! found three of them broken in ways no in-process test could see: two CRDs
//! the API server refuses outright (`docs/crd/*.yaml`), and images that could
//! not be built for the node's architecture (`Dockerfile*`).
//!
//! So the claim this file makes is narrow and is not the one `acceptance.rs`
//! makes: **a Pod submitted to a real API server is denied by a webhook serving
//! a bundle a real controller compiled and signed.** Nothing here constructs a
//! subject, an `AdmissionReview` or a decision; the only inputs are YAML in
//! this repository and the only outputs are the API server's own answers.
//!
//! ## What it needs, and what happens when it is absent
//!
//! A cluster, named by `FERRUM_E2E_CONTEXT` (a kubectl context), and the three
//! images already loaded onto its nodes:
//!
//! ```text
//! kind create cluster --name ferrum-e2e
//! docker build --platform linux/arm64 --build-arg TARGET=aarch64-unknown-linux-musl \
//!     -f Dockerfile.controller -t ghcr.io/ferrum/ferrum-controller:v0.1.0 .
//! docker build --platform linux/arm64 --build-arg TARGET=aarch64-unknown-linux-musl \
//!     -f Dockerfile.admission  -t ghcr.io/ferrum/ferrum-admission:v0.1.0 .
//! kind load docker-image --name ferrum-e2e \
//!     ghcr.io/ferrum/ferrum-controller:v0.1.0 ghcr.io/ferrum/ferrum-admission:v0.1.0
//! FERRUM_E2E_REQUIRED=1 FERRUM_E2E_CONTEXT=kind-ferrum-e2e \
//!     cargo test -p ferrum-testkit --features e2e --test e2e_cluster
//! ```
//!
//! There is no skip anywhere below. `FERRUM_E2E_CONTEXT` unset is a failure,
//! not a pass; a context that does not answer is a failure; an image that never
//! becomes Ready is a failure with the Deployment's own events in the message.
//! A gate that can decide it was not asked to run is the defect this repository
//! exists against, so the only way to not run these is to not build them — and
//! that hole is closed by the one test outside the `cfg` below, the same way
//! `ferrum-ebpf/tests/attach_live.rs` closes it for the kernel gate.
//!
//! ## What it does not cover, and this is mechanical
//!
//! `NOT_COVERED_HERE` names every §D case this file cannot decide, each with
//! the reason, and `the_uncovered_cases_are_named_not_omitted` requires that
//! list plus `COVERED` to be exactly `AcceptanceCase::ALL`. A case cannot be
//! dropped from this file by being forgotten; it can only be dropped by being
//! written down as uncovered.

/// The gate, compiled out.
///
/// `FERRUM_E2E_REQUIRED` is the caller's statement that this run *is* the
/// cluster gate. Without the `e2e` feature there is nothing left in this binary
/// to honour it — every test below is removed and the binary exits 0 having
/// executed nothing — so this is the only place that can refuse, and it is
/// deliberately outside the `cfg` that would remove it. A default
/// `cargo test -p ferrum-testkit`, which sets no such variable, still passes.
#[cfg(not(feature = "e2e"))]
#[test]
fn the_cluster_gate_must_not_be_compiled_out() {
    assert!(
        std::env::var_os("FERRUM_E2E_REQUIRED").is_none(),
        "FERRUM_E2E_REQUIRED is set, but this binary was built without \
         --features e2e: every cluster test in e2e_cluster.rs is compiled out, \
         so this run spoke to no API server and proves nothing about the \
         install. Add --features e2e."
    );
}

#[cfg(feature = "e2e")]
mod gate {
    use ferrum_cli::gen_pki::{gen_webhook_pki, GenPkiArgs, WEBHOOK_RENDERED_FILE};
    use ferrum_crypto::public_key_from_secret;
    use ferrum_testkit::AcceptanceCase;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::{Duration, Instant};

    /// RFC 8032 §7.1 test-1 seed, the same fixture key `acceptance.rs` signs
    /// with. It is the controller's `--seed-file` here, so the trust root the
    /// webhook pins is derived from it rather than written down twice.
    const SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    /// The namespace the acceptance Pods go into. Labelled `ferrum.io/zone=pci`
    /// because `prod-restricted`'s selector is a `namespaceSelector` on exactly
    /// that: an unlabelled namespace is not selected and every Pod in it is
    /// allowed, which would make these tests pass by not being asked.
    const WORKLOAD_NS: &str = "ferrum-e2e-pci";

    /// Long enough for an image pull on a cold node, short enough that a
    /// genuinely stuck rollout is reported rather than waited on forever.
    const ROLLOUT_TIMEOUT: Duration = Duration::from_secs(180);
    /// The controller compiles on its first reconcile; this is the wait for the
    /// Secret that reconcile writes.
    const RECONCILE_TIMEOUT: Duration = Duration::from_secs(120);

    /// Every case below mutates cluster state — one of them deletes the policy
    /// object and scales the controller away — so they take turns. `cargo test`
    /// runs test functions on parallel threads, and two of these at once would
    /// have one reading the cluster the other is halfway through rebuilding.
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

    /// The kubectl context. Unset is a failure and not a skip: a run that was
    /// asked for the cluster gate and silently did not speak to a cluster is
    /// the fail-open this file exists to refuse.
    fn context() -> String {
        std::env::var("FERRUM_E2E_CONTEXT").unwrap_or_else(|_| {
            panic!(
                "FERRUM_E2E_CONTEXT is unset: this binary was built with \
                 --features e2e, so it is the cluster gate, and it has no \
                 cluster to run against. Name a kubectl context (e.g. \
                 FERRUM_E2E_CONTEXT=kind-ferrum-e2e). There is no default and \
                 no skip."
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
        /// Both streams. `kubectl` puts a webhook's denial on stderr and the
        /// object it did create on stdout, and every assertion below is about
        /// one or the other without caring which.
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
            panic!("kubectl {args:?}: {e} — kubectl must be on PATH for the cluster gate")
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

    /// Poll until `ready` answers true. A timeout is a failure carrying
    /// `describe`-grade context, never a pass.
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

    fn apply(paths: &[&str]) {
        let mut args = vec!["apply"];
        for p in paths {
            args.push("-f");
            args.push(p);
        }
        kubectl_ok(&args);
    }

    fn apply_stdin(manifest: &str, what: &str) {
        let path = scratch_file(&format!("{what}.yaml"), manifest);
        kubectl_ok(&["apply", "-f", path.to_str().expect("utf-8 path")]);
    }

    /// A per-process scratch directory. `gen_webhook_pki` refuses to overwrite
    /// its own output, which is the behaviour the deploy tree wants and the
    /// reason this is per-run rather than a fixed path.
    fn scratch_dir() -> PathBuf {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!(
                "ferrum-e2e-{}-{}",
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

    fn scratch_file(name: &str, body: &str) -> PathBuf {
        let path = scratch_dir().join(name);
        std::fs::write(&path, body).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        path
    }

    /// `policies/examples/prod-restricted.yaml` with `mode: enforce`.
    ///
    /// The shipped file is `mode: audit`, and audit allows: `admit()` returns
    /// `allowed` for every mode but `enforce`. Applying it unchanged would make
    /// all three cases below pass while denying nothing, because the webhook
    /// would be asked and would answer yes. `acceptance.rs` flips the same
    /// field for the same reason, in code rather than in YAML; this is that
    /// flip, on the file the repository ships, with nothing else touched.
    fn prod_restricted_enforce() -> String {
        let path = repo_root().join("policies/examples/prod-restricted.yaml");
        let raw =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let mut doc: serde_yaml::Value = serde_yaml::from_str(&raw).expect("policy yaml");
        let spec = doc
            .get_mut("spec")
            .and_then(serde_yaml::Value::as_mapping_mut)
            .expect("policy has a spec mapping");
        let previous = spec.insert("mode".into(), "enforce".into());
        assert_eq!(
            previous,
            Some(serde_yaml::Value::from("audit")),
            "policies/examples/prod-restricted.yaml no longer says `mode: audit`. \
             This harness flips exactly that value and asserts what it replaced, \
             so a shipped file that already enforces — or that stopped carrying \
             a mode — must be read before this line is changed."
        );
        serde_yaml::to_string(&doc).expect("policy yaml")
    }

    fn trust_root_hex() -> String {
        let seed = (0..32)
            .map(|i| u8::from_str_radix(&SEED_HEX[i * 2..i * 2 + 2], 16).expect("seed hex"))
            .collect::<Vec<u8>>();
        let pk = public_key_from_secret(&seed).expect("public key from seed");
        pk.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The whole install, once per test binary, from the files in this tree.
    ///
    /// Idempotent by `kubectl apply`, because a developer re-runs this against
    /// a cluster that is already half-installed far more often than against an
    /// empty one. The one step that is not idempotent is the PKI: every run
    /// issues a fresh CA, so every run replaces the serving Secret and restarts
    /// the webhook — the deploy README's step 5, not its step 4, because a new
    /// CA is exactly what the running process pins against and refuses.
    fn install() {
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            // Reachability first, so an unreachable cluster fails here and not
            // as a puzzling apply error twenty lines down.
            kubectl_ok(&["version", "--output=json"]);

            // 1. The CRDs, from docs/crd. `the_shipped_crds_are_accepted_by_a_real_apiserver`
            //    is the test that makes this step a claim rather than a step.
            apply(&["docs/crd/"]);
            apply(&["deploy/namespace.yaml"]);

            // 2. The signing key the controller compiles with, and the trust
            //    root the webhook pins — derived from it, not written twice.
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

            // 3. The controller, from deploy/controller.
            apply(&[
                "deploy/controller/serviceaccount.yaml",
                "deploy/controller/rbac.yaml",
                "deploy/controller/deployment.yaml",
            ]);
            rollout_ready("deployment/ferrum-controller");

            // 4. The policy. From here on the bundle is the controller's work:
            //    nothing in this file compiles or signs anything.
            apply_policy();

            // 5. The webhook, from deploy/admission, with PKI issued by the CLI
            //    this repository ships rather than by a copy of it.
            let pki = issue_pki();
            apply(&[pki
                .join("ferrum-admission-tls.secret.yaml")
                .to_str()
                .expect("utf-8 path")]);
            apply(&[
                "deploy/admission/serviceaccount.yaml",
                "deploy/admission/rbac.yaml",
                "deploy/admission/service.yaml",
                "deploy/admission/deployment.yaml",
            ]);
            // A fresh CA every run, and the process pins the issuer it started
            // with: replacing the Secret under a running pod is refused by
            // design, so the pods are replaced with it.
            kubectl_ok(&[
                "-n",
                "ferrum",
                "rollout",
                "restart",
                "deployment/ferrum-admission",
            ]);
            rollout_ready("deployment/ferrum-admission");
            admission_pod_set_settled();

            // 6. The namespace the acceptance Pods live in, labelled so the
            //    policy's namespaceSelector actually selects it.
            apply_stdin(
                &format!(
                    "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {WORKLOAD_NS}\n  \
                     labels:\n    ferrum.io/zone: pci\n"
                ),
                "workload-namespace",
            );

            // 7. The webhook configuration last, exactly as deploy/admission's
            //    README orders it: with failurePolicy=Fail it starts gating the
            //    cluster the moment it exists, so nothing that has to be applied
            //    may come after it.
            apply(&[pki
                .join(WEBHOOK_RENDERED_FILE)
                .to_str()
                .expect("utf-8 path")]);
        });
    }

    fn apply_policy() {
        apply_stdin(&prod_restricted_enforce(), "prod-restricted-enforce");
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
        let status = kubectl_ok(&[
            "get",
            "clustersecuritypolicy",
            "prod-restricted",
            "-o",
            "jsonpath={.status.compile.message}",
        ]);
        assert_eq!(
            status, "compiled and signed",
            "the controller wrote the bundle Secret but did not report a clean \
             compile on the policy status"
        );
    }

    fn issue_pki() -> PathBuf {
        let dir = scratch_dir().join("pki");
        std::fs::create_dir_all(&dir).expect("pki dir");
        gen_webhook_pki(&GenPkiArgs {
            service: "ferrum-admission".into(),
            namespace: "ferrum".into(),
            days: 365,
            out_dir: Some(dir.clone()),
            template: Some(
                repo_root().join("deploy/admission/validatingwebhookconfiguration.tmpl.yaml"),
            ),
            ca_cert: None,
            ca_key: None,
            webhook_config: None,
        })
        .expect("ferrumctl gen-webhook-pki");
        dir
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
            "{target} never became Ready:\n{}\n--- pods ---\n{}",
            run.output(),
            kubectl(&["-n", "ferrum", "get", "pods", "-o", "wide"]).output()
        );
    }

    /// Submit a Pod and return what the API server said. `Ok(())` means it was
    /// created — which for every Pod below is the failure.
    fn create_pod(name: &str, spec: &str) -> Run {
        // Delete first: a Pod left behind by an earlier run would make the
        // apply a no-op update and the webhook's answer a different question.
        kubectl(&[
            "-n",
            WORKLOAD_NS,
            "delete",
            "pod",
            name,
            "--ignore-not-found",
        ]);
        let manifest = format!(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {name}\n  namespace: {WORKLOAD_NS}\n\
             spec:\n{spec}"
        );
        let path = scratch_file(&format!("pod-{name}.yaml"), &manifest);
        kubectl(&["apply", "-f", path.to_str().expect("utf-8 path")])
    }

    /// A Pod was refused *by this webhook*, with this reason.
    ///
    /// The reason is not decoration. With `failurePolicy: Fail` an API server
    /// that cannot reach the webhook at all also refuses every Pod, and a test
    /// that only checked "not created" would read a dead webhook as a working
    /// one — which is precisely the shape of the fail-open the last-known-good
    /// case below exists to rule out.
    fn assert_denied_by_ferrum(run: &Run, reason: &str) {
        let out = run.output();
        assert!(
            !run.ok(),
            "the API server created this Pod; the webhook allowed what the \
             policy denies:\n{out}"
        );
        assert!(
            out.contains("admission webhook \"policy.ferrum.io\" denied the request"),
            "the Pod was refused, but not by policy.ferrum.io — an unreachable \
             webhook under failurePolicy=Fail refuses Pods too, and that is not \
             this claim:\n{out}"
        );
        assert!(
            out.contains(reason),
            "policy.ferrum.io denied the Pod but not for {reason:?}:\n{out}"
        );
    }

    /// RFC §D: unsigned image → deny, decided by a real API server.
    ///
    /// The image is in the registry the policy allows and is not signed: no
    /// `ferrum.io/image-signature` annotation exists, so `supply.denyUnsigned`
    /// is what refuses it. The reason string is the webhook's, read back off
    /// the API server's response.
    #[test]
    fn an_unsigned_image_is_denied_by_the_real_apiserver() {
        let _lock = serialized();
        install();
        let run = create_pod(
            "e2e-unsigned",
            "  containers:\n    - name: app\n      image: registry.internal.example/app:v1\n",
        );
        assert_denied_by_ferrum(&run, "unsigned image");
    }

    /// RFC §D: privileged → deny, decided by a real API server.
    #[test]
    fn a_privileged_pod_is_denied_by_the_real_apiserver() {
        let _lock = serialized();
        install();
        let run = create_pod(
            "e2e-privileged",
            "  containers:\n    - name: app\n      image: \
             registry.internal.example/app@sha256:\
             0000000000000000000000000000000000000000000000000000000000000000\n      \
             securityContext:\n        privileged: true\n",
        );
        assert_denied_by_ferrum(&run, "privileged container");
    }

    /// RFC §D: CP down → last-known-good, not fail-open, in a real cluster.
    ///
    /// "CP down" here is not a flag on an in-process `Agent`, which is what
    /// `acceptance.rs::cp_down_keeps_last_known_good_not_fail_open` sets. It is
    /// the FERRUM control plane actually removed from a running cluster: the
    /// controller scaled to zero, the `ClusterSecurityPolicy` deleted from the
    /// API server, and the Secret the webhook mounts deleted with it. Nothing
    /// that could re-issue a decision is left.
    ///
    /// The webhook must go on denying, and denying *with its own reason* —
    /// which is the half that separates last-known-good from a dead pod behind
    /// `failurePolicy: Fail`. It must do so without a restart: a restarted pod
    /// would have re-read a mount, and the claim is about the process that
    /// never saw the deletion.
    ///
    /// Restores what it removed, because the other two cases share this
    /// cluster.
    #[test]
    fn a_control_plane_that_is_gone_keeps_the_webhook_on_last_known_good() {
        let _lock = serialized();
        install();

        // Baseline: the webhook denies while the control plane is up. Without
        // it a webhook that had never worked would pass the whole test.
        assert_denied_by_ferrum(
            &create_pod(
                "e2e-lkg-baseline",
                "  containers:\n    - name: app\n      image: \
                 registry.internal.example/app@sha256:\
                 0000000000000000000000000000000000000000000000000000000000000000\n      \
                 securityContext:\n        privileged: true\n",
            ),
            "privileged container",
        );
        admission_pod_set_settled();
        let pods_before = admission_pods();
        assert!(
            !pods_before.is_empty(),
            "no webhook Pods at all, so nothing below is about a process \
             holding a bundle"
        );

        kubectl_ok(&[
            "-n",
            "ferrum",
            "scale",
            "deployment/ferrum-controller",
            "--replicas=0",
        ]);
        kubectl_ok(&["delete", "clustersecuritypolicy", "prod-restricted"]);
        kubectl_ok(&[
            "-n",
            "ferrum",
            "delete",
            "secret",
            "ferrum-bundle-cluster-prod-restricted",
        ]);
        wait_until("the controller Pods to go away", ROLLOUT_TIMEOUT, || {
            kubectl_ok(&[
                "-n",
                "ferrum",
                "get",
                "pods",
                "-l",
                "app.kubernetes.io/name=ferrum-controller",
                "-o",
                "jsonpath={.items[*].metadata.name}",
            ])
            .trim()
            .is_empty()
        });

        assert_denied_by_ferrum(
            &create_pod(
                "e2e-lkg-after",
                "  containers:\n    - name: app\n      image: \
                 registry.internal.example/app@sha256:\
                 0000000000000000000000000000000000000000000000000000000000000000\n      \
                 securityContext:\n        privileged: true\n",
            ),
            "privileged container",
        );
        assert_eq!(
            admission_pods(),
            pods_before,
            "the webhook Pods are not the ones that answered before the control \
             plane went away — one restarted or was replaced. Whatever answered \
             afterwards re-read its mount on startup, so this run says nothing \
             about a process holding a bundle whose source is gone."
        );

        // Put it back for whichever case runs next.
        apply(&[
            "deploy/controller/serviceaccount.yaml",
            "deploy/controller/rbac.yaml",
            "deploy/controller/deployment.yaml",
        ]);
        kubectl_ok(&[
            "-n",
            "ferrum",
            "scale",
            "deployment/ferrum-controller",
            "--replicas=1",
        ]);
        rollout_ready("deployment/ferrum-controller");
        apply_policy();
    }

    /// The webhook Pods by name, each with its container restart count.
    ///
    /// Names and not just a sum: a Pod that was replaced and a Pod that
    /// restarted are the same claim here — neither process is the one that
    /// answered before — and a sum cannot tell either from a rollout that
    /// happened to keep the total at zero.
    fn admission_pods() -> Vec<String> {
        let raw = kubectl_ok(&[
            "-n",
            "ferrum",
            "get",
            "pods",
            "-l",
            "app.kubernetes.io/name=ferrum-admission",
            "-o",
            "jsonpath={range .items[*]}{.metadata.name}={.status.containerStatuses[*].restartCount}\n{end}",
        ]);
        let mut out: Vec<String> = raw
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        out.sort();
        out
    }

    /// Wait until the webhook Deployment has exactly its desired Pods and no
    /// leftovers. `rollout status` returns as soon as the new Pods are Ready,
    /// while the ones it replaced are still terminating and still listed, so a
    /// Pod census taken right after it is a census of a set that is about to
    /// change on its own.
    fn admission_pod_set_settled() {
        let want = kubectl_ok(&[
            "-n",
            "ferrum",
            "get",
            "deployment/ferrum-admission",
            "-o",
            "jsonpath={.spec.replicas}",
        ])
        .trim()
        .parse::<usize>()
        .expect("replicas is a number");
        wait_until(
            "the webhook Pod set to settle at its desired size",
            ROLLOUT_TIMEOUT,
            || admission_pods().len() == want,
        );
    }

    /// The CRDs this repository ships install into a real API server.
    ///
    /// Not a formality, and not something `deploy_gate.rs` can answer: it reads
    /// the YAML and checks that rules with the right shape are present, which
    /// is a statement about the text. The first run of this file found two of
    /// the seven files rejected outright — a CEL cost budget on
    /// `clustersecuritypolicy`/`securitypolicy`, and `now()` on
    /// `policyexception`, which does not exist in the API server's CEL because
    /// CRD validation has no clock. Neither is visible to a reader and neither
    /// was visible to any gate: the rules were held by a test that read them
    /// out of the file it was asserting about.
    ///
    /// `--dry-run=server` rather than a plain apply so this stays a question
    /// and not a second install.
    #[test]
    fn the_shipped_crds_are_accepted_by_a_real_apiserver() {
        let _lock = serialized();
        let run = kubectl(&["apply", "--dry-run=server", "-f", "docs/crd/"]);
        assert!(
            run.ok(),
            "the API server refused a CRD this repository ships. Every schema \
             rule in the refused file is inert until it is fixed — including the \
             ones deploy_gate.rs reads out of the text and reports as held:\n{}",
            run.output()
        );
    }

    /// The §D cases this file decides, bound to the shared list by the real
    /// test functions. A renamed test stops compiling here; a case added to
    /// `AcceptanceCase` fails the completeness test below until it is either
    /// covered or written down as uncovered.
    const COVERED: [(AcceptanceCase, fn()); 3] = [
        (
            AcceptanceCase::UnsignedDeny,
            an_unsigned_image_is_denied_by_the_real_apiserver,
        ),
        (
            AcceptanceCase::PrivilegedDeny,
            a_privileged_pod_is_denied_by_the_real_apiserver,
        ),
        (
            AcceptanceCase::ControlPlaneDownLkg,
            a_control_plane_that_is_gone_keeps_the_webhook_on_last_known_good,
        ),
    ];

    /// The §D cases this file does not decide, each with the reason it cannot.
    ///
    /// Prose in a doc comment would let a case leave this file by being
    /// forgotten. This list plus `COVERED` must be `AcceptanceCase::ALL`, so a
    /// case can only leave by being written down here — and every entry is a
    /// piece of work that is not done, stated in the place a reader of the
    /// covered cases will see it.
    const NOT_COVERED_HERE: [(AcceptanceCase, &str); 5] = [
        (
            AcceptanceCase::ClusterAdminBindDeny,
            "the webhook does gate clusterrolebindings, but `prod-restricted` \
             selects on a namespaceSelector and a ClusterRoleBinding has no \
             namespace: the label cache is asked about \"\", has never observed \
             it, and the request is refused as `namespace labels were never \
             observed; fail closed` rather than for the bind. Denied either \
             way, and for the wrong reason — which this file's own \
             assert_denied_by_ferrum would not accept as the case.",
        ),
        (
            AcceptanceCase::ExceptionWithoutTtlReject,
            "an API server now runs here and this case is about an API server, \
             so this is the one entry that is a gap rather than a boundary. It \
             belongs in this file. It is not in it because issue #13 named four \
             cases and this is not one of them.",
        ),
        (
            AcceptanceCase::ExecShellKill,
            "needs the agent DaemonSet, and `deploy/agent/daemonset.yaml` does \
             not start on containerd: it mounts a hostPath at \
             /sys/fs/bpf/ferrum, runc has to create that mountpoint inside the \
             container's own sysfs, and sysfs is read-only — `mkdirat \
             .../rootfs/sys/fs/bpf/ferrum: no such file or directory`. The \
             repair is a change to the manifest's pin-path mount with a \
             threat-model question in it (mounting /sys/fs/bpf whole hands the \
             agent the node's entire bpffs), not a change to this file.",
        ),
        (
            AcceptanceCase::DockerSockKill,
            "the same DaemonSet and the same runc refusal as the case above: \
             nothing in this cluster is watching openat, so there is no record \
             for a rule to decide and no process to signal.",
        ),
        (
            AcceptanceCase::BpfNotFromAgentDeny,
            "the same DaemonSet and the same runc refusal. The runtime half \
             of this case is an audit record either way — a tracepoint fires \
             after the syscall returned — and the deny half is admission's, \
             decided on a capability no Pod here carries.",
        ),
    ];

    /// Every §D case is either decided here or named as not decided here.
    ///
    /// The same shape as `acceptance.rs::every_acceptance_case_has_a_test` and
    /// `replay.rs`, with one difference that matters: this file is not expected
    /// to cover everything, so the gate is on the *partition* rather than on
    /// the coverage. A case that is neither covered nor named fails it, and so
    /// does a case that is both — an entry left in `NOT_COVERED_HERE` after the
    /// test for it landed is the boundary understating the tree, which is the
    /// direction this repository's documents rot in.
    #[test]
    fn the_uncovered_cases_are_named_not_omitted() {
        let covered: Vec<AcceptanceCase> = COVERED.iter().map(|(c, _)| *c).collect();
        let uncovered: Vec<AcceptanceCase> = NOT_COVERED_HERE.iter().map(|(c, _)| *c).collect();
        for case in AcceptanceCase::ALL {
            let in_covered = covered.contains(case);
            let in_uncovered = uncovered.contains(case);
            assert!(
                in_covered || in_uncovered,
                "§D case {:?} is neither decided by this file nor named in \
                 NOT_COVERED_HERE with the reason it is not",
                case.label()
            );
            assert!(
                !(in_covered && in_uncovered),
                "§D case {:?} is both covered and listed as uncovered: remove \
                 the NOT_COVERED_HERE entry, the work it describes is done",
                case.label()
            );
        }
        assert_eq!(
            covered.len() + uncovered.len(),
            AcceptanceCase::ALL.len(),
            "a case is listed twice"
        );
        for (case, reason) in NOT_COVERED_HERE {
            assert!(
                reason.len() > 40,
                "§D case {:?} is excused by {reason:?}, which is not a reason",
                case.label()
            );
        }
    }
}
