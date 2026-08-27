// Локальный CI Ferrum на http://localhost:8081.
// Сборка в docker.image().inside(): CARGO_TARGET_DIR обязан быть named volume.
// Bind-mount macOS/VirtioFS ломает cargo недетерминированно (E0463 can't find crate).
// clippy — check-only (.rmeta); cargo test после него пересоберёт .rlib — это ожидаемо.

def RUST_IMAGE = 'rust:1.75-bookworm'
def RUST_DOCKER_ARGS = '-v ferrum-cargo-home:/usr/local/cargo/registry -v ferrum-cargo-target:/build-target'

pipeline {
    agent {
        docker {
            image RUST_IMAGE
            args RUST_DOCKER_ARGS
            reuseNode true
        }
    }

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        // BPF ELF stage adds nightly install + build-std + bpf-linker on a cold cache.
        timeout(time: 45, unit: 'MINUTES')
    }

    environment {
        CARGO_TARGET_DIR = '/build-target'
        CARGO_TERM_COLOR = 'never'
    }

    stages {
        stage('Format') {
            steps {
                sh '''
                    set -eu
                    rustup component add rustfmt
                    cargo fmt --all -- --check
                '''
            }
        }

        stage('Clippy') {
            steps {
                sh '''
                    set -eu
                    rustup component add clippy
                    cargo clippy --workspace --all-targets -- -D warnings
                    cargo clippy -p ferrum-ebpf --features attach --all-targets -- -D warnings
                    # Default features hide the production paths: the k8smeta
                    # apiserver client and the agent's real datapath are only
                    # compiled behind these.
                    cargo clippy -p ferrum-k8smeta --features apiserver --all-targets -- -D warnings
                    cargo clippy -p ferrum-agent --features attach --all-targets -- -D warnings
                    # attach+apiserver is the only production combination: the
                    # cgroup sync into ferrum_cgroups is compiled out of every
                    # other one.
                    cargo clippy -p ferrum-agent --features attach,apiserver --all-targets -- -D warnings
                '''
            }
        }

        stage('Test') {
            steps {
                sh '''
                    set -eu
                    cargo test --workspace
                '''
            }
        }

        stage('BPF ELF') {
            steps {
                sh '''
                    set -eu
                    rustup toolchain install nightly --profile minimal --component rust-src
                    # bpf-linker (default rust-llvm feature) links -lLLVM from the
                    # nightly rustc; the image ships no plain libLLVM.so, so shim
                    # the versioned one and keep the sysroot on rpath.
                    if ! command -v bpf-linker >/dev/null 2>&1; then
                        sysroot="$(rustc +nightly --print sysroot)"
                        shim=/tmp/ferrum-llvm-shim
                        mkdir -p "$shim"
                        ln -sf "$sysroot"/lib/libLLVM-*.so "$shim/libLLVM.so"
                        RUSTFLAGS="-L $shim -L $sysroot/lib -C link-arg=-Wl,-rpath,$sysroot/lib" \
                            cargo +nightly install bpf-linker --locked
                    fi
                    cargo +nightly build -p ferrum-ebpf-progs \
                        --target bpfel-unknown-none -Z build-std=core --release
                    elf="$CARGO_TARGET_DIR/bpfel-unknown-none/release/ferrum-ebpf-progs"
                    readelf -sW "$elf" > /tmp/ferrum-bpf-symbols.txt
                    for sym in \
                        ferrum_sys_enter_execve \
                        ferrum_sys_enter_execveat \
                        ferrum_sys_enter_open \
                        ferrum_sys_enter_openat \
                        ferrum_sys_enter_bpf \
                        ferrum_sys_enter_init_module \
                        ferrum_sys_enter_finit_module \
                        ferrum_events \
                        ferrum_cgroups \
                        ferrum_self \
                        events_dropped_total
                    do
                        if ! grep -Eq "[[:space:]]$sym\$" /tmp/ferrum-bpf-symbols.txt; then
                            echo "missing symbol $sym in bpf ELF" >&2
                            exit 1
                        fi
                    done
                    FERRUM_BPF_ELF_REQUIRED=1 FERRUM_BPF_ELF="$elf" cargo test -p ferrum-ebpf --test elf_inspect
                    mkdir -p dist
                    cp "$elf" dist/ferrum-ebpf-progs.bpf.o
                '''
                archiveArtifacts artifacts: 'dist/ferrum-ebpf-progs.bpf.o', fingerprint: true
            }
        }

        stage('Crate boundary') {
            steps {
                sh '''
                    set -eu
                    # ferrum-crypto/x509 pulls a certificate generator and a
                    # parser. Only ferrumctl issues PKI; the decision path must
                    # not link either. Per-crate graphs are what a release build
                    # resolves (`cargo build -p ...`); a --workspace graph
                    # unifies features across members and always shows them, so
                    # it cannot answer this question.
                    fail=0
                    for target in \
                        "ferrum-admission:" \
                        "ferrum-admission:apiserver" \
                        "ferrum-agent:" \
                        "ferrum-agent:attach" \
                        "ferrum-agent:apiserver" \
                        "ferrum-agent:attach,apiserver"
                    do
                        crate="${target%%:*}"
                        features="${target#*:}"
                        if [ -n "$features" ]; then
                            tree="$(cargo tree -p "$crate" -e normal --features "$features")"
                        else
                            tree="$(cargo tree -p "$crate" -e normal)"
                        fi
                        for forbidden in rcgen x509-parser; do
                            if printf '%s\n' "$tree" | grep -qE "(^| )$forbidden v"; then
                                echo "crate boundary: $crate (features=${features:-default}) links $forbidden" >&2
                                fail=1
                            fi
                        done
                    done
                    if [ "$fail" -ne 0 ]; then
                        echo "the admission/agent dependency graph must not carry ferrum-crypto/x509" >&2
                        exit 1
                    fi
                    echo "ok: rcgen and x509-parser stay off the admission and agent graphs"
                '''
            }
        }

        stage('Validate policies') {
            steps {
                sh '''
                    set -eu
                    cargo run -p ferrum-cli --quiet -- validate policies/examples/prod-restricted.yaml
                    cargo run -p ferrum-cli --quiet -- validate policies/examples/exception-ok.yaml
                    cargo run -p ferrum-cli --quiet -- validate policies/examples/policy-library.yaml
                    cargo run -p ferrum-cli --quiet -- validate policies/examples/runtime-profile.yaml
                    cargo run -p ferrum-cli --quiet -- validate policies/examples/ferrum-cluster.yaml
                    cargo run -p ferrum-cli --quiet -- validate policies/examples/compliance-snapshot.yaml
                    set +e
                    cargo run -p ferrum-cli --quiet -- validate policies/examples/exception-bad-no-ticket.yaml >/tmp/ferrum-bad-exception.out 2>/tmp/ferrum-bad-exception.err
                    status=$?
                    set -e
                    if [ "$status" -eq 0 ]; then
                        echo "exception-bad-no-ticket.yaml must fail validation" >&2
                        exit 1
                    fi
                    echo "ok: exception-bad-no-ticket.yaml rejected"
                    cargo run -p ferrum-cli --quiet -- lint-deploy deploy
                    # The committed tree carries a webhook template, not an
                    # applicable configuration. Prove the issuance step closes
                    # that gap instead of trusting the template alone.
                    rm -rf /tmp/ferrum-pki && cp -r deploy /tmp/ferrum-pki
                    cargo run -p ferrum-cli --quiet -- gen-webhook-pki \
                        --service ferrum-admission --namespace ferrum --days 365 \
                        --out-dir /tmp/ferrum-pki/admission
                    set +e
                    cargo run -p ferrum-cli --quiet -- gen-webhook-pki \
                        --service ferrum-admission --namespace ferrum --days 365 \
                        --out-dir /tmp/ferrum-pki/admission >/dev/null 2>&1
                    status=$?
                    set -e
                    if [ "$status" -eq 0 ]; then
                        echo "gen-webhook-pki must refuse to overwrite issued PKI" >&2
                        exit 1
                    fi
                    echo "ok: gen-webhook-pki refuses to overwrite"
                    # The template is not applied; only the rendered file is.
                    rm /tmp/ferrum-pki/admission/validatingwebhookconfiguration.tmpl.yaml
                    cargo run -p ferrum-cli --quiet -- lint-deploy /tmp/ferrum-pki
                    rm -rf /tmp/ferrum-pki
                    set +e
                    cargo run -p ferrum-cli --quiet -- lint-deploy crates/ferrum-testkit/fixtures/deploy-bad-cabundle >/tmp/ferrum-bad-cabundle.out 2>/tmp/ferrum-bad-cabundle.err
                    status=$?
                    set -e
                    if [ "$status" -eq 0 ]; then
                        echo "fixtures/deploy-bad-cabundle must fail lint-deploy" >&2
                        exit 1
                    fi
                    echo "ok: caBundle placeholder rejected"
                    set +e
                    cargo run -p ferrum-cli --quiet -- lint-deploy crates/ferrum-testkit/fixtures/deploy-bad >/tmp/ferrum-bad-deploy.out 2>/tmp/ferrum-bad-deploy.err
                    status=$?
                    set -e
                    if [ "$status" -eq 0 ]; then
                        echo "fixtures/deploy-bad must fail lint-deploy" >&2
                        exit 1
                    fi
                    echo "ok: fixtures/deploy-bad rejected"
                '''
            }
        }
    }

    post {
        success {
            echo 'Ferrum CI passed on Jenkins :8081'
        }
        failure {
            echo 'Ferrum CI failed'
        }
    }
}
