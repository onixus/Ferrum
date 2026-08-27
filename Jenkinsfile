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
                    FERRUM_BPF_ELF="$elf" cargo test -p ferrum-ebpf --test elf_inspect
                    mkdir -p dist
                    cp "$elf" dist/ferrum-ebpf-progs.bpf.o
                '''
                archiveArtifacts artifacts: 'dist/ferrum-ebpf-progs.bpf.o', fingerprint: true
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
