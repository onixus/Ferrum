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
        timeout(time: 30, unit: 'MINUTES')
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
