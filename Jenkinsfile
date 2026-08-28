// Локальный CI Ferrum на http://localhost:8081. Гонять тесты только здесь.
// Сборка в docker.image().inside(): CARGO_TARGET_DIR обязан быть named volume.
// Bind-mount macOS/VirtioFS ломает cargo недетерминированно (E0463 can't find crate).
// clippy — check-only (.rmeta); cargo test после него пересоберёт .rlib — это ожидаемо.
// Стадии разведены на функциональные и security намеренно: падение security-стадии
// означает нарушенный инвариант из AGENTS.md, а не сломанную фичу.
// SAST стоит первым: находка роняет билд за минуту, а не после полной сборки Rust.

// cargo-deny/cargo-audit ставятся в отдельный том: /usr/local/cargo/bin трогать нельзя,
// там лежит сам cargo и монтирование его затрёт.
// Константы держим внутри метода: `def` на верхнем уровне — локальная переменная
// скрипта, из метода она не видна (MissingPropertyException, билд #9).
def rust(String script) {
    rust('rust:1-bookworm', script)
}

def rust(String image, String script) {
    def args = '-v ferrum-cargo-home:/usr/local/cargo/registry' +
               ' -v ferrum-cargo-target:/build-target' +
               ' -v ferrum-cargo-tools:/cargo-tools'
    docker.image(image).inside(args) {
        withEnv([
            'CARGO_TARGET_DIR=/build-target',
            'CARGO_TERM_COLOR=never',
            'CARGO_INSTALL_ROOT=/cargo-tools',
        ]) {
            // PATH через withEnv('PATH+…') до шелла внутри контейнера не доезжает
            // (билд #12): cargo-deny стоял, но `cargo deny` его не находил.
            sh 'export PATH=/cargo-tools/bin:$PATH\n' + script
        }
    }
}

pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 45, unit: 'MINUTES')
    }

    stages {
        stage('SAST (semgrep)') {
            steps {
                sh '''
                    set -eu
                    # Один проход: --error роняет стадию, --output оставляет артефакт.
                    # В semgrep.json попадают находки уровня ERROR — те, что и есть гейт.
                    docker run --rm -v "$WORKSPACE":/src -w /src semgrep/semgrep:latest \
                        semgrep scan --config p/rust --config p/secrets \
                            --metrics=off --severity ERROR --error \
                            --json --output semgrep.json
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
                }
            }
        }

        stage('Format') {
            steps {
                script {
                    rust '''
                        set -eu
                        rustup component add rustfmt
                        cargo fmt --all -- --check
                    '''
                }
            }
        }

        stage('Clippy') {
            steps {
                script {
                    rust '''
                        set -eu
                        rustup component add clippy
                        cargo clippy --workspace --all-targets -- -D warnings
                    '''
                }
            }
        }

        stage('Functional tests') {
            steps {
                script {
                    rust '''
                        set -eu
                        # Исключаем только целиком покрытые security-стадией crate.
                        # Списком таргетов admission не резать: новый tests/*.rs тогда
                        # не попадёт никуда и молча перестанет гоняться.
                        cargo test --workspace \
                            --exclude ferrum-policy \
                            --exclude ferrum-crypto
                    '''
                }
            }
        }

        stage('Functional: policy validation') {
            steps {
                script {
                    rust '''
                        set -eu
                        for p in prod-restricted exception-ok policy-library \
                                 runtime-profile ferrum-cluster compliance-snapshot; do
                            cargo run -p ferrum-cli --quiet -- validate "policies/examples/$p.yaml"
                        done
                    '''
                }
            }
        }

        stage('Security: policy invariants') {
            steps {
                script {
                    rust '''
                        set -eu
                        cargo test -p ferrum-policy
                        cargo test -p ferrum-crypto
                    '''
                }
            }
        }

        stage('Security: MVP acceptance') {
            // Приёмка из AGENTS.md: unsigned/privileged/cluster-admin → deny,
            // exception без TTL → reject, CP down → LKG, не fail-open.
            steps {
                script {
                    rust '''
                        set -eu
                        cargo test -p ferrum-admission --test mvp
                    '''
                }
            }
        }

        stage('Security: negative validation') {
            steps {
                script {
                    rust '''
                        set -eu
                        # Ненулевой код сам по себе ничего не доказывает: пропавший файл
                        # или сломанный разбор аргументов дают его же. Гейт держится на
                        # вердикте валидатора, поэтому ждём конкретное сообщение.
                        set -- "exception-bad-no-ticket:PolicyException.ticket пуст"
                        for spec in "$@"; do
                            bad=${spec%%:*}
                            want=${spec#*:}
                            out="$WORKSPACE/negative-$bad.log"
                            if cargo run -p ferrum-cli --quiet -- validate \
                                "policies/examples/$bad.yaml" >"$out" 2>&1; then
                                echo "$bad.yaml must fail validation" >&2
                                exit 1
                            fi
                            if ! grep -qF "$want" "$out"; then
                                echo "$bad.yaml failed for the wrong reason:" >&2
                                cat "$out" >&2
                                exit 1
                            fi
                            echo "ok: $bad.yaml rejected"
                        done
                    '''
                }
            }
        }

        stage('Security: supply chain') {
            steps {
                script {
                    rust '''
                        set -eu
                        # Сборка cargo-deny/cargo-audit не должна пачкать общий
                        # /build-target: иначе рабочие артефакты вытесняются впустую.
                        export CARGO_TARGET_DIR=/tmp/ferrum-tools-target
                        command -v cargo-deny  >/dev/null || cargo install --locked cargo-deny
                        command -v cargo-audit >/dev/null || cargo install --locked cargo-audit
                        cargo deny check licenses bans sources advisories
                        cargo audit --json > "$WORKSPACE/cargo-audit.json" || {
                            cat "$WORKSPACE/cargo-audit.json" >&2
                            exit 1
                        }
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'cargo-audit.json', allowEmptyArchive: true
                }
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
