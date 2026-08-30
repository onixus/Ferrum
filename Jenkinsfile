// Локальный CI Ferrum на http://localhost:8081.
// Сборка в docker.image().inside(): CARGO_TARGET_DIR обязан быть named volume.
// Bind-mount macOS/VirtioFS ломает cargo недетерминированно (E0463 can't find crate).
// clippy — check-only (.rmeta); cargo test после него пересоберёт .rlib — это ожидаемо.
//
// 'Agent binary', 'Admission binary' and 'Controller binary' are the stages
// that link. Everything above them — clippy on attach,apiserver included —
// stops at .rmeta or runs the default features, so until those stages the
// production combination of each shipped crate had never produced an object
// file, let alone an executable. Two of the three were added a cycle after the
// first, having been missing for exactly as long and for exactly the reason
// that closed the agent's: a binary nothing has ever linked is an empty crate
// with more steps, and `ferrum-admission --features apiserver` — the crate
// carrying three of the eight RFC section D acceptance cases — was not compiled
// by any stage in any mode.
//
// The '* image' stages are the only ones that leave the container: they need
// the docker CLI on the node, not inside the rust image, and a socket mounted
// into this container would be the escape route the runtime rules exist to
// kill. Three Dockerfiles and three stages rather than one file taking a crate
// name: what each image has to prove differs — the agent welds a bpf object to
// a userspace that must agree with its map layout, the webhook must prove the
// `apiserver` feature reached the binary, the controller neither — and a check
// behind an `if` keyed on a build arg is a check a wrong argument skips.
//
// `deploy_gate.rs` (run by 'Test') is what keeps this list closed in both
// directions: an `image:` in deploy/ that no `docker build -t` here produces,
// or a crate with a `[[bin]]` that no stage links, fails by name.

def RUST_IMAGE = 'rust:1-bookworm'
// Третий том — под cargo-deny/cargo-audit: /usr/local/cargo/bin трогать нельзя,
// там лежит сам cargo и монтирование его затрёт.
def RUST_DOCKER_ARGS = '-v ferrum-cargo-home:/usr/local/cargo/registry' +
                       ' -v ferrum-cargo-target:/build-target' +
                       ' -v ferrum-cargo-tools:/cargo-tools'

// Что группе 'Datapath' нужно сверх обычного rust-контейнера, и почему
// именно это, а не `--privileged`.
//
// Четыре цикла эта группа падала здесь, и объяснение в документах было
// неверным: не «ядро LinuxKit без tracefs», а контейнер без прав. Ядро ноды
// (6.12.76-linuxkit, aarch64) несёт CONFIG_BPF_SYSCALL, CONFIG_BPF_EVENTS,
// CONFIG_FTRACE и CONFIG_MODULES, и все пять точек, которые цепляет датапейс
// — sys_enter_{execve,openat,bpf,init_module,finit_module} — на ней есть.
// Отказ был EPERM на bpf(BPF_MAP_CREATE): агент запускается с uid 0, но с
// дефолтным bounding set докера (CapEff 00000000a80425fb), где верхние 32
// бита нулевые, то есть CAP_BPF (39) и CAP_PERFMON (38) отсутствуют.
//
// - `--cap-add=BPF --cap-add=PERFMON`: ровно два бита, которых не хватало.
//   CAP_SYS_ADMIN сознательно не даётся: он почти root на этой VM, а
//   контейнер исполняет код репозитория. Монтирование tracefs, которое его
//   потребовало бы, вынесено в отдельную стадию-однострочник ниже, где
//   привилегия не встречается с недоверенным кодом.
// - `-v /sys/kernel/tracing:...:ro`: сам bind-mount прав не требует, и
//   читать id точек достаточно только на чтение.
// - `--pid=host`: не удобство. `bpf_get_current_pid_tgid()` отдаёт pid из
//   init-namespace, а тесты сверяют его со своим `getpid()`; в собственном
//   PID namespace эти числа разные, и attach_live видел ноль «своих»
//   записей при полностью исправном датапейсе. Стадия существует, чтобы
//   смотреть на ядро глазами ядра, и в этом виде обязана делить с ним
//   пространство pid.
def DATAPATH_DOCKER_ARGS = RUST_DOCKER_ARGS +
                           ' -v /sys/kernel/tracing:/sys/kernel/tracing:ro' +
                           ' --cap-add=BPF --cap-add=PERFMON --pid=host'

pipeline {
    agent none

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        // BPF ELF stage adds nightly install + build-std + bpf-linker on a cold cache,
        // and 'Link' compiles the whole graph under QEMU the first time.
        timeout(time: 90, unit: 'MINUTES')
    }

    environment {
        CARGO_TARGET_DIR = '/build-target'
        CARGO_TERM_COLOR = 'never'
        CARGO_INSTALL_ROOT = '/cargo-tools'
    }

    stages {
        // Первым: находка роняет билд за минуту, а не после полной сборки Rust.
        // agent any по той же причине, что у стадий образов: docker CLI живёт на
        // ноде, а не внутри rust-образа.
        stage('SAST (semgrep)') {
            agent any
            steps {
                sh '''
                    set -eu
                    # Один проход: --error роняет стадию, --output оставляет артефакт.
                    # В semgrep.json попадают находки уровня ERROR — те, что и есть гейт.
                    # --exclude называет ровно один файл, и это не смягчение
                    # правила. crates/ferrum-testkit/fixtures/deploy-bad-private-key/ca.key
                    # существует затем, чтобы FD023 было на чём срабатывать: PEM-заголовок
                    # в дереве, которое коммитят. Секретное правило semgrep читает тот же
                    # заголовок — и два гейта оказались взаимным отказом: SAST ронял каждый
                    # билд на фикстуре, которая доказывает, что lint-deploy работает.
                    # Исключение держит `deploy_gate.rs::scan_exclusions`: он требует, чтобы
                    # исключён был ровно этот путь, чтобы тело файла не было ключевым
                    # материалом, и чтобы lint по-прежнему называл его находкой. Список
                    # расширять только вместе с тем гейтом — иначе это дыра без читателя.
                    docker run --rm -v "$WORKSPACE":/src -w /src semgrep/semgrep:latest \
                        semgrep scan --config p/rust --config p/secrets \
                            --metrics=off --severity ERROR --error \
                            --exclude='crates/ferrum-testkit/fixtures/deploy-bad-private-key/ca.key' \
                            --json --output semgrep.json
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'semgrep.json', allowEmptyArchive: true
                }
            }
        }

        // Каждая стадия внутри — в rust-контейнере, один воркспейс на группу.
        // Верхнеуровневый agent здесь `none` намеренно: с ним стадии `agent any`
        // (SAST и три образа) всё равно исполнялись внутри этого контейнера —
        // декоратор `reuseNode true` доезжает до них (JENKINS-30600), и `docker`
        // там не найден. Это уронило билд #17 на первой же стадии, а остальные
        // восемнадцать пропустило. Группу не разбирать на per-stage agent:
        // 'BPF attach' и ниже читают dist/, который кладёт 'BPF ELF', а
        // отдельный agent у каждой стадии — отдельный воркспейс.
        stage('Build') {
            agent {
                docker {
                    image RUST_IMAGE
                    args RUST_DOCKER_ARGS
                    reuseNode true
                }
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
                        # The webhook's production combination. It was on no clippy
                        # line and on no test line: `apiserver` is `default = []`,
                        # so `cargo test --workspace` ran without it, and the two
                        # stages that did name it — 'Admission binary' and
                        # 'Admission image' — are `cargo build`, which links the
                        # [[bin]] and compiles no test target at all. The crate
                        # carrying three of the eight section D cases was therefore
                        # lint-checked by nothing and tested by nothing in the one
                        # configuration it ships in, which is how `WatchedLabels`
                        # reached a cycle with zero tests.
                        cargo clippy -p ferrum-admission --features apiserver --all-targets -- -D warnings
                    '''
                }
            }

            stage('Test') {
                steps {
                    sh '''
                        set -eu
                        cargo test --workspace
                        # --workspace is default features, and every production
                        # feature in this tree is off by default. A `cargo build`
                        # of the same combination is not a substitute: it links the
                        # binary and never compiles a test target, so a crate can
                        # ship a feature no test has ever been compiled under.
                        # `deploy_gate.rs::every_feature_a_manifest_selects_is_a_lint_and_test_target`
                        # requires this line and the clippy line above for each one.
                        cargo test -p ferrum-admission --features apiserver
                    '''
                }
            }

            stage('BPF ELF') {
                steps {
                    sh '''
                        set -eu
                        # /cargo-tools — именованный том, и bpf-linker ставится туда.
                        # Без этой строки `command -v` его не находил, стадия
                        # пересобирала линкер каждый билд и тянула LLVM каждый билд.
                        export PATH=/cargo-tools/bin:$PATH
                        rustup toolchain install nightly --profile minimal --component rust-src
                        if ! command -v bpf-linker >/dev/null 2>&1; then
                            # bpf-linker 0.11 просит llvm-sys-23 с `no-llvm-linking`:
                            # линковать LLVM он не будет, символы даёт libLLVM самого
                            # рустца. Но его build.rs ищет llvm-config, чтобы решить,
                            # какой llvm-sys-XX включить, и без него стадия падает,
                            # ничего не собрав. Фича `rust-llvm`, под которую здесь
                            # раньше стоял один шим, существовала последний раз в
                            # 0.9.10.
                            #
                            # LLVM ставится настоящий и ровно той версии, которую
                            # несёт nightly: расхождение мажора — это ABI, по которому
                            # линкер сойдётся при сборке и разойдётся в работе.
                            llvm_major=23
                            have=$(rustc +nightly --version --verbose \
                                   | awk '/^LLVM version:/{split($3, v, "."); print v[1]}')
                            if [ "$have" != "$llvm_major" ]; then
                                echo "nightly несёт LLVM $have, стадия ставит $llvm_major:" \
                                     "поднимите llvm_major вместе с репозиторием ниже" >&2
                                exit 1
                            fi
                            if ! command -v llvm-config >/dev/null 2>&1; then
                                apt-get update
                                apt-get install -y --no-install-recommends \
                                    curl gnupg ca-certificates
                                # Ключ пинится по отпечатку, а не «как отдал сервер»:
                                # иначе подменённый ключ подписал бы подменённый LLVM,
                                # и apt на это не пожалуется.
                                curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key \
                                    -o /tmp/llvm.asc
                                fpr=$(gpg --show-keys --with-colons /tmp/llvm.asc \
                                      | awk -F: '/^fpr/{print $10; exit}')
                                if [ "$fpr" != 6084F3CF814B57C1CF12EFD515CF4D18AF4F7421 ]; then
                                    echo "ключ apt.llvm.org не тот: $fpr" >&2
                                    exit 1
                                fi
                                gpg --dearmor < /tmp/llvm.asc \
                                    > /usr/share/keyrings/ferrum-llvm.gpg
                                echo "deb [signed-by=/usr/share/keyrings/ferrum-llvm.gpg]" \
                                     "https://apt.llvm.org/bookworm/" \
                                     "llvm-toolchain-bookworm-$llvm_major main" \
                                    > /etc/apt/sources.list.d/ferrum-llvm.list
                                apt-get update
                                apt-get install -y --no-install-recommends \
                                    "llvm-$llvm_major-dev"
                                ln -sf "/usr/lib/llvm-$llvm_major/bin/llvm-config" \
                                    /usr/local/bin/llvm-config
                            fi
                            # Линковку берёт на себя рустец: образ не несёт простого
                            # libLLVM.so, поэтому версионный шимится, а сисрут едет
                            # на rpath.
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
                    // What 'Agent image' builds from. Stashed rather than trusted
                    // to still be in this workspace: that stage runs on the node
                    // with its own workspace, and an image built from whatever
                    // happened to be lying there is not the tree this pipeline
                    // tested.
                    //
                    // .dockerignore belongs in this list and was missing from it.
                    // Everything the list does not name reaches the build context
                    // through that stage's default `checkout scm` instead — from
                    // the SCM revision, not from the tree these stages just tested.
                    // For .dockerignore that decides which files `COPY . .` sees at
                    // all, so the one file that shapes the whole context was the
                    // one file arriving from somewhere else.
                    //
                    // All three image stages unstash this one context. The webhook
                    // and controller images need no bpf object, but they need the
                    // same sources and the same .dockerignore, and a second stash
                    // would be a second thing to keep in step with this list.
                    stash includes: '.dockerignore,Dockerfile,Dockerfile.admission,Dockerfile.controller,Cargo.toml,Cargo.lock,rust-toolchain.toml,crates/**,dist/ferrum-ebpf-progs.bpf.o', name: 'image-context'
                }
            }

            }
        }


        // Три стадии, которые линкуют. Контейнер родной архитектуры: цель
        // x86_64 берётся кросс-компиляцией, а не эмуляцией — под QEMU падал сам
        // rustc, а не наш скрипт. Цель из архитектуры ноды не выводится: стенд
        // ядра, на котором измерено всё с меткой K в MVP-1-BOUNDARY.md, — x86_64,
        // и бинарь под arm64 оставил бы стадию зелёной, а утверждение про
        // продуктовую комбинацию — про то, чего на стенде не будет.
        //
        // Стоит выше 'Datapath', потому что ядра ей не нужно: ни одна стадия
        // датапейса эти бинари не читает — они архивируются, и на этом их путь
        // заканчивается; образы линкуют свои заново из застэшенных исходников.
        stage('Link') {
            agent {
                docker {
                    image RUST_IMAGE
                    args RUST_DOCKER_ARGS
                    reuseNode true
                }
            }
            stages {
            // The production combination, linked. AGENTS.md requires musl of
            // userspace; ring compiles C, so the target needs a musl cc as well as
            // the Rust std. --locked because this is the artefact the image ships:
            // a release build that may resolve a different dependency set than the
            // one CI tested is not one.
            stage('Agent binary') {
                steps {
                    sh '''
                        set -eu
                        target=x86_64-unknown-linux-musl
                        rustup target add "$target"
                        # Кросс, а не эмуляция. Нода arm64, цель x86_64, и
                        # amd64-контейнер это чинил ровно до `rustc -vV`: под QEMU
                        # он падал с SIGSEGV, не начав компиляции (билд #23).
                        # Здесь rustc идёт нативно, std под цель даёт rustup, C
                        # половину ring компилирует кросс-gcc из штатного Debian,
                        # а линкует rust-lld тем musl, который rustup везёт с
                        # собой: musl-tools ставит musl-gcc родной архитектуры,
                        # и он не понимает -m64 (билд #19).
                        if ! command -v x86_64-linux-gnu-gcc >/dev/null 2>&1; then
                            apt-get update
                            apt-get install -y --no-install-recommends \
                                gcc-x86-64-linux-gnu libc6-dev-amd64-cross
                        fi
                        CC_x86_64_unknown_linux_musl=x86_64-linux-gnu-gcc \
                        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
                        RUSTFLAGS="-C link-self-contained=yes" \
                            cargo build --release --locked --target "$target" \
                                -p ferrum-agent --features attach,apiserver
                        bin="$CARGO_TARGET_DIR/$target/release/ferrum-agent"
                        test -x "$bin"
                        # A dynamically linked "musl" build is a binary that will
                        # not start on the node it was built for. `file` is not in
                        # this image; the interpreter entry is, and its absence is
                        # the whole claim.
                        if readelf -lW "$bin" | grep -q 'Requesting program interpreter'; then
                            echo "agent binary is dynamically linked, musl target notwithstanding" >&2
                            exit 1
                        fi
                        mkdir -p dist
                        cp "$bin" dist/ferrum-agent
                    '''
                    archiveArtifacts artifacts: 'dist/ferrum-agent', fingerprint: true
                }
            }

            // The webhook, in the one combination deploy/admission/deployment.yaml
            // runs. `apiserver` is off by default, `cargo test --workspace` runs
            // default features and clippy stops at .rmeta, so before this stage the
            // production build of the crate that carries unsigned-deny,
            // privileged-deny and cluster-admin-bind-deny existed in no artefact of
            // any kind.
            stage('Admission binary') {
                steps {
                    sh '''
                        set -eu
                        target=x86_64-unknown-linux-musl
                        rustup target add "$target"
                        # Кросс, а не эмуляция. Нода arm64, цель x86_64, и
                        # amd64-контейнер это чинил ровно до `rustc -vV`: под QEMU
                        # он падал с SIGSEGV, не начав компиляции (билд #23).
                        # Здесь rustc идёт нативно, std под цель даёт rustup, C
                        # половину ring компилирует кросс-gcc из штатного Debian,
                        # а линкует rust-lld тем musl, который rustup везёт с
                        # собой: musl-tools ставит musl-gcc родной архитектуры,
                        # и он не понимает -m64 (билд #19).
                        if ! command -v x86_64-linux-gnu-gcc >/dev/null 2>&1; then
                            apt-get update
                            apt-get install -y --no-install-recommends \
                                gcc-x86-64-linux-gnu libc6-dev-amd64-cross
                        fi
                        CC_x86_64_unknown_linux_musl=x86_64-linux-gnu-gcc \
                        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
                        RUSTFLAGS="-C link-self-contained=yes" \
                            cargo build --release --locked --target "$target" \
                                -p ferrum-admission --features apiserver
                        bin="$CARGO_TARGET_DIR/$target/release/ferrum-admission"
                        test -x "$bin"
                        # A dynamically linked "musl" build is a binary that will
                        # not start on the scratch base its image uses. `file` is
                        # not in this image; the interpreter entry is, and its
                        # absence is the whole claim.
                        if readelf -lW "$bin" | grep -q 'Requesting program interpreter'; then
                            echo "admission binary is dynamically linked, musl target notwithstanding" >&2
                            exit 1
                        fi
                        # The feature is checked on the binary, not trusted to the
                        # cargo line above surviving an edit. Two-sided, and the two
                        # sides are each other's positive control: exactly one of
                        # these strings is compiled in — the die() message only
                        # without the feature, the apiserver error prefix only with
                        # it. A default build fails the first; a grep that has
                        # stopped matching anything fails the second.
                        if grep -aq 'requires the `apiserver` feature at build time' "$bin"; then
                            echo "the webhook linked without --features apiserver: the --apiserver" >&2
                            echo "flag deploy/admission/deployment.yaml passes would die() on a node," >&2
                            echo "which is a build defect arriving as a CrashLoopBackOff" >&2
                            exit 1
                        fi
                        if ! grep -aq 'error: apiserver: ' "$bin"; then
                            echo "the apiserver code path is absent from this binary, so the check" >&2
                            echo "above cannot detect anything and proved nothing" >&2
                            exit 1
                        fi
                        echo "ok: ferrum-admission linked for $target with the apiserver feature in it"
                        mkdir -p dist
                        cp "$bin" dist/ferrum-admission
                    '''
                    archiveArtifacts artifacts: 'dist/ferrum-admission', fingerprint: true
                }
            }

            // The controller declares no features, so `cargo build -p
            // ferrum-controller` is its production combination — but it had never
            // been linked for the target it ships on either, and it is the one
            // component that mounts the bundle signing key.
            stage('Controller binary') {
                steps {
                    sh '''
                        set -eu
                        target=x86_64-unknown-linux-musl
                        rustup target add "$target"
                        # Кросс, а не эмуляция. Нода arm64, цель x86_64, и
                        # amd64-контейнер это чинил ровно до `rustc -vV`: под QEMU
                        # он падал с SIGSEGV, не начав компиляции (билд #23).
                        # Здесь rustc идёт нативно, std под цель даёт rustup, C
                        # половину ring компилирует кросс-gcc из штатного Debian,
                        # а линкует rust-lld тем musl, который rustup везёт с
                        # собой: musl-tools ставит musl-gcc родной архитектуры,
                        # и он не понимает -m64 (билд #19).
                        if ! command -v x86_64-linux-gnu-gcc >/dev/null 2>&1; then
                            apt-get update
                            apt-get install -y --no-install-recommends \
                                gcc-x86-64-linux-gnu libc6-dev-amd64-cross
                        fi
                        CC_x86_64_unknown_linux_musl=x86_64-linux-gnu-gcc \
                        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
                        RUSTFLAGS="-C link-self-contained=yes" \
                            cargo build --release --locked --target "$target" \
                                -p ferrum-controller
                        bin="$CARGO_TARGET_DIR/$target/release/ferrum-controller"
                        test -x "$bin"
                        if readelf -lW "$bin" | grep -q 'Requesting program interpreter'; then
                            echo "controller binary is dynamically linked, musl target notwithstanding" >&2
                            exit 1
                        fi
                        # Identity, not spelling: this binary is the one handed the
                        # signing seed, and the flags its Deployment passes are the
                        # cheapest thing in it that no other component has.
                        for flag in --seed-file --namespace; do
                            if ! grep -aq -- "$flag" "$bin"; then
                                echo "the controller binary does not know $flag, which" >&2
                                echo "deploy/controller/deployment.yaml passes it" >&2
                                exit 1
                            fi
                        done
                        echo "ok: ferrum-controller linked for $target"
                        mkdir -p dist
                        cp "$bin" dist/ferrum-controller
                    '''
                    archiveArtifacts artifacts: 'dist/ferrum-controller', fingerprint: true
                }
            }
            }
        }

        // The image deploy/agent/daemonset.yaml names. Runs on the node and
        // not in the rust container: `docker build` needs the daemon, and the
        // way to reach it from inside this container would be to mount
        // /var/run/docker.sock — the hostPath FD006 is a finding on and the
        // runtime rules kill. The Dockerfile re-runs elf_inspect against the
        // ELF it is about to put in the image, so an ELF whose map layout this
        // userspace does not agree with cannot be welded in here.
        //
        // The binary in the image is *not* the one 'Agent binary' archived and
        // fingerprinted. `docker build` links a second one from the stashed
        // sources, in its own container, and the fingerprint travelling with
        // the archive says nothing about it. The Dockerfile therefore repeats
        // the interpreter check on the binary it actually produces; the two
        // links are checked separately because they are two links.
        stage('Agent image') {
            agent any
            steps {
                unstash 'image-context'
                sh '''
                    set -eu
                    test -f dist/ferrum-ebpf-progs.bpf.o
                    docker build --platform=linux/amd64 \
                        --build-arg BPF_ELF=dist/ferrum-ebpf-progs.bpf.o \
                        -t "ghcr.io/ferrum/ferrum-agent:${FERRUM_IMAGE_TAG:-dev-$BUILD_NUMBER}" .
                '''
            }
        }

        // The image deploy/admission/deployment.yaml names. Nothing in this
        // repository produced it, so the manifest referenced a tag that had
        // never existed. Dockerfile.admission links the crate a second time, in
        // its own container, and re-checks both the interpreter and the
        // `apiserver` feature on the binary it is about to put in the image —
        // the one 'Admission binary' archived is a different file and its
        // fingerprint says nothing about this one.
        stage('Admission image') {
            agent any
            steps {
                unstash 'image-context'
                sh '''
                    set -eu
                    docker build --platform=linux/amd64 -f Dockerfile.admission \
                        -t "ghcr.io/ferrum/ferrum-admission:${FERRUM_IMAGE_TAG:-dev-$BUILD_NUMBER}" .
                '''
            }
        }

        // The image deploy/controller/deployment.yaml names, on the same terms.
        stage('Controller image') {
            agent any
            steps {
                unstash 'image-context'
                sh '''
                    set -eu
                    docker build --platform=linux/amd64 -f Dockerfile.controller \
                        -t "ghcr.io/ferrum/ferrum-controller:${FERRUM_IMAGE_TAG:-dev-$BUILD_NUMBER}" .
                '''
            }
        }

        // Каждая стадия внутри — в rust-контейнере, один воркспейс на группу.
        // Верхнеуровневый agent здесь `none` намеренно: с ним стадии `agent any`
        // (SAST и три образа) всё равно исполнялись внутри этого контейнера —
        // декоратор `reuseNode true` доезжает до них (JENKINS-30600), и `docker`
        // там не найден. Это уронило билд #17 на первой же стадии, а остальные
        // восемнадцать пропустило. Группа отдельная от 'Build', потому что между
        // ними лежат стадии образов, которым нужна нода; общего файла у них нет,
        // а /build-target — именованный том и переживает смену воркспейса.
        stage('Checks') {
            agent {
                docker {
                    image RUST_IMAGE
                    args RUST_DOCKER_ARGS
                    reuseNode true
                }
            }
            stages {
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
                        # Everything above is an assertion of absence, and absence is
                        # what a typo in $forbidden, a renamed crate, or a changed
                        # `cargo tree` output format also produce. ferrum-cli is the
                        # one member that must link both, so it is the positive
                        # control: if the greps cannot find them here, they were
                        # never capable of finding them anywhere and the loop above
                        # proved nothing.
                        cli="$(cargo tree -p ferrum-cli -e normal)"
                        for expected in rcgen x509-parser; do
                            if ! printf '%s\n' "$cli" | grep -qE "(^| )$expected v"; then
                                echo "crate boundary: ferrum-cli does not link $expected, so the" >&2
                                echo "absence checks above cannot detect anything" >&2
                                exit 1
                            fi
                        done
                        echo "ok: rcgen and x509-parser stay off the admission and agent graphs"
                        echo "ok: and are still detectable on ferrum-cli, which must carry them"
                        # ferrum-ebpf gained libc as a normal dependency, gated on
                        # `attach`, for the getrlimit/setrlimit pair every load now
                        # runs through. That is a boundary change and it is checked
                        # here rather than argued in a review: under `attach` aya
                        # already resolves libc, so the crate borrowed it in that
                        # configuration and gains nothing by naming it; the default
                        # build must still carry neither. Both halves, because an
                        # absence with no positive control proves nothing.
                        #
                        # `--depth 1`, и это не сужение проверки, а её починка.
                        # Утверждение здесь — про то, что линкует сам ferrum-ebpf;
                        # полный граф несёт libc транзитивно через ferrum-crypto и
                        # ring в любой конфигурации, так что форма без --depth
                        # утверждала то, что перестало быть правдой в тот день,
                        # когда ferrum-ebpf получил зависимость на ferrum-crypto.
                        # Заметить это было некому: стадия не исполнялась ни разу
                        # до билда #26.
                        if cargo tree -p ferrum-ebpf -e normal --depth 1 \
                            | grep -qE "(^| )libc v"; then
                            echo "crate boundary: ferrum-ebpf links libc with default features;" >&2
                            echo "the stable offline build must stay free of it" >&2
                            exit 1
                        fi
                        if ! cargo tree -p ferrum-ebpf -e normal --depth 1 --features attach \
                            | grep -qE "(^| )libc v"; then
                            echo "crate boundary: libc is absent from ferrum-ebpf --features attach," >&2
                            echo "so the check above cannot detect anything and the memlock raise" >&2
                            echo "has no libc to call" >&2
                            exit 1
                        fi
                        echo "ok: libc is on ferrum-ebpf's graph only under attach, where aya already put it"
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
                        if ! grep -qF "PolicyException.ticket пуст" \
                            /tmp/ferrum-bad-exception.err /tmp/ferrum-bad-exception.out; then
                            echo "exception-bad-no-ticket.yaml failed for the wrong reason" >&2
                            cat /tmp/ferrum-bad-exception.err /tmp/ferrum-bad-exception.out >&2
                            exit 1
                        fi
                        echo "ok: exception-bad-no-ticket.yaml rejected"
                        # A rule naming a syscall the datapath does not hook is a
                        # signed policy that can never fire. The validator has to
                        # be the place that says so, not a post-incident review.
                        set +e
                        cargo run -p ferrum-cli --quiet -- validate policies/examples/runtime-unobservable-syscall.yaml >/tmp/ferrum-bad-syscall.out 2>/tmp/ferrum-bad-syscall.err
                        status=$?
                        set -e
                        if [ "$status" -eq 0 ]; then
                            echo "runtime-unobservable-syscall.yaml must fail validation" >&2
                            exit 1
                        fi
                        if ! grep -q ptrace /tmp/ferrum-bad-syscall.err /tmp/ferrum-bad-syscall.out; then
                            echo "validation must name the offending syscall" >&2
                            exit 1
                        fi
                        echo "ok: runtime-unobservable-syscall.yaml rejected"

                        # Half of the open/openat pair is enforcement that depends
                        # on which node the workload lands on: dead on the arches
                        # that lack the named form, bypassable on the ones serving
                        # the other. One bundle ships to every node, so the gate
                        # belongs here, not in a per-arch incident review.
                        set +e
                        cargo run -p ferrum-cli --quiet -- validate policies/examples/runtime-arch-split-syscall.yaml >/tmp/ferrum-arch-split.out 2>/tmp/ferrum-arch-split.err
                        status=$?
                        set -e
                        if [ "$status" -eq 0 ]; then
                            echo "runtime-arch-split-syscall.yaml must fail validation" >&2
                            exit 1
                        fi
                        if ! grep -q "open" /tmp/ferrum-arch-split.err /tmp/ferrum-arch-split.out; then
                            echo "validation must name the missing companion syscall" >&2
                            exit 1
                        fi
                        echo "ok: runtime-arch-split-syscall.yaml rejected"

                        # The runtime plane executes allow/audit/kill. `deny` it
                        # decides and never carries out: the tracepoint fires after
                        # the syscall has already run. A rule like that ships
                        # signed and exports verdicts that never happened, so the
                        # validator has to refuse it instead of the agent
                        # explaining itself afterwards. Grep the message, not just
                        # the exit code: a fixture that fails on a schema error
                        # would pass this stage for the wrong reason.
                        set +e
                        cargo run -p ferrum-cli --quiet -- validate policies/examples/runtime-unexecutable-action.yaml >/tmp/ferrum-bad-action.out 2>/tmp/ferrum-bad-action.err
                        status=$?
                        set -e
                        if [ "$status" -eq 0 ]; then
                            echo "runtime-unexecutable-action.yaml must fail validation" >&2
                            exit 1
                        fi
                        if ! grep -q "action=deny" /tmp/ferrum-bad-action.err /tmp/ferrum-bad-action.out; then
                            echo "validation must name the unexecutable action" >&2
                            exit 1
                        fi
                        if ! grep -q "no-module" /tmp/ferrum-bad-action.err /tmp/ferrum-bad-action.out; then
                            echo "validation must name the offending rule" >&2
                            exit 1
                        fi
                        echo "ok: runtime-unexecutable-action.yaml rejected"
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
                        # FD023. Issuance leaves the CA key in the tree it wrote to,
                        # and the lint refuses that tree until the key is moved out
                        # — which is the rule's whole point, because the tree it
                        # lands in is the one that gets committed. This stage went
                        # red on exactly that, having asserted the issued tree
                        # passes the lint without first doing the one thing an
                        # operator must do with the key. Both halves: the tree must
                        # fail while the key is in it, or the removal below proves
                        # nothing about why it then passes.
                        set +e
                        cargo run -p ferrum-cli --quiet -- lint-deploy /tmp/ferrum-pki >/tmp/ferrum-pki-cakey.out 2>/tmp/ferrum-pki-cakey.err
                        status=$?
                        set -e
                        if [ "$status" -eq 0 ]; then
                            echo "the issued tree still carries ca.key and the lint accepted it" >&2
                            exit 1
                        fi
                        if ! grep -q FD023 /tmp/ferrum-pki-cakey.err /tmp/ferrum-pki-cakey.out; then
                            echo "the issued tree failed the lint on something other than FD023" >&2
                            exit 1
                        fi
                        echo "ok: the CA key issuance leaves behind is refused in the tree"
                        rm /tmp/ferrum-pki/admission/ca.key
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
                        if ! grep -q FD020 /tmp/ferrum-bad-cabundle.err /tmp/ferrum-bad-cabundle.out; then
                            echo "deploy-bad-cabundle failed on something other than FD020" >&2
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
                        # FD026. An agent with the ELF, the capabilities and the
                        # RBAC all correct and no tracefs mounted reads no
                        # tracepoint id, fails every attach and parks Degraded on
                        # every node — which is the state the shipped DaemonSets
                        # were in. The rule asserts an absence, so it needs a tree
                        # that has it: grep the code, not just the exit status, or
                        # a fixture failing for another reason passes this stage.
                        set +e
                        cargo run -p ferrum-cli --quiet -- lint-deploy crates/ferrum-testkit/fixtures/deploy-bad-tracefs >/tmp/ferrum-bad-tracefs.out 2>/tmp/ferrum-bad-tracefs.err
                        status=$?
                        set -e
                        if [ "$status" -eq 0 ]; then
                            echo "fixtures/deploy-bad-tracefs must fail lint-deploy" >&2
                            exit 1
                        fi
                        if ! grep -q FD026 /tmp/ferrum-bad-tracefs.err /tmp/ferrum-bad-tracefs.out; then
                            echo "deploy-bad-tracefs failed on something other than FD026" >&2
                            exit 1
                        fi
                        echo "ok: an attach build with no tracefs mount rejected"
                        # FD027. --apiserver against a ServiceAccount with
                        # automountServiceAccountToken: false is a webhook with the
                        # feature compiled in, the RBAC granted and no credential to
                        # use: every connect fails behind a backoff, the label cache
                        # never lists, and each policy carrying a selector denies the
                        # Pods it selects. The rule asserts an absence, so it needs a
                        # tree that has it, and the exact code is grepped for the
                        # same reason as FD026 above: a fixture failing on something
                        # else would pass this stage having proved nothing.
                        set +e
                        cargo run -p ferrum-cli --quiet -- lint-deploy crates/ferrum-testkit/fixtures/deploy-bad-token >/tmp/ferrum-bad-token.out 2>/tmp/ferrum-bad-token.err
                        status=$?
                        set -e
                        if [ "$status" -eq 0 ]; then
                            echo "fixtures/deploy-bad-token must fail lint-deploy" >&2
                            exit 1
                        fi
                        if ! grep -q FD027 /tmp/ferrum-bad-token.err /tmp/ferrum-bad-token.out; then
                            echo "deploy-bad-token failed on something other than FD027" >&2
                            exit 1
                        fi
                        echo "ok: an --apiserver webhook with no projected token rejected"
                    '''
                }
            }

            stage('Security: policy invariants') {
                steps {
                    sh '''
                        set -eu
                        cargo test -p ferrum-policy
                        cargo test -p ferrum-crypto
                        cargo test -p ferrum-crypto --features x509
                    '''
                }
            }

            // Приёмка из AGENTS.md: unsigned/privileged/cluster-admin → deny,
            // exception без TTL → reject, CP down → LKG, не fail-open.
            stage('Security: MVP acceptance') {
                steps {
                    sh '''
                        set -eu
                        cargo test -p ferrum-admission --test mvp
                    '''
                }
            }

            stage('Security: supply chain') {
                steps {
                    sh '''
                        set -eu
                        export PATH=/cargo-tools/bin:$PATH
                        # Сборка инструментов не должна пачкать общий /build-target:
                        # иначе рабочие артефакты вытесняются впустую.
                        CARGO_TARGET_DIR=/tmp/ferrum-tools-target
                        export CARGO_TARGET_DIR
                        command -v cargo-deny  >/dev/null || cargo install --locked cargo-deny
                        command -v cargo-audit >/dev/null || cargo install --locked cargo-audit
                        unset CARGO_TARGET_DIR
                        cargo deny check licenses bans sources advisories
                        cargo audit --json > "$WORKSPACE/cargo-audit.json" || {
                            cat "$WORKSPACE/cargo-audit.json" >&2
                            exit 1
                        }
                    '''
                }
                post {
                    always {
                        archiveArtifacts artifacts: 'cargo-audit.json', allowEmptyArchive: true
                    }
                }
            }
            }
        }

        // Стадии, которым нужно настоящее ядро, — последними, и это не косметика.
        // Пока они стояли посреди пайплайна, их падение уносило шесть стадий,
        // которым ядро не нужно вовсе: 'Link', три образа и всю группу 'Checks',
        // а в ней cargo-deny и cargo-audit. Терять supply chain из-за отсутствия
        // tracefs — худший из возможных обменов.
        //
        // Пропускать их по условию было бы вторым способом это починить и худшим:
        // гейт, умеющий себя пропустить, — ровно тот дефект, от которого написан
        // MVP-1-BOUNDARY.md. Они падают честно и красят билд красным на ноде без
        // ядра; всё, что здесь исполнимо, к этому моменту уже исполнено.
        // tracefs на этой ноде не смонтирован, и смонтировать его изнутри
        // сборочного контейнера можно только с CAP_SYS_ADMIN. Поэтому монтирует
        // отдельный одноразовый контейнер, который исполняет одну зашитую
        // команду и ни строчки кода репозитория: привилегия и недоверенный код
        // разведены, а сборочный контейнер получает готовый bind-mount и два
        // узких права (см. DATAPATH_DOCKER_ARGS).
        //
        // Идемпотентно и без `|| true`: mount, который не поднялся, обязан
        // уронить стадию здесь, а не превратиться в «нет tracefs» четырьмя
        // стадиями ниже, где это читается как свойство ядра.
        stage('Datapath tracefs') {
            agent any
            steps {
                sh '''
                    set -eu
                    docker run --rm --privileged --pid=host alpine:3 \
                        nsenter -t 1 -m -- sh -c \
                        'mountpoint -q /sys/kernel/tracing \
                            || mount -t tracefs tracefs /sys/kernel/tracing'
                    docker run --rm -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
                        alpine:3 sh -c \
                        'test -r /sys/kernel/tracing/events/syscalls/sys_enter_openat/id'
                    echo "ok: tracefs is mounted on the node and readable through a bind-mount"
                '''
            }
        }

        stage('Datapath') {
            agent {
                docker {
                    image RUST_IMAGE
                    args DATAPATH_DOCKER_ARGS
                    reuseNode true
                }
            }
            stages {
            // The only stage that puts the datapath in a kernel. Everything before
            // it reads the ELF; four of the RFC section D acceptance cases run through
            // Bpf::load, and nothing else in this pipeline executes a single one of
            // its instructions.
            //
            // Requires of the agent: CAP_BPF (or root) and tracefs mounted at
            // /sys/kernel/tracing. CONFIG_MODULES=y is not required: a kernel
            // without loadable modules has no init_module/finit_module tracepoint,
            // and KernelHandle::attach_for_arch narrows the enforceable set and
            // names what it dropped instead of refusing, which this stage checks
            // against tracefs. FERRUM_BPF_ELF_REQUIRED turns every remaining skip
            // into a stage failure: a green no-op here is exactly the fail-open
            // the stage exists to close.
            //
            // The one no-op FERRUM_BPF_ELF_REQUIRED cannot catch by itself is this
            // line losing `--features attach`: attach_live.rs is `cfg`-gated on it,
            // so the binary would run zero tests and exit 0 with the env var never
            // read. `the_gate_must_not_be_compiled_out` lives outside that cfg and
            // fails when the feature is off and FERRUM_BPF_ELF_REQUIRED is on.
            //
            // A passed count cannot stand in for that, and until now this stage
            // believed it could. Every skip path in the test file is an early
            // `return` from a `#[test]`, so a run that attached nothing reports
            // `test result: ok. 7 passed` character for character like a run that
            // attached everything — and dropping FERRUM_BPF_ELF_REQUIRED alone,
            // with the feature still on, took this stage green having loaded no
            // program into any kernel. What the count cannot see, a positive
            // control can: `--show-output` surfaces the line the test prints only
            // after `KernelHandle::attach_for_arch` has returned a loaded handle,
            // and that line is required below. It is emitted from inside the
            // attached path, so no skip can produce it.
            stage('BPF attach') {
                steps {
                    // dist/ приезжает стэшем: 'BPF ELF' теперь в другой
                    // группе, и её воркспейс этой стадии не наследуется.
                    unstash 'image-context'
                    sh '''
                        set -eu
                        elf="$PWD/dist/ferrum-ebpf-progs.bpf.o"
                        test -f "$elf"
                        out=/tmp/ferrum-attach-live.out
                        # Not a pipeline: /bin/sh here is dash, which has no
                        # pipefail, and `| tee` would hand `set -e` tee's status
                        # and swallow a failing cargo test.
                        if ! FERRUM_BPF_ELF_REQUIRED=1 FERRUM_BPF_ELF="$elf" \
                            cargo test -p ferrum-ebpf --features attach --test attach_live \
                            -- --show-output > "$out" 2>&1
                        then
                            cat "$out"
                            exit 1
                        fi
                        cat "$out"
                        passed="$(sed -n 's/^test result: ok\\. \\([0-9][0-9]*\\) passed.*/\\1/p' "$out" | head -1)"
                        # Every test in the gate, not "at least one". The number is
                        # derived from the source rather than written down here, so
                        # a test added to attach_live.rs is required by this stage
                        # the moment it exists — and #[ignore] on any of the ones
                        # already there drops `passed` below it and fails, which is
                        # what "at least one" could not do. `mod gate` starts the
                        # cfg(attach) half; the single test outside it is compiled
                        # out under the feature this line builds with, so counting
                        # from there is counting what actually runs.
                        src=crates/ferrum-ebpf/tests/attach_live.rs
                        expected="$(sed -n '/^mod gate {/,$p' "$src" \
                            | grep -cE '^[[:space:]]*#\\[test\\][[:space:]]*$')"
                        if [ "${expected:-0}" -lt 1 ]; then
                            echo "counted no #[test] under mod gate in $src. This stage's own" >&2
                            echo "idea of what it must run is broken, so it can no longer tell a" >&2
                            echo "full run from an empty one." >&2
                            exit 1
                        fi
                        if [ "${passed:-0}" -ne "$expected" ]; then
                            echo "BPF attach ran ${passed:-no} of the $expected kernel tests in" >&2
                            echo "$src. A test that does not run proves nothing: #[ignore] on one" >&2
                            echo "of them leaves the datapath rows it covers asserted by no code" >&2
                            echo "that executed. Check --features attach is still on the cargo" >&2
                            echo "test line, and that no test was ignored or filtered out." >&2
                            exit 1
                        fi
                        # The positive controls. Each is printed from the far side
                        # of a successful attach, so no skip can emit one however
                        # many tests it reports as passed. All of them, not the
                        # first: this stage used to require only the KernelHandle
                        # line, which is printed by exactly one of the tests above,
                        # so gutting the other seven left it green.
                        for evidence in \
                            "attached through KernelHandle on " \
                            "long path: " \
                            "foreign records from tgid "
                        do
                            if ! grep -q "$evidence" "$out"; then
                                echo "BPF attach reported $passed passed tests without printing" >&2
                                echo "\\"$evidence\\". Every skip in attach_live.rs is an early return" >&2
                                echo "from a #[test], so the count alone cannot tell a skipped run" >&2
                                echo "from a real one; that line is emitted only from inside the" >&2
                                echo "attached path. Check FERRUM_BPF_ELF_REQUIRED, --features" >&2
                                echo "attach and -- --show-output are all still on the cargo line." >&2
                                exit 1
                            fi
                        done
                        echo "ok: all $passed attach_live tests executed against this kernel"
                        # The lib tests behind the same feature. `cargo test
                        # --workspace` runs default features, so until this line
                        # nothing ever executed the RLIMIT_MEMLOCK raise that every
                        # production attach now goes through — and it is the raise
                        # living outside the code under test that this cycle was
                        # about.
                        cargo test -p ferrum-ebpf --features attach --lib
                    '''
                }
            }

            }
        }

        // Стык вынесен из docker-группы, и это не перестановка ради вкуса.
        //
        // Шесть тестов `attach_join.rs` создают собственные cgroup — `mkdir` под
        // корнем cgroup2 и запись pid в `cgroup.procs`, — а Docker монтирует
        // cgroupfs внутрь контейнера на чтение: суперблок `rw`, монтирование
        // `ro`. Отсюда `mkdir /sys/fs/cgroup/ferrum-join-…: Read-only file
        // system (os error 30)` в билдах #38-#41 и красная 'BPF join' во всех.
        // Ядро ноды тут ни при чём: cgroup v2 оно несёт.
        //
        // Лечится это remount'ом изнутри mount namespace сборочного контейнера,
        // который делает одноразовый привилегированный контейнер снаружи — тот
        // же приём, что у 'Datapath tracefs', и по той же причине: сам remount
        // требует CAP_SYS_ADMIN, а этому контейнеру его не дают, он исполняет
        // код репозитория.
        //
        // Но снаружи нужен docker CLI, а вложенная в `agent { docker }` стадия
        // с `agent any` всё равно исполняется launcher'ом контейнера, где его
        // нет: JENKINS-30600, `docker: not found` — билд #42 упал именно так и
        // унёс за собой зелёную 'BPF attach'. Тот же дефект в своё время увёл
        // отсюда 'SAST (semgrep)'. Поэтому контейнер стыка поднимает и
        // останавливает сама группа, а тела стадий идут в него `docker exec`.
        // 'BPF attach' осталась в docker-группе нетронутой: она зелёная с
        // билда #39, и переносить её вместе со стыком значило бы рискнуть
        // единственным, что на этой ноде уже доказано.
        //
        // Что здесь измерено на этой ноде, а не выведено рассуждением:
        // писуемым становится собственное поддерево контейнера, а не иерархия
        // узла (у настоящего корня узла нет `cgroup.events`, у этого есть, а
        // `/sys/fs/cgroup/../..` упирается в `/sys`), и `remount` не меняет
        // поле root в mountinfo, поэтому продуктовый `detect_cgroup2_root()`
        // этот корень принимает. Bind-mount хостового дерева запись бы дал, но
        // поле root у него не `/`, вывод корня вернул бы Degraded, и стадия
        // осталась бы красной по новой причине.
        stage('Datapath join') {
            agent any
            environment {
                DATAPATH_IMAGE = "${RUST_IMAGE}"
                DATAPATH_ARGS = "${DATAPATH_DOCKER_ARGS}"
            }
            stages {
            // Поднимает контейнер стыка и делает его cgroup2 писуемой.
            //
            // Проверяет `docker exec`, а не `nsenter`, и это не стилистика:
            // поле root в mountinfo относительно cgroup namespace читателя —
            // снаружи та же строка читается как `/../<id контейнера>`, изнутри
            // как `/`. Первое `detect_cgroup2_root()` отвергло бы, второе
            // принимает, и решает именно второе, потому что код идёт внутри
            // контейнера. Проверка обязана смотреть с той же точки, что и
            // проверяемое.
            //
            // Без `|| true` и без условного пропуска, как и у tracefs: remount,
            // который не поднялся, обязан уронить стадию здесь, а не
            // превратиться в прежний EROFS стадией ниже. И проверка — не
            // `mount | grep rw`, а настоящие `mkdir`/`rmdir` в том самом
            // namespace: «смонтировано rw» и «сюда можно писать» различает
            // только попытка записи.
            stage('Datapath cgroup') {
                steps {
                    // dist/ приезжает стэшем: у этой группы свой воркспейс,
                    // и 'BPF ELF' в него ничего не клала.
                    unstash 'image-context'
                    sh '''
                        set -eu
                        docker rm -f "$(cat .datapath-cid 2>/dev/null || true)" >/dev/null 2>&1 || true
                        cid=$(docker run -d --rm -u 0:0 \
                                -v "$WORKSPACE":"$WORKSPACE" -w "$WORKSPACE" \
                                $DATAPATH_ARGS "$DATAPATH_IMAGE" sleep 7200)
                        echo "$cid" > .datapath-cid
                        pid=$(docker inspect -f '{{.State.Pid}}' "$cid")
                        docker run --rm --privileged --pid=host alpine:3 \
                            nsenter -t "$pid" -m -- mount -o remount,rw /sys/fs/cgroup
                        docker exec "$cid" sh -c \
                            'grep -qE " / /sys/fs/cgroup rw," /proc/self/mountinfo \
                                || { echo "cgroup2 is not rw, or its mountinfo root is no longer /" >&2; exit 1; }
                             mkdir /sys/fs/cgroup/ferrum-cgroup-rw-probe
                             rmdir /sys/fs/cgroup/ferrum-cgroup-rw-probe'
                        echo "ok: cgroup2 is writable in the datapath container and its mountinfo root is still /"
                    '''
                }
            }

            // The join: a record this kernel wrote, through a signed bundle, to a
            // real SIGKILL. `BPF attach` proves the datapath writes the record the
            // decoder reads and links no agent; `cargo test --workspace` proves the
            // decision path on recorded bytes. Only this stage runs both halves in
            // one process, and it is the only place `SignalResponder::kill` — the
            // only unsafe call in the agent — ever returns Ok.
            //
            // Requires root (CAP_BPF plus CAP_KILL over its own forked probe),
            // tracefs, and a writable cgroup2 hierarchy: the probe is put in a
            // cgroup of the test's own so the reaction is checked against the real
            // /proc by ProcCgroupCheck, not a stub.
            //
            // The same three protections as `BPF attach`, for the same reason, and
            // the middle one is why that stage's comment used to say two.
            // FERRUM_BPF_ELF_REQUIRED turns every skip (no ELF, no tracepoint, no
            // cgroup2) into a failure. It cannot catch this line losing
            // `--features attach`, because attach_join.rs is cfg-gated on it and
            // would run zero tests and exit 0 — so `the_gate_must_not_be_compiled_out`
            // lives outside that cfg and fails when the var is set and the feature
            // is not. And the passed count is not a third protection: every skip in
            // `live()` is an early `return` from a `#[test]`, so a run that
            // attached nothing, decided nothing and killed nothing reports
            // `test result: ok. 4 passed` exactly like a real one, and dropping the
            // env var alone used to print this stage's own success line over it.
            // The positive control the count cannot supply is the evidence line the
            // shell test prints after `waitpid` has confirmed the SIGKILL: it is
            // reachable only from the far end of record → verdict → signal, so it
            // is required below, and `--show-output` is what makes a passing test's
            // stdout visible to that check.
            stage('BPF join') {
                steps {
                    writeFile file: '.datapath-join.sh', text: '''
                        set -eu
                        elf="$PWD/dist/ferrum-ebpf-progs.bpf.o"
                        test -f "$elf"
                        out=/tmp/ferrum-attach-join.out
                        # Not a pipeline: /bin/sh is dash, which has no pipefail,
                        # and `| tee` would hand `set -e` tee's status.
                        if ! FERRUM_BPF_ELF_REQUIRED=1 FERRUM_BPF_ELF="$elf" \
                            cargo test -p ferrum-agent --features attach,apiserver \
                            --test attach_join -- --show-output > "$out" 2>&1
                        then
                            cat "$out"
                            exit 1
                        fi
                        cat "$out"
                        passed="$(sed -n 's/^test result: ok\\. \\([0-9][0-9]*\\) passed.*/\\1/p' "$out" | head -1)"
                        src=crates/ferrum-agent/tests/attach_join.rs
                        # Every test in the join, derived from the source for the
                        # reason the same line in 'BPF attach' is: "at least one"
                        # goes green with the other four ignored, and the boundary
                        # rows for docker.sock, the truncated path, the flag-stripped
                        # record and REFUSE_STALE_TARGET would then be proved by
                        # nothing that ran. `mod gate` starts the cfg(attach) half.
                        expected="$(sed -n '/^mod gate {/,$p' "$src" \
                            | grep -cE '^[[:space:]]*#\\[test\\][[:space:]]*$')"
                        if [ "${expected:-0}" -lt 1 ]; then
                            echo "counted no #[test] under mod gate in $src. This stage's own" >&2
                            echo "idea of what it must run is broken, so it can no longer tell a" >&2
                            echo "full run from an empty one." >&2
                            exit 1
                        fi
                        if [ "${passed:-0}" -ne "$expected" ]; then
                            echo "BPF join ran ${passed:-no} of the $expected tests in $src. The" >&2
                            echo "only stage that carries a kernel record to a real SIGKILL must" >&2
                            echo "run all of them: an ignored or filtered test leaves the section D" >&2
                            echo "row it covers asserted by no code that executed. Check that" >&2
                            echo "--features attach is still on the cargo test line." >&2
                            exit 1
                        fi
                        # Per-test evidence, named. Each test that reaches a
                        # confirmed SIGKILL prints one line through one helper. The
                        # line is printed after waitpid has confirmed the signal, so
                        # it is reachable only from the far end of record -> verdict
                        # -> signal, and no skip can emit it.
                        #
                        # The set is read out of join_evidence.rs and NOT out of
                        # $src, which is where it came from until cycle 11.
                        # Deriving it from the file under test is self-lowering one
                        # level finer than the count, and cheaper to hit: gut the
                        # kill half of one test — keep its record and decode
                        # assertions, drop the responder call and its
                        # signalled(...) — and the test passes, passed still equals
                        # expected, the required set silently shrinks from four
                        # labels to three, this stage goes green, and the section D
                        # row that test covers keeps a K witness that no longer
                        # carries a record to a signal. join_evidence.rs holds the
                        # set to the rows the boundary document names and asserts
                        # against $src in both directions under a plain cargo test.
                        #
                        # The one join test with no line here is the stale-target
                        # refusal, which deliberately kills nothing; the count check
                        # above is what covers it.
                        names=/tmp/ferrum-join-evidence.txt
                        anchor=crates/ferrum-agent/tests/join_evidence.rs
                        sed -n 's/^ *evidence: "\\(.*\\)",$/\\1/p' "$anchor" \
                            | sort -u > "$names"
                        if [ ! -s "$names" ]; then
                            echo "no evidence labels found in $anchor: this stage can no longer" >&2
                            echo "name the evidence it requires, so requiring it proves nothing." >&2
                            echo "Check the shape of REQUIRED_KILLS." >&2
                            exit 1
                        fi
                        while read -r what; do
                            if ! grep -q "$what: kernel record" "$out"; then
                                echo "BPF join reported $passed passed tests without the evidence" >&2
                                echo "line for '$what'. Every skip in live() is an early return" >&2
                                echo "from a #[test], so the count alone cannot tell a skipped run" >&2
                                echo "from a real one; the waitpid line can, and this one is" >&2
                                echo "absent. Check FERRUM_BPF_ELF_REQUIRED, --features attach and" >&2
                                echo "-- --show-output are all still on the cargo test line." >&2
                                exit 1
                            fi
                        done < "$names"
                        evidence="$(wc -l < "$names")"
                        echo "ok: all $passed join tests ran and $evidence of them took a kernel"
                        echo "ok: record through a signed bundle to a confirmed SIGKILL"
                        # The lib tests under the pair of features the DaemonSet
                        # ships with, for the same reason the ebpf stage above runs
                        # its own: `--test attach_join` compiles and runs exactly
                        # one integration target. `cargo test --workspace` is
                        # default features and both of these are off, so until this
                        # line the agent's 150 unit tests had never been *run*
                        # under `attach,apiserver` — only compiled, by the clippy
                        # line, which links nothing and executes nothing.
                        cargo test -p ferrum-agent --features attach,apiserver --lib
                    '''
                    sh '''
                        set -eu
                        docker exec -w "$WORKSPACE" \
                            -e CARGO_TARGET_DIR=/build-target \
                            -e CARGO_TERM_COLOR=never \
                            -e CARGO_INSTALL_ROOT=/cargo-tools \
                            "$(cat .datapath-cid)" sh .datapath-join.sh
                    '''
                }
            }

            // Measures the gate above rather than the code: each patch must make
            // the join fail. Cycle 8's most valuable finding came from patching the
            // datapath by hand and watching six of seven tests still pass, and that
            // measurement survived only as prose in a merge body.
            //
            // No patch here survives. This comment said one did until the harness
            // was run: on Linux 6.18.44 all six are killed, each naming the gate::
            // test that caught it. It then said four for a cycle after two more
            // were added — the patch headers and the boundary document were
            // refreshed and this line was not, which is why the count it names is
            // now derived and not written down. A `cargo test` exit status is not
            // on its own a kill — it is also what a compile error returns — so
            // run.sh requires per patch that the join built, ran, and named a
            // failing test.
            //
            // And how many patches: run.sh iterated whatever *.patch it found and
            // asserted nothing about the number, so deleting five of six left one
            // measured mutation, no survivors, and this stage green. The set is
            // named in crates/ferrum-agent/tests/mutation_manifest.rs, which
            // run.sh checks this directory against before it applies anything and
            // which `cargo test --workspace` holds to the directory on every
            // commit, kernel or no kernel.
            stage('BPF join mutations') {
                steps {
                    writeFile file: '.datapath-mutations.sh', text: '''
                        set -eu
                        FERRUM_BPF_ELF="$PWD/dist/ferrum-ebpf-progs.bpf.o" \
                            crates/ferrum-agent/tests/mutations/run.sh
                    '''
                    sh '''
                        set -eu
                        docker exec -w "$WORKSPACE" \
                            -e CARGO_TARGET_DIR=/build-target \
                            -e CARGO_TERM_COLOR=never \
                            -e CARGO_INSTALL_ROOT=/cargo-tools \
                            "$(cat .datapath-cid)" sh .datapath-mutations.sh
                    '''
                }
            }
            }
            post {
                always {
                    sh 'docker rm -f "$(cat .datapath-cid 2>/dev/null || true)" >/dev/null 2>&1 || true'
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
