# The agent image. Produces ghcr.io/onixus/ferrum-agent, which deploy/agent
# names and which nothing in this repository built until now.
#
# Two things this file exists to guarantee, neither of which any other stage of
# the pipeline can:
#
#  1. The binary is linked with `--features attach,apiserver`. That is the only
#     production combination — the cgroup sync into ferrum_cgroups is compiled
#     out of every other one — and until this file it appeared exactly once in
#     CI, on a `cargo clippy` line that emits .rmeta and no object code.
#  2. The ELF in the image is the one this userspace agrees with. The map layout
#     is the whole join between an out-of-tree bpf object and the agent that
#     attaches it, and the image is where the two are welded together, so the
#     check runs here against the ELF that ships rather than against one that
#     happened to sit in a build directory.
#
#     `elf_inspect` reads that ELF and the map expectations compiled into
#     ferrum-ebpf. It never opens /ferrum-agent, so it is not a check on "the
#     two files that ship" — this header claimed that for a cycle and it was
#     not true of any line below. The binary gets its own check, and it needs
#     one: `cargo build` here is a second link, in a second container, from the
#     stashed sources. The one the pipeline archives and fingerprints is a
#     different file that never enters this image, so the musl/static claim
#     made about it does not carry over and is re-made below.
#
# The bpf object is built out of tree (nightly, bpfel-unknown-none, bpf-linker)
# and passed in through the build context at BPF_ELF. `COPY` fails when it is
# absent: an agent image with no datapath ELF is an agent that exits on the
# --bpf-elf the DaemonSet passes it, and that must fail here rather than on a
# node.
#
#   cargo +nightly build -p ferrum-ebpf-progs \
#       --target bpfel-unknown-none -Z build-std=core --release
#   cp target/bpfel-unknown-none/release/ferrum-ebpf-progs dist/ferrum-ebpf-progs.bpf.o
#   docker build -t ghcr.io/onixus/ferrum-agent:v0.1.0 .

ARG RUST_IMAGE=rust:1.75-bookworm
ARG TARGET=x86_64-unknown-linux-musl

# cargo-auditable вписывает в бинарь список crate и версий из Cargo.lock той
# сборки, которая его слинковала. Без него SBOM образа — это `scratch` и один
# статический ELF: syft увидит файл и ни одной зависимости, то есть SBOM,
# который нечего сказать. С ним `cargo audit bin` на стороне получателя
# отвечает на вопрос «что внутри» из самого артефакта, а не из репозитория,
# которому получатель ещё не обязан верить.
#
# Версия закреплена. `cargo install` без неё подписывает то, что выложат
# завтра, — в файле, который существует ради происхождения.
ARG CARGO_AUDITABLE_VERSION=0.7.5
ARG BPF_ELF=dist/ferrum-ebpf-progs.bpf.o

# --platform=$BUILDPLATFORM: собирать натив, а образ помечать целевой
# платформой. Без этого `docker build` на arm64-ноде клеймит образ
# linux/arm64, а внутри лежит x86_64-бинарь — образ, который не
# запустится ни там, ни там, и ни одна проверка внутри него этого не
# видит: они читают сам файл, а не манифест вокруг него.
FROM --platform=$BUILDPLATFORM ${RUST_IMAGE} AS build
ARG TARGET
ARG CARGO_AUDITABLE_VERSION
ARG BPF_ELF

# musl, not gnu, и цель x86_64 берётся кроссом, а не архитектурой демона:
# `docker build` идёт на ноде, а нода здесь arm64. musl-tools дал бы musl-gcc
# родной архитектуры, который не понимает -m64 в C-половине ring; линкует
# rust-lld тем musl, который везёт rustup. `rustup target add` стоит ниже COPY
# намеренно: rust-toolchain.toml пинит тулчейн, и до появления исходников цель
# ставится не тому, который потом собирает.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        gcc-x86-64-linux-gnu libc6-dev-amd64-cross \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Ниже COPY по той же причине, что и `rustup target add`: тулчейн пинит
# rust-toolchain.toml, и до появления исходников инструмент собрался бы
# не тем компилятором, который потом линкует бинарь.
RUN cargo install --locked "cargo-auditable@${CARGO_AUDITABLE_VERSION}"

# --locked: the image is a release artefact, and a build that may resolve a
# different dependency set than CI tested is not one.
RUN rustup target add "${TARGET}" \
 && CC_x86_64_unknown_linux_musl=x86_64-linux-gnu-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    RUSTFLAGS="-C link-self-contained=yes" \
    cargo auditable build --release --locked --target "${TARGET}" \
        -p ferrum-agent --features attach,apiserver \
 && cp "target/${TARGET}/release/ferrum-agent" /ferrum-agent

# The base below is scratch: a dynamically linked "musl" build would produce an
# image whose only executable cannot start, and nothing in the image could say
# why. `file` is not in this image; the interpreter entry is, and its absence is
# the whole claim. This repeats the check the 'Agent binary' stage makes because
# that stage checks a different file — its binary is archived, not copied here.
RUN if readelf -lW /ferrum-agent | grep -q 'Requesting program interpreter'; then \
        echo "the agent linked for ${TARGET} requests an interpreter: it would not" >&2; \
        echo "start on the scratch base this image is built on" >&2; \
        exit 1; \
    fi

# Список зависимостей — в бинаре, а не только в обещании выше. Секция
# `.dep-v0` — то единственное, что `cargo audit bin` на стороне получателя
# читает; сборка обычным `cargo build` её не кладёт, и SBOM образа тогда
# честно перечисляет один файл. Проверка стоит здесь, потому что это
# единственное место, где виден именно тот бинарь, который поедет в образ.
RUN if ! readelf -SW /ferrum-agent | grep -q '\.dep-v0'; then \
        echo "/ferrum-agent carries no .dep-v0 section: it was linked by plain" >&2; \
        echo "cargo build, and the SBOM of this image would list no dependency" >&2; \
        exit 1; \
    fi

COPY ${BPF_ELF} /ferrum-ebpf-progs.bpf.o

# The map layout of the ELF that is about to be copied into the image, against
# the layout this workspace's userspace expects. FERRUM_BPF_ELF_REQUIRED turns a
# skip into a failure: this test skips silently without an ELF, and a silent
# skip here would ship exactly the mismatch the test exists to catch.
RUN FERRUM_BPF_ELF_REQUIRED=1 FERRUM_BPF_ELF=/ferrum-ebpf-progs.bpf.o \
    cargo test -p ferrum-ebpf --test elf_inspect

# scratch, not distroless: the binary is static-pie musl and the agent's only
# TLS root is the cluster CA it reads from its ServiceAccount, so there is
# nothing for a base image to provide. readOnlyRootFilesystem in the DaemonSet
# then has nothing left to protect, which is the point.
FROM scratch
COPY --from=build /ferrum-agent /usr/local/bin/ferrum-agent
# The path deploy/agent/daemonset.yaml and optional-respond.yaml pass as
# --bpf-elf. Changing it here changes it in both manifests.
COPY --from=build /ferrum-ebpf-progs.bpf.o /usr/share/ferrum/ferrum-ebpf-progs.bpf.o

# No USER: the container starts with capabilities dropped to BPF and PERFMON by
# the DaemonSet, which is the bound that matters. A uid switch here would not
# add one and would cost the added capabilities their permitted set.
ENTRYPOINT ["/usr/local/bin/ferrum-agent"]
