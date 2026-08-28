# The agent image. Produces ghcr.io/ferrum/ferrum-agent, which deploy/agent
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
#     check runs here against the two files that ship, not against a pair that
#     happened to sit in a build directory.
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
#   docker build -t ghcr.io/ferrum/ferrum-agent:v0.1.0 .

ARG RUST_IMAGE=rust:1.75-bookworm
ARG TARGET=x86_64-unknown-linux-musl
ARG BPF_ELF=dist/ferrum-ebpf-progs.bpf.o

FROM ${RUST_IMAGE} AS build
ARG TARGET
ARG BPF_ELF

# musl, not gnu: AGENTS.md requires it of userspace, and a static agent is one
# fewer thing that has to match the node's libc. ring compiles C, so the musl
# target needs its own cc as well as the Rust std.
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add "${TARGET}"

WORKDIR /src
COPY . .

# --locked: the image is a release artefact, and a build that may resolve a
# different dependency set than CI tested is not one.
RUN CC_x86_64_unknown_linux_musl=musl-gcc \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
    cargo build --release --locked --target "${TARGET}" \
        -p ferrum-agent --features attach,apiserver \
 && cp "target/${TARGET}/release/ferrum-agent" /ferrum-agent

COPY ${BPF_ELF} /ferrum-ebpf-progs.bpf.o

# The join, checked between the two files that are about to be copied into the
# same image. FERRUM_BPF_ELF_REQUIRED turns a skip into a failure: this test
# skips silently without an ELF, and a silent skip here would ship exactly the
# mismatch the test exists to catch.
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
