#!/bin/sh
# Measure the join gate, not the code it gates.
#
# A gate no mutation can break is a gate nobody has measured. Cycle 8 found its
# most valuable defect by patching the datapath, rebuilding, and observing that
# six of seven tests still passed — a fact about the *suite* that existed
# afterwards only as prose. This script is that measurement, kept executable.
#
# Each patch beside this one deletes one thing the join is supposed to prove.
# For each: apply, rebuild what the patch invalidates, run
# `tests/attach_join.rs`, and require that it FAILS. A patch the suite survives
# is reported as a survivor and fails this script, so a mutation whose defect
# the gate stopped catching cannot go unnoticed either.
#
# Every patch is reverted before the next one, including after a failure.
#
# Usage, from the repository root:
#
#     FERRUM_BPF_ELF=/path/to/ferrum-ebpf-progs crates/ferrum-agent/tests/mutations/run.sh
#
# Needs the same environment as the join itself (root, tracefs, cgroup2), plus
# the nightly toolchain and bpf-linker for the one mutation that lives in the
# datapath.
set -eu

root="$(git rev-parse --show-toplevel)"
here="$root/crates/ferrum-agent/tests/mutations"
: "${FERRUM_BPF_ELF:?set FERRUM_BPF_ELF to the compiled bpf ELF}"
elf="$FERRUM_BPF_ELF"
test -f "$elf"

# The ELF is rebuilt in place for datapath mutations, so keep the clean one.
clean_elf=/tmp/ferrum-mutations-clean.bpf.o
cp "$elf" "$clean_elf"

built="${CARGO_TARGET_DIR:-$root/target}/bpfel-unknown-none/release/ferrum-ebpf-progs"

build_elf() {
    cargo +nightly build -p ferrum-ebpf-progs \
        --target bpfel-unknown-none -Z build-std=core --release
    # The caller may have handed us a copy (the Jenkins stage archives one).
    if [ "$built" != "$elf" ]; then
        cp "$built" "$elf"
    fi
}

survivors=0
for patch in "$here"/*.patch; do
    name="$(basename "$patch")"
    echo "=== mutation: $name"
    git -C "$root" apply "$patch"

    if grep -q 'ferrum-ebpf-progs' "$patch"; then
        # A datapath mutation is invisible until the object is rebuilt; running
        # the join against the old ELF would report a false survivor.
        echo "    rebuilding the bpf ELF"
        build_elf
    fi

    status=0
    FERRUM_BPF_ELF_REQUIRED=1 FERRUM_BPF_ELF="$elf" \
        cargo test -p ferrum-agent --features attach,apiserver --test attach_join \
        > /tmp/ferrum-mutation.out 2>&1 || status=$?

    git -C "$root" apply -R "$patch"
    if grep -q 'ferrum-ebpf-progs' "$patch"; then
        build_elf
    fi

    if [ "$status" -eq 0 ]; then
        echo "    SURVIVOR: the join passed with this mutation applied." >&2
        sed -n 's/^test result: /    /p' /tmp/ferrum-mutation.out >&2
        survivors=$((survivors + 1))
    else
        echo "    killed by:"
        sed -n 's/^    gate::/        gate::/p' /tmp/ferrum-mutation.out
        sed -n 's/^test result: /    /p' /tmp/ferrum-mutation.out
    fi
done

# The ELF the caller handed us must be the one they get back.
cp "$clean_elf" "$elf"

if [ "$survivors" -ne 0 ]; then
    echo "$survivors mutation(s) survived: the join does not gate what it claims to" >&2
    exit 1
fi
echo "ok: every mutation beside this script makes tests/attach_join.rs fail"
