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
# `tests/attach_join.rs`, and require that it FAILS *and names the tests that
# failed*. A patch the suite survives is reported as a survivor and fails this
# script, so a mutation whose defect the gate stopped catching cannot go
# unnoticed either.
#
# A non-zero `cargo test` is not on its own evidence of anything. It is also
# what a compile error exits with, so a patch that stops building — a type
# error, or a rename in the code it depends on — would otherwise be counted as
# a kill by a harness that never ran the join once: this script's own defect
# class, aimed at itself. Each patch therefore has to clear three separate
# bars: the tree still built, the join actually ran, and at least one `gate::`
# test is named in the failure list.
#
# Three ways of not measuring are reported apart, because they are three
# different repairs:
#
#   * the patch does not apply -> the harness is stale, the build is not
#     broken. These patches are anchored to code other slices edit; when one
#     drifts, `git apply` says "patch does not apply", which reads as a broken
#     build unless something says otherwise. Re-anchor the patch.
#   * it applied and nothing ran -> a mutation is supposed to break behaviour,
#     not compilation. Fix the patch.
#   * the join passed -> a survivor. Fix the gate, or the patch is describing a
#     property the gate never had.
#
# Every patch is reverted before the next one, including after a failure and
# including on a signal: the revert and the ELF restore run from an EXIT trap,
# because `set -e` on a failing build would otherwise leave the working tree
# patched and `dist/ferrum-ebpf-progs.bpf.o` holding the *mutated* datapath —
# an object nothing consumes today and an image would ship the day the stages
# are reordered.
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
out=/tmp/ferrum-mutation.out

# The patch currently applied to the working tree, empty when none is.
applied=''

# Runs on every exit path, including a failing build under `set -e` and a
# signal. Restoring the clean object is a copy and never a rebuild: a rebuild
# is itself a thing that can fail, and this is the handler for things failing.
restore() {
    code=$?
    if [ -n "$applied" ]; then
        if git -C "$root" apply -R "$applied"; then
            applied=''
        else
            echo "could not revert $(basename "$applied"): the working tree is still" >&2
            echo "mutated. Revert it by hand before trusting anything built here." >&2
            code=1
        fi
    fi
    cp "$clean_elf" "$elf" || code=1
    if [ -f "$built" ]; then
        cp "$clean_elf" "$built" || code=1
    fi
    exit "$code"
}
trap restore EXIT
trap 'exit 1' INT TERM HUP

build_elf() {
    cargo +nightly build -p ferrum-ebpf-progs \
        --target bpfel-unknown-none -Z build-std=core --release
    # The caller may have handed us a copy (the Jenkins stage archives one).
    if [ "$built" != "$elf" ]; then
        cp "$built" "$elf"
    fi
}

# Revert the patch this iteration applied, and put the datapath object back
# where the next iteration expects it.
revert() {
    git -C "$root" apply -R "$1"
    applied=''
    if grep -q 'ferrum-ebpf-progs' "$1"; then
        build_elf
    fi
}

survivors=0
unmeasured=0
for patch in "$here"/*.patch; do
    name="$(basename "$patch")"
    echo "=== mutation: $name"
    if ! git -C "$root" apply "$patch"; then
        echo "    STALE: $name no longer applies to this tree." >&2
        echo "    That is a fact about the mutation harness, not about the build:" >&2
        echo "    the patch is anchored to code another slice has since edited." >&2
        echo "    Re-anchor it to the current source; do not delete it." >&2
        unmeasured=$((unmeasured + 1))
        continue
    fi
    applied="$patch"

    if grep -q 'ferrum-ebpf-progs' "$patch"; then
        # A datapath mutation is invisible until the object is rebuilt; running
        # the join against the old ELF would report a false survivor.
        echo "    rebuilding the bpf ELF"
        if ! build_elf; then
            echo "    UNMEASURED: the datapath does not build with $name applied." >&2
            echo "    A mutation must break behaviour, not compilation. Nothing here" >&2
            echo "    ran the join, so nothing here says the gate catches anything." >&2
            unmeasured=$((unmeasured + 1))
            revert "$patch"
            continue
        fi
    fi

    status=0
    FERRUM_BPF_ELF_REQUIRED=1 FERRUM_BPF_ELF="$elf" \
        cargo test -p ferrum-agent --features attach,apiserver --test attach_join \
        > "$out" 2>&1 || status=$?

    revert "$patch"

    # The three bars, in the order they can fail. `cargo test` exits non-zero
    # for a compile error exactly as it does for a failing assertion, so the
    # status alone proves nothing; a `test result:` line proves the binary was
    # linked and run; a named `gate::` test proves the join is what objected.
    if ! grep -q '^test result: ' "$out"; then
        echo "    UNMEASURED: no test binary ran with $name applied." >&2
        echo "    cargo exited $status without reporting a test result, which is what" >&2
        echo "    a compile error looks like. A patch that stops the tree building" >&2
        echo "    measures nothing about the gate. Last lines:" >&2
        tail -n 15 "$out" >&2
        unmeasured=$((unmeasured + 1))
        continue
    fi
    if [ "$status" -eq 0 ]; then
        echo "    SURVIVOR: the join passed with this mutation applied." >&2
        sed -n 's/^test result: /    /p' "$out" >&2
        survivors=$((survivors + 1))
        continue
    fi
    killers="$(sed -n 's/^    gate::/gate::/p' "$out" | sort -u)"
    if [ -z "$killers" ]; then
        echo "    UNMEASURED: the join ran and failed with $name applied, and named" >&2
        echo "    no gate:: test. Something other than the mutation's own defect" >&2
        echo "    ended this run. Last lines:" >&2
        tail -n 15 "$out" >&2
        unmeasured=$((unmeasured + 1))
        continue
    fi
    echo "    killed by:"
    echo "$killers" | sed 's/^/        /'
    sed -n 's/^test result: /    /p' "$out"
done

if [ "$unmeasured" -ne 0 ]; then
    echo "$unmeasured mutation(s) measured nothing: the harness never ran the join" >&2
    echo "against them, so it says nothing about what the gate catches" >&2
    exit 1
fi
if [ "$survivors" -ne 0 ]; then
    echo "$survivors mutation(s) survived: the join does not gate what it claims to" >&2
    exit 1
fi
echo "ok: every mutation beside this script makes tests/attach_join.rs fail, and each"
echo "    failure names the gate:: test that caught it"
