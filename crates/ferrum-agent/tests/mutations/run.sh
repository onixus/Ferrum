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

# The root, from this script's own path rather than from `git rev-parse`, and
# every git call below carrying `-c safe.directory=$root`.
#
# Both halves are about the same fact: everywhere this script is *meant* to
# run, the process is root and the checkout is not its. The join needs CAP_BPF
# and CAP_KILL, so the container runs `-u 0:0`, while the tree it mounts
# belongs to whoever cloned it — and git refuses a repository owned by another
# user with `dubious ownership`, before the first patch is applied. That is
# what happened on the third stand (docs/MVP-1-BOUNDARY.md): the stage died on
# `git rev-parse`, having measured nothing, and looked from the log exactly
# like a broken build. It does not happen on the Jenkins node only because
# there the workspace happens to belong to the same uid as the container, i.e.
# by coincidence of that one setup.
#
# `-c` and not `git config --global`: the exemption is scoped to this one path
# and to these invocations, and it does not edit the caller's ~/.gitconfig or
# outlive the run. What it gives up is nothing this script had: the check
# exists to stop git from reading another user's repository config and hooks,
# and this script is a file *in* that repository, invoked deliberately, which
# then builds and runs that repository's code. There is no trust here for the
# check to protect — refusing to run is the only thing it can add.
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
root="${here%/crates/ferrum-agent/tests/mutations}"
if [ "$root" = "$here" ]; then
    echo "run.sh must live in crates/ferrum-agent/tests/mutations of the tree it" >&2
    echo "mutates: it derives the repository root from its own path, and from" >&2
    echo "$here it cannot. Run the copy in the checkout, not a copy beside it." >&2
    exit 1
fi

git_tree() {
    git -c "safe.directory=$root" -C "$root" "$@"
}

# git's own answer, kept as a cross-check rather than as the source: a root
# derived from a path and a root git disagrees with means this script is about
# to patch a tree other than the one it was run from.
toplevel="$(git_tree rev-parse --show-toplevel)"
if [ "$toplevel" != "$root" ]; then
    echo "this script sits in $root but git calls $toplevel the top level of that" >&2
    echo "tree. Applying mutations here would patch one checkout and test another." >&2
    exit 1
fi
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
        if git_tree apply -R "$applied"; then
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
    git_tree apply -R "$1"
    applied=''
    if grep -q 'ferrum-ebpf-progs' "$1"; then
        build_elf
    fi
}

# The floor, derived from the tree rather than from this directory.
#
# Everything below iterates whatever *.patch it finds and asserts nothing about
# how many. Delete 02..06 and keep 01: one mutation is measured, survivors=0,
# unmeasured=0, and the success line at the end still says every mutation makes
# the join fail — of a set a fifth of the size, with the boundary rows for the
# truncated path, the flag-stripped record and RESPOND_SIGNAL_FAILING then
# measured by nothing that ran. That is the "green having run almost nothing"
# shape the two stages above this one closed by deriving their counts from the
# source, and a harness cannot derive its own floor from the directory it is
# supposed to be checking. `mutation_manifest.rs` names the set; a `cargo test`
# holds that list to this directory, and this holds this run to that list.
manifest="$root/crates/ferrum-agent/tests/mutation_manifest.rs"
test -f "$manifest"
floor="$(sed -n 's/^ *"\(.*\.patch\)",$/\1/p' "$manifest" | wc -l)"
if [ "$floor" -lt 1 ]; then
    echo "read no patch names out of $manifest. This script's own idea of how many" >&2
    echo "mutations it must measure is broken, so it can no longer tell a full run" >&2
    echo "from one patch." >&2
    exit 1
fi
found=0
for patch in "$here"/*.patch; do
    test -f "$patch" && found=$((found + 1))
done
if [ "$found" -ne "$floor" ]; then
    echo "$here holds $found patch(es) and $manifest names $floor. A mutation that is" >&2
    echo "not on disk is a property this gate is no longer measured against, and this" >&2
    echo "script would otherwise report ok for whatever is left. Re-anchor the missing" >&2
    echo "patch, or register a new one in mutation_manifest.rs." >&2
    exit 1
fi

survivors=0
unmeasured=0
measured=0
for patch in "$here"/*.patch; do
    name="$(basename "$patch")"
    echo "=== mutation: $name"
    if ! git_tree apply "$patch"; then
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
    measured=$((measured + 1))
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
if [ "$measured" -ne "$floor" ]; then
    echo "$measured of $floor mutations reached a kill. Nothing above reported a" >&2
    echo "survivor or an unmeasured patch, so the loop did not run over the set this" >&2
    echo "script checked before it started: the count is what is left to notice that." >&2
    exit 1
fi
echo "ok: all $floor mutations named by mutation_manifest.rs make tests/attach_join.rs"
echo "    fail, and each failure names the gate:: test that caught it"
