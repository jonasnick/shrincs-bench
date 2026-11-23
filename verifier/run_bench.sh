#!/usr/bin/env bash
# Build, test and benchmark shrincs_verify for parameter sets and compiler
# configurations.
#
#   ./run_bench.sh SRC VECTORS OUT CPU [SET...]
#
# SRC is a Bitcoin Core source tree, VECTORS a directory with one CSV of
# signatures per parameter set (gen_vectors.py writes bench.csv for the BIP's
# set, gen_param_vectors.py <set>.csv for the others), OUT receives
# results.jsonl, CPU pins the runs. Every binary first runs `test` on its
# vectors (valid and tampered signatures in every variant) and is benchmarked
# only if that passes.
set -euo pipefail

src=$1
vectors=$(realpath "$2")
out=$(realpath "$3")
cpu=$4
shift 4
here=$(dirname "$(realpath "$0")")
mkdir -p "$out"

# Parameter set: compiler flags (the BIP's set needs none).
declare -A params=(
    [bip]=""
    [sl-45-5-10-13-16]=""
    [sl-40-5-10-15-32]="-DSL_WOTS_BITS=5 -DSL_LAYERS=5 -DSL_XMSS_HEIGHT=8 -DSL_FORS_HEIGHT=15 -DSL_FORS_COUNT=10"
    [sl-42-6-9-15-64]="-DSL_WOTS_BITS=6 -DSL_LAYERS=6 -DSL_XMSS_HEIGHT=7 -DSL_FORS_HEIGHT=15 -DSL_FORS_COUNT=9"
    [sl-40-5-9-16-64]="-DSL_WOTS_BITS=6 -DSL_LAYERS=5 -DSL_XMSS_HEIGHT=8 -DSL_FORS_HEIGHT=16 -DSL_FORS_COUNT=9"
    [sl-40-4-9-16-64]="-DSL_WOTS_BITS=6 -DSL_LAYERS=4 -DSL_XMSS_HEIGHT=10 -DSL_FORS_HEIGHT=16 -DSL_FORS_COUNT=9"
    [sl-44-4-8-16-64]="-DSL_WOTS_BITS=6 -DSL_LAYERS=4 -DSL_XMSS_HEIGHT=11 -DSL_FORS_HEIGHT=16 -DSL_FORS_COUNT=8"
    [sl-42-3-7-19-64]="-DSL_WOTS_BITS=6 -DSL_LAYERS=3 -DSL_XMSS_HEIGHT=14 -DSL_FORS_HEIGHT=19 -DSL_FORS_COUNT=7"
    [sf-w16]=""
    [sf-w32]="-DSF_WOTS_BITS=5"
    [sf-w64]="-DSF_WOTS_BITS=6"
)
# Compiler configuration: CXX and flags for shrincs_verify.cpp.
configs=(
    "g++|-O2"
    "g++|-O2 -march=native"
    "g++|-O3"
    "g++|-O3 -march=native"
    "clang++|-O2"
    "clang++|-O2 -march=native"
)

sets=("$@")
failed=0
{
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2-), pinned to CPU $cpu"
    echo "g++: $(g++ --version | head -1)"
    echo "clang++: $(clang++ --version 2>/dev/null | head -1)"
    echo "bitcoin core: $(sed -nE 's/^set\(CLIENT_VERSION_(MAJOR|MINOR|BUILD) ([0-9]+)\)/\2/p' "$src/CMakeLists.txt" 2>/dev/null | paste -sd.)"
    (cd "$here" && sha256sum shrincs_verify.cpp build.sh run_bench.sh ../model/measure_constants.py)
    (cd "$vectors" && sha256sum ./*.csv)
} > "$out/manifest.txt"
[ ${#sets[@]} -eq 0 ] && sets=(sl-45-5-10-13-16 sl-40-5-10-15-32 sl-42-6-9-15-64 sl-40-5-9-16-64 sl-40-4-9-16-64 sl-44-4-8-16-64 sl-42-3-7-19-64 sf-w16 sf-w32 sf-w64)

for set in "${sets[@]}"; do
    csv="$vectors/$set.csv"
    [ "$set" = bip ] && csv="$vectors/bench.csv"
    for config in "${configs[@]}"; do
        cxx=${config%%|*}
        flags=${config#*|}
        bin="$out/shrincs_verify"
        # shellcheck disable=SC2086
        CXX=$cxx "$here/build.sh" "$src" "$bin" $flags ${params[$set]} -DALLOW_ANY_SIZES
        if ! taskset -c "$cpu" "$bin" test "$csv" > "$out/test.log"; then
            echo "TEST FAILED: $set, $cxx $flags" | tee -a "$out/failures.log"
            cat "$out/test.log" >> "$out/failures.log"
            failed=1
            continue
        fi
        taskset -c "$cpu" "$bin" bench "$csv" 5 |
            sed "s/^{/{\"set\": \"$set\", \"compiler\": \"$cxx $flags\", /" | tee -a "$out/results.jsonl"
    done
done
exit $failed
