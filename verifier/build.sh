#!/usr/bin/env bash
# Build shrincs_verify against a Bitcoin Core source tree.
#
#   ./build.sh SRC OUT [FLAGS...]
#
# SRC is the Bitcoin Core source tree, OUT the output binary. FLAGS are passed
# when compiling shrincs_verify.cpp only (e.g. -O3, -march=native, or a
# parameter set: -DSL_WOTS_BITS=6 -DSL_LAYERS=6 ...); Bitcoin Core's SHA-256
# and libsecp256k1 (for the BIP340 timing) are built as in measure_constants.py.
# CXX selects the compiler for shrincs_verify.cpp (default g++).
set -euo pipefail

src=$(realpath "$1")
out=$2
shift 2
here=$(dirname "$(realpath "$0")")
obj=$(mktemp -d)
trap 'rm -rf "$obj"' EXIT

python3 -c "import sys; sys.path.insert(0, '$here/../model'); import measure_constants as m; open('$obj/secp_bench.c', 'w').write(m.SECP_BENCH_C)"
secp="$src/src/secp256k1"
gcc -O2 -DECMULT_WINDOW_SIZE=15 -DUSE_ASM_X86_64=1 -I"$secp" -I"$secp/include" -I"$secp/src" \
    -c "$obj/secp_bench.c" -o "$obj/secp_bench.o"

core=(g++ -O2 -std=c++20 -I"$src/src" -DENABLE_SSE41 -DENABLE_AVX2 -DENABLE_X86_SHANI)
"${core[@]}" -c "$src/src/crypto/sha256.cpp" -o "$obj/sha256.o"
"${core[@]}" -c "$src/src/crypto/sha256_sse4.cpp" -o "$obj/sha256_sse4.o"
"${core[@]}" -msse4.1 -c "$src/src/crypto/sha256_sse41.cpp" -o "$obj/sha256_sse41.o"
"${core[@]}" -mavx -mavx2 -c "$src/src/crypto/sha256_avx2.cpp" -o "$obj/sha256_avx2.o"
"${core[@]}" -msse4 -msha -c "$src/src/crypto/sha256_x86_shani.cpp" -o "$obj/sha256_x86_shani.o"

"${CXX:-g++}" -O2 -std=c++20 -Wall -Wextra -I"$src/src" "$@" -c "$here/shrincs_verify.cpp" -o "$obj/shrincs_verify.o"
g++ "$obj"/*.o -o "$out"
