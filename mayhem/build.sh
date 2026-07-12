#!/usr/bin/env bash
#
# mayhem/build.sh — cpp-peglib (header-only PEG parser library).
# Builds: (1) the peglib-fuzz libFuzzer harness (sanitized, DWARF-3),
#         (2) a standalone run-once reproducer, and
#         (3) the upstream googletest suite (peglib-test-main) with normal flags.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# 1+2) The library is header-only (peglib.h): compiling the harness with $SANITIZER_FLAGS
#      instruments the whole fuzzed code path.
$CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
    -I"$SRC" "$SRC/mayhem/peglib-fuzz.cpp" -lpthread \
    -o /mayhem/peglib-fuzz

# Standalone (non-fuzzer) run-once reproducer: compile the driver as C first so
# its LLVMFuzzerTestOneInput reference keeps C linkage.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS \
    -I"$SRC" "$SRC/mayhem/peglib-fuzz.cpp" /tmp/standalone_main.o -lpthread \
    -o /mayhem/peglib-fuzz-standalone

# 3) Upstream test suite (googletest, normal flags). googletest is pre-fetched into the
#    image at /home/mayhem/googletest-src (Dockerfile) so this configures offline.
cmake -S "$SRC" -B "$SRC/build-tests" \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
    -DBUILD_TESTS=ON -DPEGLIB_BUILD_BENCHMARK=OFF \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=/home/mayhem/googletest-src
cmake --build "$SRC/build-tests" -j"$MAYHEM_JOBS" --target peglib-test-main
