#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# 1) Sanitized + coverage-instrumented build of mergerfs and its vendored libfuse, with upstream's
#    own Makefiles, into build/fuzz (under the gitignored build/ and vendored/libfuse/build/).
#    CXXFLAGS replaces upstream's default flag set (its -Werror=*-move warnings are GCC-oriented);
#    the Makefile still appends -std=c++20 -MMD -MP and its include/define flags. The top Makefile
#    spells its object list as build/.objs/..., so OBJS is overridden to match BUILDDIR.
FUZZ_OBJS=$(for f in src/*.cpp; do b=${f#src/}; printf 'build/fuzz/.objs/%s.o ' "$b"; done)
FUZZ_CXXFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 -Wall -Wno-unused-result -Wno-unused-parameter -pipe"
# libfuse first, on its own: OBJS on the top-level command line would leak into its sub-make.
make -j"$MAYHEM_JOBS" -C vendored/libfuse BUILDDIR=build/fuzz CXX="$CXX" CC="$CC" \
     CXXFLAGS="$FUZZ_CXXFLAGS" CFLAGS="$FUZZ_CXXFLAGS" build/fuzz/libfuse.a
make -j"$MAYHEM_JOBS" BUILDDIR=build/fuzz OBJS="$FUZZ_OBJS" CXX="$CXX" CC="$CC" \
     CXXFLAGS="$FUZZ_CXXFLAGS" CFLAGS="$FUZZ_CXXFLAGS" build/fuzz/mergerfs

# 2) Harnesses: link every mergerfs object except mergerfs.cpp.o (it holds main), like upstream's
#    `tests` rule, plus the sanitized libfuse.a. Each is linked twice (libFuzzer + standalone).
INC="-Isrc -Ivendored -Ivendored/libfuse/include -DUSE_XATTR=1 -D_FILE_OFFSET_BITS=64 -DBOOST_UNORDERED_DISABLE_PARALLEL_ALGORITHMS -std=c++20"
OBJS=$(ls build/fuzz/.objs/*.cpp.o | grep -v '/mergerfs\.cpp\.o$')
LIBS="vendored/libfuse/build/fuzz/libfuse.a -lrt -pthread"
mkdir -p build/fuzz/harness
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/fuzz/harness/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/fuzz/harness/standalone_main.o
for h in fuzz_config fuzz_cli fuzz_fuse; do
  $CXX $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1 $INC \
       -c "mayhem/harnesses/$h.cpp" -o "build/fuzz/harness/$h.o"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "build/fuzz/harness/$h.o" \
       build/fuzz/harness/lsan_off.o $OBJS $LIBS -o "/mayhem/$h"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS build/fuzz/harness/standalone_main.o "build/fuzz/harness/$h.o" \
       build/fuzz/harness/lsan_off.o $OBJS $LIBS -o "/mayhem/$h-standalone"
done

# 3) Upstream's own unit-test suite (tests/tests.cpp, acutest) with the project's NORMAL flags,
#    into upstream's default build/ dir: build/tests. (The tests/TEST_* scripts need a live
#    FUSE mount and are not run.)
make -j"$MAYHEM_JOBS" CXX="$CXX" CC="$CC" tests
