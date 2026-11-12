#!/usr/bin/env bash
#
# mayhem/build.sh — build the netmap fuzz harnesses (sanitized) and the known-answer probe (normal flags).
# Runs inside the commit image as `mayhem` in /mayhem; offline.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
M="$SRC/mayhem"
FUZZ="$M/build-fuzz"
TEST="$M/build-test"
INC="-I$SRC/sys -I$SRC/libnetmap -I$SRC/apps/include -I$SRC/apps/lb"
LIBSRC="nmctx nmctx-pthreads nmport nmreq"
LIBS="-lm -lpthread -lrt"

rm -rf "$FUZZ" "$TEST"
mkdir -p "$FUZZ" "$TEST"

# 1) libnetmap, sanitized, with SanCov so the fuzzed library reports edges (the harness TUs get the same flag).
for f in $LIBSRC; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link $INC \
      -c "$SRC/libnetmap/$f.c" -o "$FUZZ/$f.o"
done
# pkt_hash.c reads the IP header through a `struct ip *` at offset 14 of the packet buffer (every packet trips
# -fsanitize=alignment) and builds addresses as `(uint8_t)byte << 24` (any MAC byte >= 0x80 trips shift-base);
# both are benign on every supported target. Relax only these two checks, only on this file.
$CC $SANITIZER_FLAGS -fno-sanitize=alignment,shift-base $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link $INC \
    -c "$SRC/apps/lb/pkt_hash.c" -o "$FUZZ/pkt_hash.o"
ar rcs "$FUZZ/libnetmap.a" "$FUZZ/nmctx.o" "$FUZZ/nmctx-pthreads.o" "$FUZZ/nmport.o" "$FUZZ/nmreq.o"
$CXX $SANITIZER_FLAGS -c "$M/lsan_off.cc" -o "$FUZZ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ/standalone_main.o"

HFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link $INC"

# libfuzzer_target <name> <extra objects/libs...>: fuzzer binary + non-fuzzer reproducer
libfuzzer_target() {
  local name="$1"; shift
  $CC $HFLAGS $LIB_FUZZING_ENGINE "$M/$name.c" "$@" "$FUZZ/lsan_off.o" $LIBS -o "$SRC/$name"
  $CC $HFLAGS "$M/$name.c" "$FUZZ/standalone_main.o" "$@" "$FUZZ/lsan_off.o" $LIBS -o "$SRC/$name-standalone"
}

libfuzzer_target fuzz_nmport_parse "$FUZZ/libnetmap.a"
libfuzzer_target fuzz_nm_parse
libfuzzer_target fuzz_pkt_hdr_hash "$FUZZ/pkt_hash.o"
# file-input target: one input file per process
$CC $HFLAGS "$M/fuzz_nmreplay_pcap.c" "$FUZZ/libnetmap.a" "$FUZZ/lsan_off.o" $LIBS -o "$SRC/fuzz_nmreplay_pcap"

# 2) known-answer probe with the project's normal flags (test.sh only runs it)
for f in $LIBSRC; do
  $CC -O2 $COVERAGE_FLAGS $INC -c "$SRC/libnetmap/$f.c" -o "$TEST/$f.o"
done
ar rcs "$TEST/libnetmap.a" "$TEST/nmctx.o" "$TEST/nmctx-pthreads.o" "$TEST/nmport.o" "$TEST/nmreq.o"
$CC -O2 $COVERAGE_FLAGS $INC "$M/kat.c" "$TEST/libnetmap.a" $COVERAGE_FLAGS $LIBS -o "$TEST/kat"
