# nmreplay: parse_bw()/parse_time() cast a negative or huge double to uint64_t

**Reproducer:** `reproducer` = `s,-6` (harness family 1 = bandwidth, argument `-6`), i.e. `nmreplay -B -6`.
`/mayhem/fuzz_nmreplay_cfg-standalone reproducer` -> UBSan "-6 is outside the range of representable values of type 'unsigned long'" at `apps/nmreplay/nmreplay.c:1356` (Mayhem defect #3605909).
Values such as `6e67` (any double above 2^64) trip the same check; `parse_time()` has the same cast at line 1341.

**Cause:** `(uint64_t)parse_gen(...)` converts an out-of-range `double` to an unsigned integer, which is undefined behaviour in C
(`strtod` accepts a sign and exponents).

**Impact:** on x86-64 the result is an arbitrary 64-bit value, so `-B -6` silently configures a wrong (huge or zero) bandwidth;
no memory corruption.

**One-line upstream fix:** reject out-of-range values before the cast: `if (d < 0 || d >= 18446744073709551616.0) goto error;` in `parse_gen()` (or in `parse_bw`/`parse_time`).
