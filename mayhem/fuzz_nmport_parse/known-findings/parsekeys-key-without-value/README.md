# nmreq_option_parsekeys: key without `=value` at the end of the spec reads (and writes) past the string

**Reproducer:** `reproducer` = `netmap:eth0@conf:host_tx_rings` (no `=` after the last key).
`/mayhem/fuzz_nmport_parse-standalone reproducer` -> ASan heap-buffer-overflow READ at `libnetmap/nmreq.c:449` (Mayhem defect #3605595, CWE-125).

**Cause:** when the last key has no `=` (and no trailing `,`), `delim == '\0'` and `*scan = '\0'; scan++` (nmreq.c:431) steps
one byte past the string's terminator. `value = scan` then starts at that out-of-bounds byte; the value loop (nmreq.c:449) reads
until the next `,`/NUL and the following `*scan = '\0'` stores a zero byte at that position.

**Impact:** a 1-byte-and-longer heap over-read of the caller's port-spec string, followed by a one-byte NUL store at the same
out-of-bounds address (ASan stops at the read). Reachable from `nmport_open()`/`nmport_prepare()` with any spec that ends in a
bare option key. Not remotely reachable in the stock tools; it is a library-API robustness bug.

**One-line upstream fix:** do not advance past the terminator: `scan += (delim != '\0');` instead of the unconditional `scan++`
(libnetmap/nmreq.c, after `*scan = '\0';` in the key branch).
