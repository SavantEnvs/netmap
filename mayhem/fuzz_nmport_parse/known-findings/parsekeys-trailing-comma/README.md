# nmreq_option_parsekeys: trailing `,` makes the next "key" start at the terminator

**Reproducer:** `reproducer` = `netmap:eth0@conf:tx_rings=1,` (option list ending in a comma).
`/mayhem/fuzz_nmport_parse-standalone reproducer` -> ASan heap-buffer-overflow READ at `libnetmap/nmreq.c:425` (Mayhem defect #3605594, CWE-125).

**Cause:** after the value `1` ends at the `,`, `delim1 = ','` keeps the `while (delim1 != '\0')` loop going while `scan` already
points at the string's NUL. `key = scan; for (scan++; ...)` (nmreq.c:425) then skips that NUL and scans the bytes after the
allocation; the following `*scan = '\0'` stores a zero byte there.

**Impact:** same class as `parsekeys-key-without-value`: one-byte-and-longer heap over-read and a NUL store past the end of the
caller's spec string, from any spec ending in `,`.

**One-line upstream fix:** stop at the terminator at the top of the loop: `if (*scan == '\0') break;` (or reject the empty key)
before `key = scan;` in `nmreq_option_parsekeys()`.
