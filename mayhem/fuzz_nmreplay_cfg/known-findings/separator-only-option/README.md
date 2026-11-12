# nmreplay: an option made only of separators (`-D ' '`, `-B ' '`, `-L ' '`) reaches the parsers with `ac == 0`

**Reproducer:** `reproducer` = bytes `01 20` (harness family 1 = bandwidth, argument `" "`), the same as `nmreplay -B ' '`.
`/mayhem/fuzz_nmreplay_cfg-standalone reproducer` -> UBSan null pointer passed to `strncmp` at `apps/nmreplay/nmreplay.c:1615` (`const_bw_parse`).
Libfuzzer's default one-byte `\n` seed turns into this shape (`\n\n`) by itself within a few runs without a corpus.
The harness does NOT filter this shape; it is a real finding in the target.

**Cause:** `cmd_apply()` (nmreplay.c:1036) calls `split_arg()` and passes `(ac, av)` straight to every `parse` callback. For an argument that
contains only separators `ac == 0` and `av[0] == NULL`, and every callback starts with `strcmp/strncmp(av[0], ...)`.

**Impact:** NULL dereference (crash) at start-up of the `nmreplay` CLI with `-D`, `-B` or `-L` set to a blank string.

**One-line upstream fix:** in `cmd_apply()`, after `split_arg()`: `if (av == NULL || ac == 0) { free(av); return 1; }`.
