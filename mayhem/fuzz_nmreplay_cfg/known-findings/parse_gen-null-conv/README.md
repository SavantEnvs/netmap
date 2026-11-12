# nmreplay: parse_gen() dereferences a NULL `conv` when the number has a unit suffix

**Reproducer:** `reproducer` = `t,100m` (harness family 2 = loss, argument `,100m` -> `plr` parser gets `100m`).
`/mayhem/fuzz_nmreplay_cfg-standalone reproducer` -> UBSan member access within null pointer at `apps/nmreplay/nmreplay.c:1311` (Mayhem defects #3605903, #3605908, #3605941).
Equivalent CLI: `nmreplay -L plr,100m`.

**Cause:** the loss parsers call `parse_gen(arg, NULL, &err)` ("no conversion table"). The special case only handles `conv == NULL && *ep == '\0'`;
with any trailing character (`100m`, `2x`) control falls into `for (; conv->s; conv++)` with `conv == NULL`.

**Impact:** NULL dereference (crash) from a user-supplied `-L`/`-D`/`-B` value with a suffix after the number.

**One-line upstream fix:** `for (; conv && conv->s; conv++)` in `parse_gen()` (the loop then falls through to the existing `error:` label).
