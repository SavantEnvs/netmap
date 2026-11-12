The `fuzz_nmreplay_cfg` target was dropped: Mayhem's start-up probe (event 393863, "libFuzzer target failed to fuzz for 5 iterations")
fails because a separator-only option crashes `cmd_apply()` (`nmreplay.c:1615`) within 5 iterations, and the harness may not filter it.
These records are what that target found (8 defects in run 3, three root causes); each reproducer is also the equivalent `nmreplay`
command line given in its README, which reaches the same code through `cmd_apply()`:
`separator-only-option/` (`const_delay_parse:1494`, `const_bw_parse:1615`, `const_plr_parse:1716`), `parse_gen-null-conv/` (`nmreplay.c:1311`, 3 defects)
and `parse_bw-negative-to-uint64/` (`parse_bw:1356`, `parse_time:1341`).
The `/mayhem/fuzz_nmreplay_cfg-standalone` binary named in the READMEs no longer ships.
