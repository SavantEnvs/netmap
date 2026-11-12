# nmreplay: pad() overflows `int` on an attacker-controlled pcap record length

**Reproducer:** `reproducer.pcap` (78 bytes): a pcap file whose first record header has wire length `0x7fffffe0`.
`/mayhem/fuzz_nmreplay_pcap reproducer.pcap` -> UBSan "signed integer overflow: 2147483616 + 32 cannot be represented in type 'int'" at `apps/nmreplay/nmreplay.c:220` (Mayhem defect #3605613).

**Cause:** `readpcap()` reads the 32-bit `len` field of each record from the file and calls `pad(len)` (nmreplay.c:402), which is
`static inline int pad(int x) { return (x + PKT_PAD - 1) & ~(PKT_PAD - 1); }`; `len` above `INT_MAX - 31` overflows the signed `int`.

**Impact:** signed-overflow UB on a value read from the trace file. In practice the wrapped result corrupts `tot_bytes_rounded`,
which sizes the replay queue (`need = loops * pf->tot_bytes_rounded`, nmreplay.c:761).

**One-line upstream fix:** make the helper unsigned: `static inline uint32_t pad(uint32_t x)` (nmreplay.c:218) and keep `tot_bytes_rounded` 64-bit.
