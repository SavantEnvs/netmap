# lb pkt_hdr_hash(): the header walker follows nested encapsulation past the end of the packet buffer

All 9 Mayhem defects of this target at run 4 (CWE-125, `apps/lb/pkt_hash.c`: `decode_gre_hash` 373 and 377, `decode_ip_n_hash` 152 at column 11 and at column 42, `pkt_hdr_hash` 343, `decode_ipv6_n_hash` 217, 218, 221 and 222) are ONE root cause.

**Reproducers**
- `ipip-chain` (hand-made): `hash_split=4, seed=0` followed by a 2048-byte buffer holding an Ethernet header (type IPv4) and then
  IPv4 headers (`ihl=5, ip_len=20, proto=IPIP`) back to back. `/mayhem/fuzz_pkt_hdr_hash-standalone ipip-chain` -> heap-buffer-overflow READ at `pkt_hash.c:152` (`decode_ip_n_hash`).
- `mayhem-<site>`: one Mayhem crasher per distinct first frame, `gre373`, `gre377`, `ip152` (column 11, the `ip_hl` byte), `ip152-col42`
  (column 42, the `ip_len` read inside `ntohs()`), `eth343`, `ipv6-217`, `ipv6-218`, `ipv6-221`, `ipv6-222`.
  Each reproduces its own site with the same `-standalone` binary. In `mayhem-ipv6-222` and `mayhem-ip152-col42` the faulting address is
  exactly buffer offset 2048 (one past the end).

**Cause:** `pkt_hdr_hash(buffer, hash_split, seed)` takes no length and never checks one. `decode_ip_n_hash` (IPIP, header length from
`ip_hl`), `decode_gre_hash` and `decode_ipv6_n_hash` recurse into the next header at an attacker-controlled offset; GRE protocol
`0x6558` calls `pkt_hdr_hash()` again, so each hop re-enters the Ethernet decoder. A chain of about 50-165 hops (traced for all 31 crashers
Mayhem saved at run 4: the last header that starts inside the buffer starts at offset 2014..2046, so its fields or the next header
cross offset 2048) reaches the end of the buffer, and whichever field is read first across the boundary gives a different first
frame. The 9 defects (8 distinct lines, `:152` at two columns) are the same bug seen at different field reads, not nine bugs.
`ipv6-222` is the `ip6_dst.s6_addr[2] << 16` read: its chain is 23 Ethernet, 38 IPv6 and 37 GRE(0x6558) headers (98 hops, the
same shape as `ipv6-218`), the last IPv6 header starts at offset 2022, so its `dst[2]` is byte 2048.

**Buffer size:** the harness uses 2048 bytes because that is netmap's default buffer size: `nm_mem.params[NETMAP_BUF_POOL].size = 2048`
(`sys/dev/netmap/netmap_mem2.c:572`, minimum private pool also 2048 at line 525), and `lb.c:1026` calls
`pkt_hdr_hash(NETMAP_BUF(...), 4, 'B')` on such a buffer without passing `rs->len`. The pool size is a sysctl (`objmaxsize` 65536),
so a larger configured `buf_size` moves the boundary but does not remove the bug.

**Impact:** read of a few bytes beyond a netmap buffer (the neighbouring buffer in the pool) while hashing a crafted packet
of ~2 KB; the value only feeds the load-balancer hash. Information disclosure of at most a few bytes, no write.

**One-line upstream fix:** give the walker a limit: pass `rs->len` (or `const uint8_t *end`) into `pkt_hdr_hash()` and return 0 when a
header would extend past it.
