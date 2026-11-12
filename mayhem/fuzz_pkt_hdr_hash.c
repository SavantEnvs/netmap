/* apps/lb pkt_hdr_hash(): Ethernet/VLAN/IPv4/IPv6/GRE header walker used by the netmap load balancer. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pkt_hash.h"

/* pkt_hdr_hash() takes no length: lb.c passes a netmap buffer, whose default size is 2048 bytes
 * (the "netmap_buf" pool, `.size = 2048` in sys/dev/netmap/netmap_mem2.c; configurable up to 64 KiB). */
#define NM_BUF_SIZE 2048

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *buf;
	uint8_t hash_split, seed;

	if (size < 2)
		return -1;
	hash_split = data[0];
	seed = data[1];
	data += 2;
	size -= 2;
	buf = calloc(1, NM_BUF_SIZE);
	if (buf == NULL)
		return -1;
	memcpy(buf, data, size < NM_BUF_SIZE ? size : NM_BUF_SIZE);
	(void)pkt_hdr_hash(buf, hash_split, seed);
	free(buf);
	return 0;
}
