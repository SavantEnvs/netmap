/* Known-answer probe for mayhem/test.sh: runs netmap's own parsers on fixed inputs and prints what they
 * return. Built with the project's normal flags and linked against the normal libnetmap build. */
#define _GNU_SOURCE
#define NETMAP_WITH_LIBS
#define LIBNETMAP_NOTHREADSAFE
#include <arpa/inet.h>
#include <net/netmap_user.h>
#define main nmreplay_unused_main
#include "../apps/nmreplay/nmreplay.c"
#undef main
#include "../apps/lb/pkt_hash.c"

static void port(const char *spec)
{
	struct nmport_d *d = nmport_prepare(spec);

	if (d == NULL) {
		printf("port %s -> error\n", spec);
		return;
	}
	printf("port %s -> name=%s mode=%u ringid=%u flags=0x%llx memid=%u txr=%u rxr=%u txs=%u rxs=%u\n", spec,
	    d->hdr.nr_name, (unsigned)d->reg.nr_mode, (unsigned)d->reg.nr_ringid,
	    (unsigned long long)d->reg.nr_flags, (unsigned)d->reg.nr_mem_id,
	    (unsigned)d->reg.nr_tx_rings, (unsigned)d->reg.nr_rx_rings,
	    (unsigned)d->reg.nr_tx_slots, (unsigned)d->reg.nr_rx_slots);
	nmport_undo_prepare(d);
}

static void nmparse(const char *name)
{
	struct nm_desc d;
	char err[MAXERRMSG] = "";
	int rc;

	memset(&d, 0, sizeof(d));
	rc = nm_parse(name, &d, err);
	if (rc < 0)
		printf("nm_parse %s -> error '%s'\n", name, err);
	else
		printf("nm_parse %s -> name=%s ringid=%u flags=0x%x arg2=%u\n", name, d.req.nr_name,
		    (unsigned)d.req.nr_ringid, (unsigned)d.req.nr_flags, (unsigned)d.req.nr_arg2);
}

static void packet(uint8_t *p, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{
	memset(p, 0, 2048);
	memcpy(p, "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00", 14);
	p[14] = 0x45;
	p[17] = 40;
	p[22] = 64;
	p[23] = 6;
	memcpy(p + 26, &sip, 4);
	memcpy(p + 30, &dip, 4);
	p[34] = sport >> 8;
	p[35] = sport & 0xff;
	p[36] = dport >> 8;
	p[37] = dport & 0xff;
}

static void hashes(void)
{
	uint8_t a[2048], b[2048];
	uint32_t ip1 = htonl(0x0a000001), ip2 = htonl(0x0a000002);
	int split;

	packet(a, ip1, ip2, 1234, 80);
	packet(b, ip2, ip1, 80, 1234);
	for (split = 0; split < 3; split++)
		printf("hash split=%d seed=0 fwd=%08x rev=%08x\n", split, pkt_hdr_hash(a, split, 0),
		    pkt_hdr_hash(b, split, 0));
}

static void pcap(void)
{
	char path[256];
	const char *tmp = getenv("TMPDIR");
	/* little-endian classic pcap: global header, then two records (caplen 4, len 60 / caplen 4, len 100) */
	static const unsigned char file[] = {
		0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
		1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 60, 0, 0, 0, 'a', 'b', 'c', 'd',
		3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 100, 0, 0, 0, 'e', 'f', 'g', 'h',
	};
	struct nm_pcap_file *pf;
	FILE *f;

	snprintf(path, sizeof(path), "%s/kat-%d.pcap", tmp ? tmp : "/tmp", (int)getpid());
	f = fopen(path, "w");
	if (f == NULL || fwrite(file, 1, sizeof(file), f) != sizeof(file)) {
		printf("pcap -> cannot write fixture\n");
		return;
	}
	fclose(f);
	pf = readpcap(path);
	unlink(path);
	if (pf == NULL) {
		printf("pcap -> error\n");
		return;
	}
	printf("pcap -> pkts=%llu bytes=%llu res=%u swap=%d tx_time=%llu\n",
	    (unsigned long long)pf->tot_pkt, (unsigned long long)pf->tot_bytes, pf->resolution, pf->swap,
	    (unsigned long long)pf->total_tx_time);
	destroy_pcap(pf);
}

static void cfg(const char *kind, const struct _cfg *table, const char *arg)
{
	int ac = 0, i;
	char **av = split_arg(arg, &ac);

	for (i = 0; av != NULL && table[i].parse; i++) {
		struct _cfg x = table[i];
		struct _qs q;
		int ret;

		memset(&q, 0, sizeof(q));
		x.arg = NULL;
		x.arg_len = 0;
		bzero(&x.d, sizeof(x.d));
		ret = x.parse(&q, &x, ac, av);
		if (ret == 2)
			continue;
		if (ret == 1) {
			printf("%s '%s' -> error\n", kind, arg);
		} else {
			q.cur_len = 1500;
			q.cur_tt = 7;
			printf("%s '%s' -> d0=%llu d1=%llu d2=%llu f0=%g arglen=%d", kind, arg,
			    (unsigned long long)x.d[0], (unsigned long long)x.d[1],
			    (unsigned long long)x.d[2], x.f[0], x.arg_len);
			if (x.arg != NULL)
				printf(" t0=%llu t511=%llu", (unsigned long long)((uint64_t *)x.arg)[0],
				    (unsigned long long)((uint64_t *)x.arg)[511]);
			if (x.run == const_bw_run || x.run == ether_bw_run || x.run == real_bw_run) {
				x.run(&q, &x);
				printf(" tt=%llu", (unsigned long long)q.cur_tt);
			}
			printf("\n");
			free(x.arg);
		}
		free(av);
		return;
	}
	printf("%s '%s' -> not recognised\n", kind, arg);
	free(av);
}

int main(void)
{
	port("netmap:eth0");
	port("netmap:eth0-3/x");
	port("netmap:eth0*");
	port("netmap:eth0^");
	port("netmap:eth0/R");
	port("vale0:p1");
	port("vale0:p1{5");
	port("netmap:eth0@conf:rings=2,slots=1024");
	port("netmap:eth0@conf:tx_rings=3,rx_slots=64");
	port("netmap:eth0-");
	port("netmap:eth0/q");
	nmparse("netmap:em0");
	nmparse("netmap:em0-2/x");
	nmparse("netmap:em0^/xR@7");
	nmparse("vale0:p1");
	nmparse("vale0:p1}3");
	nmparse("netmap:em0@0");
	nmparse("netmap:em0*z");
	hashes();
	pcap();
	cfg("delay", delay_cfg, "const,100m");
	cfg("delay", delay_cfg, "5u");
	cfg("delay", delay_cfg, "uniform,1u,2m");
	cfg("delay", delay_cfg, "uniform,2m,1u");
	cfg("delay", delay_cfg, "exp,5m,1m");
	cfg("bw", bw_cfg, "const,10m");
	cfg("bw", bw_cfg, "ether,10g");
	cfg("bw", bw_cfg, "real,2");
	cfg("loss", loss_cfg, "0.25");
	cfg("loss", loss_cfg, "ber,1e-6");
	return 0;
}
