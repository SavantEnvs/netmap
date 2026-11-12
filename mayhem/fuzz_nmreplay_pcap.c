/* nmreplay trace loader: readpcap() mmaps a pcap file and walks its records. File-input target. */
#define main nmreplay_unused_main
#include "../apps/nmreplay/nmreplay.c"
#undef main

int main(int argc, char **argv)
{
	struct nm_pcap_file *pf;

	if (argc < 2)
		return 2;
	pf = readpcap(argv[1]);
	destroy_pcap(pf);
	return 0;
}
