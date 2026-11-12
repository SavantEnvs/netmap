/* nm_parse() from sys/net/netmap_user.h: the port-name parser behind nm_open(). */
#define NETMAP_WITH_LIBS
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <net/netmap_user.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct nm_desc d;
	char err[MAXERRMSG];
	char *name = malloc(size + 1);

	if (name == NULL)
		return -1;
	memcpy(name, data, size);
	name[size] = '\0';
	/* nm_open() only calls nm_parse() for names with one of these prefixes
	 * (a name without them returns NULL with errno = 0, "not recognised"). */
	if (strncmp(name, "netmap:", 7) && strncmp(name, NM_BDG_NAME, strlen(NM_BDG_NAME))) {
		free(name);
		return -1;
	}
	memset(&d, 0, sizeof(d));
	memset(err, 0, sizeof(err));
	nm_parse(name, &d, err);
	free(name);
	return 0;
}
