/* libnetmap port-spec parser: header ("netmap:"/"vale<id>:" + name), register modifiers, @option list. */
#define LIBNETMAP_NOTHREADSAFE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <net/netmap_user.h>
#include <libnetmap.h>

static void quiet_error(struct nmctx *ctx, const char *msg)
{
	(void)ctx;
	(void)msg;
}

/* Process-wide settings, fixed for the whole run: silence the library's stderr output, keep the
 * "extmem" option (which opens and mmaps a path taken from the input) off, and turn the
 * default-disabled "offset" option on so its parser is reachable. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	static struct nmctx quiet;

	(void)argc;
	(void)argv;
	quiet = *nmctx_get();
	quiet.error = quiet_error;
	nmctx_set_default(&quiet);
	nmport_disable_option("extmem");
	nmport_enable_option("offset");
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct nmport_d *d;
	char *spec = malloc(size + 1);

	if (spec == NULL)
		return -1;
	memcpy(spec, data, size);
	spec[size] = '\0';
	d = nmport_prepare(spec);
	if (d != NULL)
		nmport_undo_prepare(d);
	free(spec);
	return 0;
}
