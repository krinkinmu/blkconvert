#include <syslog.h>

#include "debug.h"

static ssize_t syslog_write(void *cookie, const char *buf, size_t size)
{
	(void)cookie;

	syslog(LOG_ERR, "%s", buf);
	return size;
}

static cookie_io_functions_t syslog_fops = {
	.write = syslog_write
};

void redirect_to_syslog(FILE **filep)
{
	if (*filep)
		fclose(*filep);
	*filep = fopencookie(NULL, "w", syslog_fops);
	setvbuf(*filep, NULL, _IOLBF, 0);
}
