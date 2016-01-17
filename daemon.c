#include "daemon.h"
#include "debug.h"

#include <unistd.h>

#include <stdlib.h>
#include <errno.h>

int mydaemon(const char *name, daemon_fptr_t fptr)
{
	const pid_t pid = fork();

	if (pid < 0)
		return errno;

	if (pid == 0) {
		fclose(stdin);
		fclose(stdout);
		openlog(name, 0, 0);
		redirect_to_syslog(&stderr);

		const pid_t sid = setsid();

		if (sid < 0) {
			ERR("Cannot create a new session (%d)\n", errno);
			exit(1);
		}

		if (chdir("/")) {
			ERR("Cannot change dir to \"/\" (%d)\n", errno);
			exit(1);
		}
		fptr();
		closelog();
		exit(0);
	} else {
		exit(0);
	}

	return 0;
}
