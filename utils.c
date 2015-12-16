#include <stdlib.h>

#include "utils.h"

int handle_signal(int sig, void (*handler)(int))
{
	struct sigaction act;

	act.sa_handler = handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	return sigaction(sig, &act, NULL);
}
