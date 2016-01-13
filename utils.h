#ifndef __UTILS_H__
#define __UTILS_H__

#include <signal.h>

int handle_signal(int signum, void (*handler)(int));

#endif /*__UTILS_H__*/
