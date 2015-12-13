#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <syslog.h>
#include <stdio.h>

#define ERR(...) fprintf(stderr, __VA_ARGS__)

void redirect_to_syslog(FILE **filep);

#endif /*__DEBUG_H__*/
