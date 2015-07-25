#ifndef __COMMON_H__
#define __COMMON_H__

#include <stddef.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define container_of(ptr, type, member) \
	((type *)(((char *)(ptr)) - offsetof(type, member)))

#endif /*__COMMON_H__*/
