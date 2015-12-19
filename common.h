#ifndef __COMMON_H__
#define __COMMON_H__

#include <stddef.h>
#include <stdint.h>

#define MIN_CONST(a, b) ((a) < (b) ? (a) : (b))
#define MAX_CONST(a, b) ((a) > (b) ? (a) : (b))

static inline intmax_t __min(intmax_t l, intmax_t r)
{ return MIN_CONST(l, r); }

static inline uintmax_t __minu(uintmax_t l, uintmax_t r)
{ return MIN_CONST(l, r); }

static inline intmax_t __max(intmax_t l, intmax_t r)
{ return MAX_CONST(l, r); }

static inline uintmax_t __maxu(uintmax_t l, uintmax_t r)
{ return MAX_CONST(l, r); }

#undef MIN
#undef MAX

#define MIN(a, b)  __min(a, b)
#define MINU(a, b) __minu(a, b)
#define MAX(a, b)  __max(a, b)
#define MAXU(a, b) __maxu(a, b)

#define container_of(ptr, type, member) \
	((type *)(((char *)(ptr)) - offsetof(type, member)))

#endif /*__COMMON_H__*/
