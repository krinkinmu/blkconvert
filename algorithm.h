#ifndef __ALGORITHM_H__
#define __ALGORITHM_H__

#include <stdlib.h>
#include <stddef.h>

typedef int (*comparison_fn_t)(const void *, const void *);

size_t __lower_bound(char *ptr, size_t count, size_t size, const char *key,
			comparison_fn_t cmp);

#define sort(ptr, count, cmp) \
	qsort((void *)ptr, count, sizeof(*ptr), (comparison_fn_t)cmp)

#define lower_bound(ptr, count, key, cmp) \
	__lower_bound((char *)ptr, count, sizeof(*ptr), (char *)&key, \
				(comparison_fn_t)cmp)

#endif /*__ALGORITHM_H__*/
