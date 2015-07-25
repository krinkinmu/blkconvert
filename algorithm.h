#ifndef __ALGORITHM_H__
#define __ALGORITHM_H__

#include <stdlib.h>
#include <stddef.h>

typedef int (*comparison_fn_t)(const void *, const void *);
typedef int (*filter_fn_t)(const void *);

size_t __lower_bound(char *ptr, size_t count, size_t size, const char *key,
			comparison_fn_t cmp);

size_t __remove_if(char *ptr, size_t count, size_t size, filter_fn_t);

#define sort(ptr, count, cmp) \
	qsort((void *)ptr, count, sizeof(*ptr), (comparison_fn_t)cmp)

#define lower_bound(ptr, count, key, cmp) \
	__lower_bound((char *)ptr, count, sizeof(*ptr), (char *)&key, \
				(comparison_fn_t)cmp)

#define remove_if(ptr, count, filter) \
	__remove_if((char *)ptr, count, sizeof(*ptr), (filter_fn_t)filter)

#endif /*__ALGORITHM_H__*/
