#include <stddef.h>
#include "algorithm.h"

size_t __lower_bound(char *ptr, size_t count, size_t size, const char *key,
			comparison_fn_t cmp)
{
	char *begin = ptr;
	size_t len = count;

	while (len) {
		const size_t half = len / 2;
		char * const m = ptr + half * size;

		if (cmp(m, key) < 0) {
			ptr = m + size;
			len = len - half - 1;
		} else {
			len = half;
		}
	}
	return (ptr - begin) / size;
}
