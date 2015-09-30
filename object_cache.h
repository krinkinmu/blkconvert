#ifndef __OBJECT_CACHE_H__
#define __OBJECT_CACHE_H__

#include <stddef.h>
#include "list.h"

struct object_cache {
	struct list_head head;
	size_t object_size;
};

void object_cache_init(struct object_cache *cache, size_t object_size);
struct object_cache *object_cache_create(size_t object_size);
void object_cache_finit(struct object_cache *cache);
void object_cache_destroy(struct object_cache *cache);
void *object_cache_alloc(struct object_cache *cache);
void object_cache_free(struct object_cache *cache, void *object);

#endif /*__OBJECT_CACHE_H__*/
