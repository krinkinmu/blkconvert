#ifndef __OBJECT_CACHE_H__
#define __OBJECT_CACHE_H__

#include <stddef.h>

struct object_cache;

struct object_cache *object_cache_create(size_t object_size);
void object_cache_destroy(struct object_cache *cache);
void *object_cache_alloc(struct object_cache *cache);
void object_cache_free(struct object_cache *cache, void *object);

#endif /*__OBJECT_CACHE_H__*/
