#include <stdlib.h>

#include "object_cache.h"
#include "common.h"
#include "debug.h"
#include "list.h"

struct object_cache {
	struct list_head head;
	size_t object_size;
};

struct object_cache *object_cache_create(size_t object_size)
{
	struct object_cache *cache = malloc(sizeof(struct object_cache));

	if (!cache) {
		ERR("Cannot allocate object cache\n");
		return 0;
	}

	cache->object_size = MAX(object_size, sizeof(struct list_head));
	list_init(&cache->head);
	return cache;
}

void object_cache_destroy(struct object_cache *cache)
{
	while (!list_empty(&cache->head)) {
		struct list_head *head = cache->head.next;

		list_unlink(head);
		free(head);
	}
	free(cache);
}

void *object_cache_alloc(struct object_cache *cache)
{
	if (!list_empty(&cache->head)) {
		struct list_head *head = cache->head.next;

		list_unlink(head);
		return (void *)head;
	}
	return malloc(cache->object_size);
}

void object_cache_free(struct object_cache *cache, void *object)
{ list_link_after(&cache->head, object); }
