#include <stdlib.h>

#include "object_cache.h"
#include "common.h"
#include "debug.h"

void object_cache_init(struct object_cache *cache, size_t object_size)
{
	cache->object_size = MAX(object_size, sizeof(struct list_head));
	list_head_init(&cache->head);
}

struct object_cache *object_cache_create(size_t object_size)
{
	struct object_cache *cache = malloc(sizeof(struct object_cache));

	if (!cache) {
		ERR("Cannot allocate object cache\n");
		return 0;
	}

	object_cache_init(cache, object_size);
	return cache;
}

void object_cache_finit(struct object_cache *cache)
{
	struct list_head *head = &cache->head;

	for (struct list_head *ptr = head->next; ptr != head;) {
		struct list_head *tmp = ptr;

		ptr = ptr->next;
		free(tmp);
	}
}

void object_cache_destroy(struct object_cache *cache)
{
	object_cache_finit(cache);
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
