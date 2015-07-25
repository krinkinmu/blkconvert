#include <stdlib.h>

#include "object_cache.h"
#include "common.h"
#include "stack.h"
#include "debug.h"

struct object_cache {
	struct stack_head *head;
	size_t object_size;
};

struct object_cache *object_cache_create(size_t object_size)
{
	struct object_cache *cache = malloc(sizeof(struct object_cache));

	if (!cache) {
		ERR("Cannot allocate object cache\n");
		return 0;
	}

	cache->object_size = MAX(object_size, sizeof(struct stack_head));
	cache->head = 0;
	return cache;
}

void object_cache_destroy(struct object_cache *cache)
{
	while (!stack_empty(cache->head)) {
		struct stack_head *head = stack_pop(&cache->head);
		free(head);
	}
	free(cache);
}

void *object_cache_alloc(struct object_cache *cache)
{
	if (!stack_empty(cache->head))
		return (void *)stack_pop(&cache->head);
	return malloc(cache->object_size);
}

void object_cache_free(struct object_cache *cache, void *object)
{
	stack_push(&cache->head, object);
}
