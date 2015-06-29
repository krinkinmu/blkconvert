#include <assert.h>
#include <stdlib.h>

#include "blkioqueue.h"

struct blkio_cache *create_blkio_cache(void)
{
	struct blkio_cache *cache = malloc(sizeof(struct blkio_cache));
	assert(cache && "Cannot allocate blkio cache");
	INIT_LIST_HEAD(&cache->head);
	return cache;
}

void destory_blkio_cache(struct blkio_cache *cache)
{
	while (!list_empty(&cache->head)) {
		struct list_head *first = cache->head.next;
		struct blkio *io = list_entry(first, struct blkio, link.head);
		list_del(first);
		free(io);
	}
	free(cache);
}

struct blkio *blkio_cache_alloc(struct blkio_cache *cache)
{
	struct list_head *first;

	if (list_empty(&cache->head)) {
		struct blkio *io = malloc(sizeof(struct blkio));
		assert(io && "Cannot allocate blkio");
		return io;
	}

	first = list_first(&cache->head);
	list_del(first);
	return list_entry(first, struct blkio, link.head);
}

void blkio_cache_free(struct blkio_cache *cache, struct blkio *io)
{
	struct list_head *head = &cache->head;
	list_add_tail(&io->link.head, head);
}

struct blkio_queue *create_blkio_queue(void)
{
	struct blkio_queue *queue = malloc(sizeof(struct blkio_queue));
	assert(queue && "Cannot allocate blkio queue");
	queue->root.rb_node = NULL;
	return queue;
}

static void dispose_rb_tree(struct rb_node *node)
{
	if (!node)
		return;

	while (node) {
		struct rb_node *tmp = node;
		dispose_rb_tree(node->rb_right);
		node = node->rb_left;
		free(tmp);
	}
}

void destory_blkio_queue(struct blkio_queue *queue)
{
	dispose_rb_tree(queue->root.rb_node);
	free(queue);
}

void enqueue_blkio(struct blkio_queue *queue, struct blkio *new)
{
	const uint64_t time = new->time;
	struct rb_node **p = &queue->root.rb_node;
	struct rb_node *parent = NULL;
	struct blkio *io;

	while (*p) {
		parent = *p;
		io = rb_entry(parent, struct blkio, link.node);

		if (time < io->time)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}
	rb_link_node(&new->link.node, parent, p);
	rb_insert_color(&new->link.node, &queue->root);
}

void dequeue_blkio(struct blkio_queue *queue)
{
	struct blkio *io = queue_front(queue);

	if (io)
		rb_erase(&io->link.node, &queue->root);
}

struct blkio *queue_front(struct blkio_queue *queue)
{
	struct rb_node *first = rb_first(&queue->root);

	if (!first)
		return NULL;

	return rb_entry(first, struct blkio, link.node);
}

struct blkio *queue_back(struct blkio_queue *queue)
{
	struct rb_node *last = rb_last(&queue->root);

	if (!last)
		return NULL;

	return rb_entry(last, struct blkio, link.node);
}
