#ifndef __BLKIO_QUEUE_H__
#define __BLKIO_QUEUE_H__

#include <stddef.h>

#include "list.h"
#include "rbtree.h"

struct blkio {
	union {
		struct rb_node node;
		struct list_head head;
	} link;
	uint64_t time;
	uint64_t sector;
	uint32_t bytes;
	int write;
};

struct blkio_cache {
	struct list_head head;
};

struct blkio_cache *create_blkio_cache(void);
void destory_blkio_cache(struct blkio_cache *cache);
struct blkio *blkio_cache_alloc(struct blkio_cache *cache);
void blkio_cache_free(struct blkio_cache *cache, struct blkio *io);

struct blkio_queue {
	struct rb_root root;
};

struct blkio_queue *create_blkio_queue(void);
void destory_blkio_queue(struct blkio_queue *queue);
void enqueue_blkio(struct blkio_queue *queue, struct blkio *io);
void dequeue_blkio(struct blkio_queue *queue);
struct blkio *queue_front(struct blkio_queue *queue);
struct blkio *queue_back(struct blkio_queue *queue);

#endif /*__BLKIO_QUEUE_H__*/
