#ifndef __BLKQUEUE_H__
#define __BLKQUEUE_H__

#include "object_cache.h"
#include "rbtree.h"

struct blkio {
	struct rb_node rb_node;
	unsigned long long from;
	unsigned long long to;
	unsigned long pid;
	unsigned long cpu;
};

static inline struct blkio *BLKIO(struct rb_node *node)
{
        if (!node)
                return 0;
        return rb_entry(node, struct blkio, rb_node);
}

struct blkio_queue {
	struct object_cache cache;
	struct rb_root rb_root;
};

void blkio_queue_init(struct blkio_queue *q);
void blkio_queue_finit(struct blkio_queue *q);
void blkio_lookup(struct blkio_queue *q, unsigned long long from,
			unsigned long long to,
			struct blkio **first, struct blkio **last);
struct blkio *blkio_insert(struct blkio_queue *q, struct blkio *io);

struct blkio *blkio_alloc(struct blkio_queue *q);
void blkio_free(struct blkio_queue *q, struct blkio *range);
void blkio_erase(struct blkio_queue *q, struct blkio *range);
void blkio_remove(struct blkio_queue *q, struct blkio *range);

#endif /*__BLKQUEUE_H__*/
