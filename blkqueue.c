#include "blkqueue.h"
#include "debug.h"

#include <string.h>

void blkio_queue_init(struct blkio_queue *q)
{
	memset(q, 0, sizeof(*q));
	object_cache_init(&q->cache, sizeof(struct blkio));
}

static void blkio_tree_release(struct object_cache *cache, struct rb_node *node)
{
	while (node) {
		struct blkio *tmp = (struct blkio *)node;

		blkio_tree_release(cache, node->rb_right);
		node = node->rb_left;
		object_cache_free(cache, tmp);
	}
}

void blkio_queue_finit(struct blkio_queue *q)
{
	blkio_tree_release(&q->cache, q->rb_root.rb_node);
	object_cache_finit(&q->cache);
	memset(q, 0, sizeof(*q));
}

static struct blkio *blkio_left_lookup(struct rb_node *root,
			unsigned long long from)
{
	struct blkio *first = 0;

	while (root) {
		struct blkio *range = BLKIO(root);

		if (range->to > from) {
			first = range;
			root = root->rb_left;
		} else
			root = root->rb_right;
	}
	return first;
}

static struct blkio *blkio_right_lookup(struct rb_node *root,
			unsigned long long to)
{
	struct blkio *last = 0;

	while (root) {
		struct blkio *range = BLKIO(root);

		if (range->from < to)
			root = root->rb_right;
		else {
			last = range;
			root = root->rb_left;
		}
	}
	return last;
}

void blkio_lookup(struct blkio_queue *q, unsigned long long from,
			unsigned long long to,
			struct blkio **first, struct blkio **last)
{
	struct rb_node *p = q->rb_root.rb_node;

	*first = blkio_left_lookup(p, from);
	*last = blkio_right_lookup(p, to);
}

struct blkio *blkio_alloc(struct blkio_queue *q)
{
	struct blkio *range = object_cache_alloc(&q->cache);

	if (!range) {
		ERR("blkio_alloc failed\n");
		return 0;
	}

	memset(&range->rb_node, 0, sizeof(range->rb_node));
	return range;
}

void blkio_free(struct blkio_queue *q, struct blkio *range)
{ object_cache_free(&q->cache, range); }

struct blkio *blkio_insert(struct blkio_queue *q, struct blkio *io)
{
	struct rb_node **p = &q->rb_root.rb_node;
	struct rb_node *parent = 0;

	while (*p) {
		struct blkio *range = BLKIO(*p);
		const unsigned long long b = range->from;
		const unsigned long long e = range->to;

		parent = *p;
		if (b >= io->to)
			p = &parent->rb_left;
		else if (e <= io->from)
			p = &parent->rb_right;
		else
			return range;
	}

	rb_link_node(&io->rb_node, parent, p);
	rb_insert_color(&io->rb_node, &q->rb_root);
	return 0;
}

void blkio_erase(struct blkio_queue *q, struct blkio *range)
{ rb_erase(&range->rb_node, &q->rb_root); }

void blkio_remove(struct blkio_queue *q, struct blkio *range)
{
	blkio_erase(q, range);
	blkio_free(q, range);
}
