#include <assert.h>

#include "algorithm.h"
#include "generator.h"
#include "debug.h"
#include "ctree.h"

struct bio_ctree {
	struct ctree link;
	struct bio *first;
	struct bio *last;
};

#define RANDOM_SHUFFLE(array, size, type) \
	do { \
		const size_t __size = (size); \
		type *__array = (array); \
		size_t __i; \
		if (__size < 2) \
			break; \
		for (__i = 0; __i != __size - 1; ++__i) { \
			const size_t pos = myrandom(__i, __size); \
			const type tmp = __array[pos]; \
			__array[pos] = __array[__i]; \
			__array[__i] = tmp; \
		} \
	} while (0)

static unsigned long myrandom(unsigned long from, unsigned long to)
{
	const unsigned long bits = 15;
	const unsigned long mask = (1ul << bits) - 1;

	unsigned long value = 0;

	for (unsigned gen = 0; gen < sizeof(value) * 8; gen += bits)
		value |= ((unsigned long)rand() & mask) << gen;
	return value % (to - from) + from;
}

static int bio_offset_cmp(const struct bio *l, const struct bio *r)
{
	if (l->offset < r->offset)
		return -1;
	if (l->offset > r->offset)
		return 1;
	return 0;
}

static int bio_ctree_offset_cmp(const struct bio_ctree *l,
			const struct bio_ctree *r)
{ return bio_offset_cmp(l->first, r->first); }

static void bio_ctree_sort_by_offset(struct bio_ctree *bios, size_t size)
{ sort(bios, size, &bio_ctree_offset_cmp); }

static void bio_ctree_node_init(struct bio_ctree *node, struct bio *bio)
{
	cinit(&node->link);
	node->first = node->last = bio;
}

static void bio_ctree_append(struct ctree **tree, struct bio_ctree *node)
{ *tree = cappend(*tree, &node->link); }

static struct bio_ctree *bio_ctree_extract(struct ctree **tree, size_t idx)
{
	struct ctree *node;

	assert(idx < csize(*tree) && "Tree is to small");
	*tree = cextract(*tree, idx, &node);
	assert(node && "Node must not be NULL");
	return centry(node, struct bio_ctree, link);
}

static size_t __bio_runs_fill(struct bio *bios, size_t size,
			struct bio_ctree *nodes, size_t max_len)
{
	bio_ctree_node_init(nodes, bios);

	size_t count = 1;

	for (size_t i = 1, len = 1; i != size; ++i) {
		const unsigned long long poff = bios[i - 1].offset;
		const unsigned long plen = bios[i - 1].bytes;
		const unsigned long long off = bios[i].offset;

		if (poff + plen == off && len < max_len) {
			nodes[count - 1].last = bios + i;
			++len;
		} else {
			bio_ctree_node_init(nodes + count++, bios + i);
			len = 1;
		}
	}

	return count;
}

static size_t bio_runs_fill(struct bio *bios, size_t size,
			struct bio_ctree *nodes,
			const struct blkio_disk_layout *layout)
{
	const size_t max_len = layout->max_len;
	const size_t seq = layout->seq;

	if (!seq)
		return 0;

	size_t l = 1;
	size_t r = max_len;

	while (l < r) {
		const size_t m = l + (r - l) / 2;
		const size_t count = __bio_runs_fill(bios, size, nodes, m);

		if (count > seq) l = m + 1;
		else r = m;
	}

	return __bio_runs_fill(bios, size, nodes, l);
}

static unsigned long long max_invs(unsigned long items)
{ return items * (items - 1) / 2; }

static int bio_fill_flags(struct bio *bios, unsigned long flags,
			const struct blkio_disk_layout *layout)
{
	const unsigned long long first = layout->first_sector;
	const unsigned long long last = layout->last_sector;

	size_t ios = 0;

	for (int i = 0; i != IO_OFFSET_BITS; ++i)
		ios += layout->io_offset[i];

	if (!ios)
		return 0;

	unsigned long long *io_offset = calloc(ios, sizeof(*io_offset));

	if (!io_offset) {
		ERR("Cannot allocate array of IO offsets\n");
		return 1;
	}

	for (size_t i = 0, j = 0; i != IO_OFFSET_BITS; ++i) {
		for (size_t k = 0; k != layout->io_offset[i]; ++k)
			io_offset[j++] = i ? (1ull << (i - 1)) : 0;
	}
	RANDOM_SHUFFLE(io_offset, ios, unsigned long long);

	for (size_t i = 0; i != ios; ++i)
		bios[i].flags = flags;
	for (size_t i = 0; i != layout->sync; ++i)
		bios[i].flags |= BIO_SYNC | BIO_NOIDLE;
	for (size_t i = 0; i != layout->fua; ++i)
		bios[i].flags |= BIO_FUA;
	RANDOM_SHUFFLE(bios, ios, struct bio);

	unsigned long long off = first;

	for (size_t i = 0, j = 0; i != IO_SIZE_BITS; ++i) {
		const unsigned long size = 1ul << i;

		for (size_t k = 0; k != layout->io_size[i]; ++k) {
			if (off + size > last)
				off = first;

			bios[j].offset = BYTES(off);
			bios[j].bytes = BYTES(size);

			off += size + io_offset[j++];
		}
	}
	free(io_offset);

	return 0;
}

int bio_generate(struct bio *bios, const struct blkio_stats *stat)
{
	const size_t reads = stat->reads;
	const size_t writes = stat->writes;
	const size_t size = reads + writes;

	struct bio *copy = calloc(size, sizeof(*copy));

	if (!copy) {
		ERR("Cannot allocate array for BIOs copies\n");
		return 1;
	}

	if (bio_fill_flags(copy, BIO_READ, &stat->reads_layout)) {
		free(copy);
		return 1;
	}

	if (bio_fill_flags(copy + reads, BIO_WRITE, &stat->writes_layout)) {
		free(copy);
		return 1;
	}

	struct bio_ctree *nodes = calloc(size, sizeof(*nodes));

	if (!nodes) {
		ERR("Cannot allocate cartesian tree nodes\n");
		free(copy);
		return 1;
	}

	size_t count = bio_runs_fill(copy, reads, nodes, &stat->reads_layout);
	size_t total = count;

	count = bio_runs_fill(copy + reads, writes, nodes + count,
				&stat->writes_layout);
	total += count;
	bio_ctree_sort_by_offset(nodes, total);

	struct ctree *tree = 0;

	for (size_t i = 0; i != total; ++i)
		bio_ctree_append(&tree, nodes + i);

	unsigned long long invs = stat->inversions;

	for (size_t i = 0, j = 0; i != total; ++i) {
		const size_t max = total - i - 1;
		const size_t min = max_invs(max) < invs ?
					MINU(max, invs - max_invs(max)) : 0;
		const size_t idx = myrandom(min, max + 1);

		struct bio_ctree *node = bio_ctree_extract(&tree, idx);

		invs -= idx;
		for (struct bio *bio = node->first; bio <= node->last; ++bio)
			bios[j++] = *bio;
	}
	free(nodes);
	free(copy);

	return 0;
}
