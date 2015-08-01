#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

#include <libaio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "object_cache.h"
#include "algorithm.h"
#include "blkrecord.h"
#include "file_io.h"
#include "common.h"
#include "ctree.h"
#include "debug.h"

static const char *input_file_name;
static const char *device_file_name;
static unsigned number_of_events = 512u;
static unsigned sector_size = 512u;
static int use_direct_io = 1;

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		" -d <device>           | --device=<device>\n" \
		"[-f <input file>       | --file=<input file>]\n" \
		"[-e <number of events> | --events=<number of events>]\n" \
		"[-s <sector size>      | --sector=<sector size>]\n" \
		"[-b                    | --buffered]\n" \
		"\t-d Block device file. No default, must be specified.\n" \
		"\t-f Use specified blkrecord file. Default: stdin\n" \
		"\t-s Block device sector size. Default: 512\n" \
		"\t-e Max number of concurrently processing events. Default: 512\n" \
		"\t-b Use buffered IO (do not use direct IO)\n";

	ERR("Usage: %s %s", name, usage);
}

static int parse_args(int argc, char **argv)
{
	static struct option long_opts[] = {
		{
			.name = "file",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'f'
		},
		{
			.name = "device",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'd'
		},
		{
			.name = "events",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'e'
		},
		{
			.name = "sector",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 's'
		},
		{
			.name = "buffered",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'b'
		},
		{
			.name = NULL
		}
	};
	static const char *opts = "f:d:e:s:b";

	long i;
	int c;

	while ((c = getopt_long(argc, argv, opts, long_opts, NULL)) >= 0) {
		switch (c) {
		case 'f':
			input_file_name = optarg;
			break;
		case 'd':
			device_file_name = optarg;
			break;
		case 'e':
			i = atol(optarg);
			if (i <= 0) {
				ERR("Number of events must be positive\n");
				return 1;
			}
			number_of_events = (unsigned)i;
			break;
		case 's':
			i = atol(optarg);
			if (i <= 0) {
				ERR("Sector size must be positive\n");
				return 1;
			}
			sector_size = (unsigned)i;
			break;
		case 'b':
			use_direct_io = 0;
			break;
		default:
			show_usage(argv[0]);
			return 1;
		}
	}

	if (!device_file_name) {
		ERR("Spcify device file name\n");
		show_usage(argv[0]);
		return 1;
	}

	return 0;
}

static int blkio_stats_read(int fd, struct blkio_stats *stats)
{ return myread(fd, (char *)stats, sizeof(*stats)); }

static unsigned mylog2(unsigned long long x)
{
	unsigned bits;
	for (bits = 0; x; x >>= 1)
		++bits;
	return bits;
}

static unsigned long long myrandom(unsigned long long from,
			unsigned long long to)
{
	const unsigned bits = mylog2(RAND_MAX);
	unsigned long long value = 0;
	unsigned gen;

	for (gen = 0; gen < sizeof(value) * 8; gen += bits)
		value |= (unsigned long long)rand() << gen;
	return value % (to - from + 1) + from;
}

/**
 * struct iocb management routines (cached allocation and release mostly).
 */
static struct object_cache *iocb_cache;

static struct iocb *iocb_alloc(void)
{
	return object_cache_alloc(iocb_cache);
}

static void iocb_free(struct iocb *iocb)
{
	object_cache_free(iocb_cache, iocb);
}

static struct iocb *iocb_get(int fd, unsigned long long off, unsigned long len,
			int rw)
{
	struct iocb *iocb;
	void *buf;

	if (!(iocb = iocb_alloc())) {
		ERR("Cannot allocate iocb\n");
		return 0;
	}

	if (posix_memalign(&buf, sector_size, len)) {
		ERR("Cannot allocate buffer for an IO operation\n");
		iocb_free(iocb);
		return 0;
	}

	if (rw) {
		io_prep_pwrite(iocb, fd, buf, len, off);
		memset(buf, 0x13, len);
	} else {
		io_prep_pread(iocb, fd, buf, len, off);
	}
	return iocb;
}

static void iocb_release(struct iocb *iocb)
{
	free(iocb->u.c.buf);
	iocb_free(iocb);
}

static void iocbs_release(struct iocb **iocbs, size_t count)
{
	size_t i;
	for (i = 0; i != count; ++i)
		iocb_release(iocbs[i]);
}


static int iocb_offset_compare(const struct iocb **l, const struct iocb **r)
{
	if ((*l)->u.c.offset < (*r)->u.c.offset)
		return -1;
	if ((*l)->u.c.offset > (*r)->u.c.offset)
		return 1;
	return 0;
}

/**
 * iocbs_sort - sorts iocbs pointers by offset in ascending order
 */
static void iocbs_sort(struct iocb **iocbs, size_t size)
{ sort(iocbs, size, &iocb_offset_compare); }


/**
 * We use implicit cartesian tree instead mere array, because we need
 * effectively remove items from middle.
 */
struct iocb_ctree {
	struct ctree link;
	struct iocb *iocb;
};

static void iocb_ctree_node_init(struct iocb_ctree *tree, struct iocb *iocb)
{
	cinit(&tree->link);
	tree->iocb = iocb;
}

/**
 * iocb_ctree_append - append node to the end of tree.
 *
 * tree - pointer to pointer to tree to append to :)
 * node - new node to insert.
 */
static void iocb_ctree_append(struct ctree **tree, struct iocb_ctree *node)
{ *tree = cappend(*tree, &node->link); }

/**
 * iocb_ctree_extract - removes idx node from the tree, and returns pointer.
 *
 * tree - tree to remove item from
 * idx - item index (starting from 0)
 *
 * NODE: tree MUST contain at least idx items.
 */
static struct iocb_ctree *iocb_ctree_extract(struct ctree **tree,
			size_t idx)
{
	struct ctree *node;

	assert(idx < csize(*tree) && "Tree is too small");
	*tree = cextract(*tree, idx, &node);
	assert(node && "Node must not be NULL");
	return centry(node, struct iocb_ctree, link);
}

static unsigned long long max_invs(unsigned long long items)
{ return items * (items - 1) / 2; }

/**
 * iocbs_shuffle - shuffles iocbs so that number of inversions
 *                 approximately equal to invs.
 *
 * iocbs - pointers to iocb pointers to shuffle
 * size - number of iocbs
 * inv - number of inversions
 *
 * NOTE: invs MUST be less or equal to max_invs(size), otherwise
 *       it is impossible to generate appropriate permutation.
 *
 * NOTE: actual number of inversions is less or equal to invs,
 *       because iocbs can contain items with same offset, even
 *       though permutation contains exactly invs inversions.
 */
static int iocbs_shuffle(struct iocb **iocbs, size_t size,
			unsigned long long invs)
{
	struct ctree *tree = 0;
	struct iocb_ctree *nodes;
	size_t i;

	nodes = calloc(size, sizeof(struct iocb_ctree));
	if (!nodes) {
		ERR("Cannot allocate cartesian tree nodes\n");
		return 1;
	}

	iocbs_sort(iocbs, size);
	for (i = 0; i != size; ++i) {
		iocb_ctree_node_init(nodes + i, iocbs[i]);
		iocb_ctree_append(&tree, nodes + i);
	}

	for (i = 0; i != size; ++i) {
		const unsigned long long rem = size - i - 1;
		const unsigned long long min = max_invs(rem) < invs
					? invs - max_invs(rem) : 0;
		const unsigned long long max = MIN(invs, rem);
		const unsigned long long idx = myrandom(min, max);

		assert(min <= max && "Wrong inversions limits");
		assert(idx <= max && idx >= min && "Wrong item index");

		iocbs[i] = iocb_ctree_extract(&tree, idx)->iocb;
		invs -= idx;
	}
	free(nodes);
	return 0;
}

/**
 * iocbs_fill - genreates iocbs accoriding to stat. Number of
 *              iocbs to generate is stat->reads + stats->writes.
 *
 * iocbs - array large enough to store appropriate number of iocb
 *         pointers
 * fd - file descriptor to work with
 * stat - IO parameters.
 */
static int iocbs_fill(struct iocb **iocbs, int fd,
			const struct blkio_stats *stat)
{
	const unsigned long long min_sec = stat->min_sector;
	const unsigned long long max_sec = stat->max_sector;
	const unsigned long long spot_sectors = stat->merged_sectors;
	const unsigned long long spot_bytes = sector_size * spot_sectors;

	const size_t reads = stat->reads;
	const size_t writes = stat->writes;
	const size_t ios = reads + writes;

	unsigned long long bytes = stat->sectors * sector_size;
	size_t i;

	if (use_direct_io)
		bytes = (bytes + sector_size - 1) & ~(sector_size - 1);

	for (i = 0; i != ios;) {
		const unsigned long long off = sector_size * myrandom(min_sec,
					max_sec - spot_sectors);
		unsigned long long j;

		for (j = 0; i != ios && j < spot_bytes; j += bytes, ++i) {
			const int wr = i < writes;

			iocbs[i] = iocb_get(fd, off + j, bytes, wr);
			if (!iocbs[i]) {
				iocbs_release(iocbs, i);
				return 1;
			}
		}
	}

	return iocbs_shuffle(iocbs, ios, stat->inversions);
}

/**
 * iocbs_submit - submits exactly count IOs from iocbs array.
 *
 * ctx - aio context
 * iocbs - array of at least count iocbs
 * count - number of IOs to submit
 *
 * Returns 0, if success.
 */
static int iocbs_submit(io_context_t ctx, struct iocb **iocbs, size_t count)
{
	size_t sb = 0;

	while (sb != count) {
		int ret = io_submit(ctx, count - sb, iocbs + sb);
		if (ret < 0) {
			ERR("Error %d, while submiting IO\n", -ret);
			return 1;
		}
		sb += ret;
	}
	return 0;
}

/**
 * io_events_check - check events array filled with io_getevents. If at least
 *                   one of io_event reports error function print detailed info
 *                   to stderr and returns 1.
 */
static int io_events_check(const struct io_event *events, size_t count)
{
	size_t i;

	for (i = 0; i != count; ++i) {
		const struct io_event * const e = events + i;
		const struct iocb * const iocb = e->obj;

		if (e->res != iocb->u.c.nbytes) {
			const char *op = iocb->aio_lio_opcode == IO_CMD_PREAD
						? "read" : "write";
			ERR("AIO %s of %ld bytes at %lld failed (%ld/%ld)\n",
						op,
						iocb->u.c.nbytes,
						iocb->u.c.offset,
						e->res,
						e->res2);
			return 1;
		}
	}
	return 0;
}

/**
 * blkio_stats_play - generate, submit and recalim IOs.
 *
 * ctx - aio context
 * fd - file descriptor to work with (a.k.a block device)
 * stat - IOs parameters
 *
 * Returns 0, if success.
 */
static int blkio_stats_play(io_context_t ctx, int fd,
			const struct blkio_stats *stat)
{
	const size_t ios = stat->reads + stat->writes;
	const size_t iodepth = MIN(stat->iodepth, number_of_events);
	const size_t batch = stat->batch;
	struct iocb **iocbs;
	struct io_event *events;
	size_t submit_i, reclaim_i;
	int rc = 0;

	iocbs = calloc(ios, sizeof(struct iocb *));
	if (!iocbs) {
		ERR("Cannot allocate array of struct iocb\n");
		return 1;
	}

	events = calloc(iodepth, sizeof(struct io_event));
	if (!events) {
		free(iocbs);
		ERR("Cannot allocate array of struct io_event\n");
		return 1;
	}

	if (iocbs_fill(iocbs, fd, stat)) {
		free(iocbs);
		free(events);
		return 1;
	}

	reclaim_i = submit_i = 0;
	while (reclaim_i != ios) {
		size_t remain = ios - submit_i;
		size_t todo = MIN(batch, remain);
		size_t running;
		int ret;

		if (iocbs_submit(ctx, iocbs + submit_i, todo)) {
			rc = 1;
			break;
		}
		submit_i += todo;

		running = submit_i - reclaim_i;
		remain = ios - submit_i;
		todo = 1;
		if (iodepth - running < batch)
			todo = MIN(running, batch - (iodepth - running));

		ret = io_getevents(ctx, todo, iodepth, events, NULL);
		if (ret < 0) {
			ERR("Error %d, while reclaiming IO\n", -ret);
			rc = 1;
			break;
		}
		reclaim_i += ret;

		if (io_events_check(events, ret)) {
			rc = 1;
			break;
		}
	}

	iocbs_release(iocbs, ios);
	free(iocbs);
	free(events);
	return rc;
}

static void play(int ifd, int dfd)
{
	struct blkio_stats stat;
	io_context_t ctx = 0;
	int ret;

	iocb_cache = object_cache_create(sizeof(struct iocb));

	if ((ret = io_setup(number_of_events, &ctx))) {
		ERR("Cannot initialize AIO context (%d)\n", -ret);
		object_cache_destroy(iocb_cache);
		return;
	}

	while (!blkio_stats_read(ifd, &stat)) {
		if (blkio_stats_play(ctx, dfd, &stat))
			break;
	}

	io_destroy(ctx);
	object_cache_destroy(iocb_cache);
}

int main(int argc, char **argv)
{
	int ifd = 0, dfd = 1;
	int flags = O_RDWR;

	if (parse_args(argc, argv))
		return 1;

	if (input_file_name && strcmp("-", input_file_name)) {
		ifd = open(input_file_name, 0);
		if (ifd < 0) {
			perror("Cannot open input file");
			return 1;
		}
	}

	if (use_direct_io)
		flags |= O_DIRECT;
	dfd = open(device_file_name, flags);
	if (dfd < 0) {
		close(ifd);
		perror("Cannot open block device file");
		return 1;
	}

	srand(time(NULL));
	play(ifd, dfd);

	close(dfd);
	close(ifd);

	return 0;
}
