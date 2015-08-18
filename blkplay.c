#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include <libaio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
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
static unsigned page_size = 4096u;
static long pid = -1;
static int use_direct_io = 1;

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		" -d <device>           | --device=<device>\n" \
		" -f <input file>       | --file=<input file>\n" \
		"[-e <number of events> | --events=<number of events>]\n" \
		"[-s <sector size>      | --sector=<sector size>]\n" \
		"[-p <pid>              | --pid=<pid>]\n" \
		"[-b                    | --buffered]\n" \
		"\t-d Block device file. Must be specified.\n" \
		"\t-f Use specified blkrecord file. Default: stdin\n" \
		"\t-e Max number of concurrently processing events. Default: 512\n" \
		"\t-s Block device sector size. Default: 512\n" \
		"\t-p Process PID to play.\n" \
		"\t-b Use buffered IO (do not use direct IO)\n";

	ERR("Usage: %s %s", name, usage);
}

static int parse_args(int argc, char **argv)
{
	static struct option long_opts[] = {
		{
			.name = "device",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'd'
		},
		{
			.name = "file",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'f'
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
			.name = "pid",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'p'
		},
		{
			.name = "buffered",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 'b'
		},
		{
			.name = NULL
		}
	};
	static const char *opts = "d:f:e:s:p:b";

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
		case 'p':
			i = atol(optarg);
			if (i < 0) {
				ERR("PID cannot be negative\n");
				return 1;
			}
			pid = i;
			break;
		case 'b':
			use_direct_io = 0;
			break;
		default:
			show_usage(argv[0]);
			return 1;
		}
	}

	if (!input_file_name) {
		ERR("Spcify input file name\n");
		show_usage(argv[0]);
		return 1;
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
	return value % (to - from) + from;
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

	if (posix_memalign(&buf, page_size, len)) {
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
static void iocbs_sort_by_offset(struct iocb **iocbs, size_t size)
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

	iocbs_sort_by_offset(iocbs, size);
	for (i = 0; i != size; ++i) {
		iocb_ctree_node_init(nodes + i, iocbs[i]);
		iocb_ctree_append(&tree, nodes + i);
	}

	for (i = 0; i != size; ++i) {
		const unsigned long long rem = size - i - 1;
		const unsigned long long min = max_invs(rem) < invs
					? invs - max_invs(rem) : 0;
		const unsigned long long max = MIN(invs, rem);
		const unsigned long long idx = myrandom(min, max + 1);

		assert(min <= max && "Wrong inversions limits");
		assert(idx <= max && idx >= min && "Wrong item index");

		iocbs[i] = iocb_ctree_extract(&tree, idx)->iocb;
		invs -= idx;
	}
	free(nodes);
	return 0;
}

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

static int __iocbs_fill(struct iocb **iocbs, int fd, int wr,
			const struct blkio_disk_layout *dl)
{
	const unsigned long long first = dl->first_sector;
	const unsigned long long last = dl->last_sector;

	unsigned long *spot_size, *io_size;
	unsigned long long *spot_offset;
	unsigned long long offset;
	unsigned long spot, spots = 0, ios = 0;

	size_t i, j;

	for (i = 0; i != SECTOR_SIZE_BITS; ++i)
		ios += dl->io_size[i];

	if (!ios)
		return 0;

	for (i = 0; i != SECTOR_SIZE_BITS; ++i)
		spots += dl->merged_size[i];

	io_size = calloc(ios, sizeof(*io_size));
	if (!io_size) {
		ERR("Cannot allocate array of IO sizes\n");
		return 1;
	}

	spot_size = calloc(spots, sizeof(*spot_size));
	if (!spot_size) {
		ERR("Cannot allocate array of spot sizes\n");
		free(io_size);
		return 1;
	}

	spot_offset = calloc(spots, sizeof(*spot_offset));
	if (!spot_offset) {
		ERR("Cannot allocate array of spot offsets\n");
		free(spot_size);
		free(io_size);
		return 1;
	}

	for (i = 0, j = 0; i != SECTOR_SIZE_BITS; ++i) {
		const size_t last = j + dl->io_size[i];
		for (; j != last; ++j)
			io_size[j] = 1ul << i;
	}
	RANDOM_SHUFFLE(io_size, ios, unsigned long);

	for (i = 0, j = 0; i != SECTOR_SIZE_BITS; ++i) {
		const size_t last = j + dl->merged_size[i];
		for (; j != last; ++j)
			spot_size[j] = 1ul << i;
	}
	RANDOM_SHUFFLE(spot_size, spots, unsigned long);

	for (i = 0, j = 1; i != SPOT_OFFSET_BITS; ++i) {
		const size_t last = j + dl->spot_offset[i];
		for (; j != last; ++j)
			spot_offset[j] = 1ull << i;
	}
	RANDOM_SHUFFLE(spot_offset, spots - 1, unsigned long long);

	#define BYTES(sec) ((sec) * sector_size)
	offset = first;
	spot = 0;
	for (i = 0; i != ios;) {
		const unsigned long size = spot_size[spot];

		for (j = 0; i != ios && j < size; j += io_size[i], ++i) {
			const unsigned long long off = BYTES(offset + j);
			const unsigned long len = BYTES(io_size[i]);

			iocbs[i] = iocb_get(fd, off, len, wr);
			if (!iocbs[i]) {
				iocbs_release(iocbs, i);
				free(spot_offset);
				free(spot_size);
				free(io_size);
				return 1;
			}
		}

		if (spots > 1) {
			offset += size + spot_offset[spot % (spots - 1)];
			if (offset + spot_size[spot] >= last)
				offset = first;
		}
		spot = (spot + 1) % spots;
	}
	#undef BYTES

	free(spot_offset);
	free(spot_size);
	free(io_size);
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
	const unsigned long reads = stat->reads;
	const unsigned long writes = stat->writes;

	if (__iocbs_fill(iocbs, fd, 0, &stat->reads_layout))
		return 1;

	if (__iocbs_fill(iocbs + reads, fd, 1, &stat->writes_layout))
		return 1;

	return iocbs_shuffle(iocbs, reads + writes, stat->inversions);
}

/**
 * iocbs_submit - submits exactly count IOs from iocbs array.
 *
 * ctx - aio context
 * iocbs - array of at least count iocbs
 * count - number of IOs to submit
 *
 * Returns number of submitted IOs, if returned value less then count,
 * then error occured.
 */
static size_t iocbs_submit(io_context_t ctx, struct iocb **iocbs, size_t count)
{
	size_t sb = 0;

	while (sb != count) {
		const int ret = io_submit(ctx, count - sb, iocbs + sb);

		if (ret < 0) {
			ERR("Error %d, while submiting IO\n", -ret);
			return sb;
		}
		sb += ret;
	}
	return sb;
}

/**
 * io_events_check_and_release - check events array filled with io_getevents.
 *                               If at least one of io_event reports error
 *                               function print detailed info to stderr and
 *                               returns 1. Also releases all iocbs.
 */
static int io_events_check_and_release(struct io_event *events, size_t count)
{
	size_t i;
	int ret = 0;

	for (i = 0; i != count; ++i) {
		struct io_event *e = events + i;
		struct iocb *iocb = e->obj;

		if (e->res != iocb->u.c.nbytes) {
			const char *op = iocb->aio_lio_opcode == IO_CMD_PREAD
						? "read" : "write";
			ERR("AIO %s of %ld bytes at %lld failed (%ld/%ld)\n",
						op,
						iocb->u.c.nbytes,
						iocb->u.c.offset,
						e->res,
						e->res2);
			ret = 1;
		}
		iocb_release(iocb);
	}
	return ret;
}

struct process_context {
	io_context_t io_ctx;
	struct io_event *events;
	long size, running;
};

static struct process_context *process_context_create(void)
{
	struct process_context *ctx = malloc(sizeof(struct process_context));
	int ret;

	if (!ctx) {
		ERR("Cannot allocate process_context\n");
		return 0;
	}

	ctx->io_ctx = 0;
	ctx->size = number_of_events;
	ctx->running = 0;
	ctx->events = calloc(number_of_events, sizeof(struct io_event));
	if (!ctx->events) {
		ERR("Cannot allocate array of io_event\n");
		free(ctx);
		return 0;
	}

	if ((ret = io_setup(number_of_events, &ctx->io_ctx))) {
		ERR("Cannot initialize AIO context (%d)\n", -ret);
		free(ctx->events);
		free(ctx);
		return 0;
	}

	return ctx;
}

static void process_context_destroy(struct process_context *ctx)
{
	if (ctx->running) {
		const int ret = io_getevents(ctx->io_ctx, ctx->running,
					ctx->size, ctx->events, NULL);

		if (ret < 0)
			ERR("Error %d, while reclaiming IO\n", -ret);
		else
			io_events_check_and_release(ctx->events, ret);
	}

	io_destroy(ctx->io_ctx);
	free(ctx->events);
	free(ctx);
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
static int blkio_stats_play(struct process_context *ctx, int fd,
			const struct blkio_stats *stat)
{
	const long ios = stat->reads + stat->writes;
	const long iodepth = MIN(stat->iodepth, ctx->size);
	const long batch = MIN(iodepth, stat->batch);

	struct iocb **iocbs;
	long submit_i;
	int rc = 0;

	iocbs = calloc(ios, sizeof(struct iocb *));
	if (!iocbs) {
		ERR("Cannot allocate array of struct iocb\n");
		return 1;
	}

	if (iocbs_fill(iocbs, fd, stat)) {
		free(iocbs);
		return 1;
	}

	submit_i = 0;
	while (submit_i != ios) {
		long submit = 0, reclaim = 1;
		long next, submitted, reclaimed;

		if (ctx->running < iodepth)
			submit = MIN(ios - submit_i, iodepth - ctx->running);

		submitted = iocbs_submit(ctx->io_ctx, iocbs + submit_i, submit);
		submit_i += submitted;
		ctx->running += submitted;

		if (submitted < submit) {
			rc = 1;
			break;
		}

		next = MIN(ios - submit_i, batch);
		if (ctx->running > iodepth - next)
			reclaim = ctx->running - iodepth + next;

		reclaimed = io_getevents(ctx->io_ctx, reclaim, ctx->size,
					ctx->events, NULL);
		if (reclaimed < 0) {
			ERR("Error %ld, while reclaiming IO\n", -reclaimed);
			rc = 1;
			break;
		}
		ctx->running -= reclaimed;

		if (io_events_check_and_release(ctx->events, reclaimed)) {
			rc = 1;
			break;
		}
	}

	iocbs_release(iocbs + submit_i, ios - submit_i);
	free(iocbs);
	return rc;
}

static int open_input_file(void)
{
	int fd = open(input_file_name, 0);

	if (fd < 0)
		perror("Cannot open input file");
		
	return fd;
}

static int open_disk_file(void)
{	
	int flags = O_RDWR;
	int fd;

	if (use_direct_io)
		flags |= O_DIRECT;

	fd = open(device_file_name, flags);
	if (fd < 0)
		perror("Cannot open block device file");

	return fd;
}

static void play_pid(unsigned long pid)
{
	struct process_context *ctx;
	struct blkio_stats stat;
	int ifd, dfd;

	ifd = open_input_file();
	if (ifd < 0)
		return;

	dfd = open_disk_file();
	if (dfd < 0) {
		close(ifd);
		return;
	}

	iocb_cache = object_cache_create(sizeof(struct iocb));
	if (!iocb_cache) {
		ERR("Cannot create iocb cache\n");
		close(dfd);
		close(ifd);
		return;
	}

	ctx = process_context_create();
	if (!ctx) {
		ERR("Cannot create process_context\n");
		object_cache_destroy(iocb_cache);
		close(dfd);
		close(ifd);
		return;
	}

	while (!blkio_stats_read(ifd, &stat)) {
		if (stat.pid != pid)
			continue;

		if (blkio_stats_play(ctx, dfd, &stat))
			break;
	}

	process_context_destroy(ctx);
	object_cache_destroy(iocb_cache);
	close(dfd);
	close(ifd);
}

static void play(void)
{
	#define MAX_PIDS 4096
	unsigned long pids[MAX_PIDS];
	unsigned long size = 0;
	struct blkio_stats stat;
	int fd;

	fd = open_input_file();
	if (fd < 0)
		return;

	while (!blkio_stats_read(fd, &stat)) {
		const unsigned long pid = stat.pid;
		unsigned long i;

		for (i = 0; i != size; ++i)
			if (pids[i] == pid)
				break;

		if (i == size) {
			pid_t child;
			pids[size++] = pid;

			child = fork();
			if (child < 0) {
				ERR("Cannot create child process\n");
				break;
			}

			if (child == 0) {
				close(fd);
				play_pid(pid);
				return;
			}
		}
	}
	close(fd);

	while (size--) {
		errno = 0;
		if (wait(NULL) == -1 && errno == ECHILD)
			break;
	}
	#undef MAX_PIDS
}

int main(int argc, char **argv)
{
	if (parse_args(argc, argv))
		return 1;

	srand(time(NULL));
	if (pid != -1)
		play_pid(pid);
	else
		play();

	return 0;
}
