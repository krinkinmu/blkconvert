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

#include <zlib.h>

#include "object_cache.h"
#include "algorithm.h"
#include "blkrecord.h"
#include "file_io.h"
#include "common.h"
#include "ctree.h"
#include "debug.h"

static const unsigned long long NS = 1000000000ull;

static const char *input_file_name;
static const char *device_file_name;
static unsigned number_of_events = 512u;
static unsigned sector_size = 512u;
static unsigned page_size = 4096u;
static int use_direct_io = 1;
static int time_accurate = 0;

#define BYTES(sec)          ((sec) * sector_size)
#define MAX_PIDS_SIZE       1024
#define MAX_PLAY_PROCESSES  256

static unsigned long pids_to_play[MAX_PIDS_SIZE];
static unsigned pids_to_play_size;

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		" -d <device>           | --device=<device>\n" \
		" -f <input file>       | --file=<input file>\n" \
		"[-e <number of events> | --events=<number of events>]\n" \
		"[-s <sector size>      | --sector=<sector size>]\n" \
		"[-p <pid>              | --pid=<pid>]\n" \
		"[-t                    | --time]\n" \
		"[-b                    | --buffered]\n" \
		"\t-d Block device file. Must be specified.\n" \
		"\t-f Use specified blkrecord file. Default: stdin\n" \
		"\t-e Max number of concurrently processing events. Default: 512\n" \
		"\t-s Block device sector size. Default: 512\n" \
		"\t-p Process PID to play.\n" \
		"\t-t Time accurate playing.\n" \
		"\t-b Use buffered IO (do not use direct IO)\n";

	ERR("Usage: %s %s", name, usage);
}

static int pid_compare(unsigned long lpid, unsigned long rpid)
{
	if (lpid < rpid)
		return -1;
	if (lpid > rpid)
		return 1;
	return 0;
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
			.name = "time",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 't'
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
	static const char *opts = "d:f:e:s:p:tb";

	unsigned j;
	long i;
	int c, found;

	while ((c = getopt_long(argc, argv, opts, long_opts, NULL)) >= 0) {
		switch (c) {
		case 'd':
			device_file_name = optarg;
			break;
		case 'f':
			input_file_name = optarg;
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

			found = 0;
			for (j = 0; j != pids_to_play_size; ++j) {
				if (pids_to_play[j] == (unsigned long)i) {
					found = 1;
					break;
				}
			}
			if (!found)
				pids_to_play[pids_to_play_size++] = i;
			break;
		case 't':
			time_accurate = 1;
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

	if (pids_to_play_size)
		sort(pids_to_play, pids_to_play_size, &pid_compare);

	return 0;
}

static int to_play(unsigned long pid)
{
	size_t pos;

	if (!pids_to_play_size)
		return 1;

	pos = lower_bound(pids_to_play, pids_to_play_size, pid, &pid_compare);
	if (pos == pids_to_play_size || pids_to_play[pos] != pid)
		return 0;
	return 1;
}

static int blkio_stats_read(int fd, struct blkio_stats *stats)
{ return myread(fd, (char *)stats, sizeof(*stats)); }

static int blkio_stats_write(int fd, const struct blkio_stats *stats)
{ return mywrite(fd, (char *)stats, sizeof(*stats)); }

static int blkio_zstats_read(gzFile zfd, struct blkio_stats *stats)
{
	const size_t size = sizeof(*stats);
	char *buf = (char *)stats;
	size_t read = 0;

	while (read != size) {
		int ret = gzread(zfd, buf + read, size - read);

		if (!ret) {
			if (!gzeof(zfd)) {
				int gzerr = 0;
				const char *msg = gzerror(zfd, &gzerr);

				if (gzerr != Z_ERRNO)
					ERR("zlib read failed: %s\n", msg);
				else
					perror("Read failed");
			}
			return 1;
		}
		read += ret;
	}
	return 0;
}

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

struct process_context {
	io_context_t io_ctx;
	struct io_event *events;
	long size, running;
	int fd;
	struct object_cache *cache;
};

/**
 * struct iocb management routines (cached allocation and release mostly).
 */
static struct iocb *iocb_alloc(struct object_cache *cache)
{
	return object_cache_alloc(cache);
}

static void iocb_free(struct object_cache *cache, struct iocb *iocb)
{
	object_cache_free(cache, iocb);
}

static struct iocb *iocb_get(struct process_context *ctx,
			unsigned long long off, unsigned long len, int rw)
{
	struct iocb *iocb;
	void *buf;

	if (!(iocb = iocb_alloc(ctx->cache))) {
		ERR("Cannot allocate iocb\n");
		return 0;
	}

	if (posix_memalign(&buf, page_size, len)) {
		ERR("Cannot allocate buffer for an IO operation\n");
		iocb_free(ctx->cache, iocb);
		return 0;
	}

	if (rw) {
		io_prep_pwrite(iocb, ctx->fd, buf, len, off);
		memset(buf, 0x13, len);
	} else {
		io_prep_pread(iocb, ctx->fd, buf, len, off);
	}

	return iocb;
}

static void iocb_release(struct process_context *ctx, struct iocb *iocb)
{
	free(iocb->u.c.buf);
	iocb_free(ctx->cache, iocb);
}

static void iocbs_release(struct process_context *ctx, struct iocb **iocbs,
			size_t count)
{
	size_t i;
	for (i = 0; i != count; ++i)
		iocb_release(ctx, iocbs[i]);
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

static int __iocbs_fill(struct iocb **iocbs, struct process_context *ctx,
			int wr, const struct blkio_disk_layout *dl)
{
	const unsigned long long first = dl->first_sector;
	const unsigned long long last = dl->last_sector;

	unsigned long long *io_offset;
	unsigned long long off;
	unsigned long i, j, ios = 0;

	for (i = 0; i != IO_OFFSET_BITS; ++i)
		ios += dl->io_offset[i];

	if (!ios)
		return 0;

	io_offset = calloc(ios, sizeof(*io_offset));
	if (!io_offset) {
		ERR("Cannot allocate array of IO sizes\n");
		return 1;
	}

	for (i = 0, j = 0; i != IO_OFFSET_BITS; ++i) {
		unsigned long k;

		for (k = 0; k != dl->io_offset[i]; ++k)
			io_offset[j++] = i ? (1ull << (i - 1)) : 0;
	}
	RANDOM_SHUFFLE(io_offset, ios, unsigned long long);

	off = first;
	for (i = 0, j = 0; i != IO_SIZE_BITS; ++i) {
		const unsigned long size = 1ul << i;
		unsigned long k;

		for (k = 0; k != dl->io_size[i]; ++k) {
			if (off + size > last)
				off = first;

			iocbs[j] = iocb_get(ctx, BYTES(off), BYTES(size), wr);
			if (!iocbs[j]) {
				iocbs_release(ctx, iocbs, j);
				free(io_offset);
				return 1;
			}
			off += size + io_offset[j++];
		}
	}
	free(io_offset);
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
static int iocbs_fill(struct iocb **iocbs, struct process_context *ctx,
			const struct blkio_stats *stat)
{
	const unsigned long reads = stat->reads;
	const unsigned long writes = stat->writes;

	if (__iocbs_fill(iocbs, ctx, 0, &stat->reads_layout))
		return 1;

	if (__iocbs_fill(iocbs + reads, ctx, 1, &stat->writes_layout))
		return 1;

	return iocbs_shuffle(iocbs, reads + writes, stat->inversions);
}

/**
 * iocbs_submit - submits exactly count IOs from iocbs array.
 *
 * ctx - initialized process_context
 * iocbs - array of at least count iocbs
 * count - number of IOs to submit
 *
 * Returns number of submitted IOs, if returned value less then count,
 * then error occured.
 */
static size_t iocbs_submit(struct process_context *ctx, struct iocb **iocbs,
			size_t count)
{
	size_t sb = 0;

	while (sb != count) {
		const int ret = io_submit(ctx->io_ctx, count - sb, iocbs + sb);

		if (ret < 0) {
			ERR("Error %d, while submiting IO\n", -ret);
			ERR("iocb offset %lld, size %lu, ptr %lx\n",
				iocbs[sb]->u.c.offset,
				iocbs[sb]->u.c.nbytes,
				(unsigned long)iocbs[sb]->u.c.buf);
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
static int io_events_check_and_release(struct process_context *ctx,
			size_t count)
{
	size_t i;
	int ret = 0;

	for (i = 0; i != count; ++i) {
		struct io_event *e = ctx->events + i;
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
		iocb_release(ctx, iocb);
	}
	return ret;
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

static int process_context_setup(struct process_context *ctx)
{
	int ret;

	ctx->io_ctx = 0;
	ctx->size = number_of_events;
	ctx->running = 0;
	ctx->fd = open_disk_file();

	if (ctx->fd < 0)
		return 1;

	ctx->cache = object_cache_create(sizeof(struct iocb));
	if (!ctx->cache) {
		ERR("Cannot create iocb cache\n");
		close(ctx->fd);
		return 1;
	}

	ctx->events = calloc(number_of_events, sizeof(struct io_event));
	if (!ctx->events) {
		ERR("Cannot allocate array of io_event\n");
		object_cache_destroy(ctx->cache);
		close(ctx->fd);
		return 1;
	}

	if ((ret = io_setup(number_of_events, &ctx->io_ctx))) {
		ERR("Cannot initialize AIO context (%d)\n", -ret);
		free(ctx->events);
		object_cache_destroy(ctx->cache);
		close(ctx->fd);
		return 1;
	}

	return 0;
}

static void process_context_destroy(struct process_context *ctx)
{
	if (ctx->running) {
		const int ret = io_getevents(ctx->io_ctx, ctx->running,
					ctx->size, ctx->events, NULL);

		if (ret < 0)
			ERR("Error %d, while reclaiming IO\n", -ret);
		else
			io_events_check_and_release(ctx, ret);
	}

	io_destroy(ctx->io_ctx);
	free(ctx->events);
	object_cache_destroy(ctx->cache);
	close(ctx->fd);
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
static int blkio_stats_play(struct process_context *ctx,
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

	if (iocbs_fill(iocbs, ctx, stat)) {
		free(iocbs);
		return 1;
	}

	submit_i = 0;
	while (submit_i != ios) {
		long submit = 0, reclaim = 1;
		long next, submitted, reclaimed;

		if (ctx->running < iodepth)
			submit = MIN(ios - submit_i, iodepth - ctx->running);

		submitted = iocbs_submit(ctx, iocbs + submit_i, submit);
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

		if (io_events_check_and_release(ctx, reclaimed)) {
			rc = 1;
			break;
		}
	}

	iocbs_release(ctx, iocbs + submit_i, ios - submit_i);
	free(iocbs);
	return rc;
}

static void play(int fd)
{
	struct process_context ctx;
	struct blkio_stats stats;

	if (process_context_setup(&ctx)) {
		ERR("Cannot create process context\n");
		return;
	}

	while (!blkio_stats_read(fd, &stats)) {
		if (blkio_stats_play(&ctx, &stats))
			break;
	}
	process_context_destroy(&ctx);
}

static unsigned long long current_time(void)
{
	struct timespec time;

	clock_gettime(CLOCK_MONOTONIC, &time);
	return time.tv_sec * NS + time.tv_nsec;
}

struct play_process {
	unsigned long long end_time;
	unsigned long pid;
	int fd;
};

static void __play_pids(gzFile zfd, struct play_process *p, unsigned size)
{
	const unsigned long long play_time = current_time();

	unsigned long long record_time = ~0ull;
	struct blkio_stats stats;

	while (!blkio_zstats_read(zfd, &stats)) {
		const unsigned long pid = stats.pid;
		unsigned parent;

		if (!to_play(pid))
			continue;

		if (record_time > stats.begin_time)
			record_time = stats.begin_time;

		if (time_accurate) {
			const unsigned long long p_elapsed =
						current_time() - play_time;
			const unsigned long long r_elapsed =
						stats.begin_time - record_time;

			if (p_elapsed < r_elapsed) {
				struct timespec wait;

				wait.tv_sec = (r_elapsed - p_elapsed) / NS;
				wait.tv_nsec = (r_elapsed - p_elapsed) % NS;
				nanosleep(&wait, 0);
			}
		}

		parent = 0;
		if (blkio_stats_write(p[parent].fd, &stats))
			break;

		p[parent].end_time = stats.end_time;
		while (parent < size) {
			struct play_process tmp;
			const size_t l = 2 * (parent + 1) - 1;
			const size_t r = 2 * (parent + 1);
			size_t swap = parent;

			if (l < size && p[l].end_time < p[swap].end_time)
				swap = l;

			if (r < size && p[r].end_time < p[swap].end_time)
				swap = r;

			if (swap == parent)
				break;

			tmp = p[parent];
			p[parent] = p[swap];
			p[swap] = tmp;
			parent = swap;
		}
	}	
}

static void play_pids(unsigned pool_size)
{
	struct play_process player[MAX_PLAY_PROCESSES];
	unsigned i;
	int fail = 0;

	for (i = 0; i != pool_size; ++i) {
		player[i].end_time = 0;
		player[i].fd = -1;
	}

	for (i = 0; i != pool_size; ++i) {
		int pfds[2], ret;
		unsigned j;

		if (pipe(pfds)) {
			perror("Cannot create pipe for play process");
			fail = 1;
			for (j = 0; j != i; ++j)
				close(player[j].fd);
			break;
		}

		player[i].fd = pfds[1];
		ret = fork();
		if (ret < 0) {
			perror("Cannot create play process");
			fail = 1;
			close(pfds[0]);
			close(pfds[1]);
			for (j = 0; j != i; ++j)
				close(player[j].fd);
			break;
		}

		player[i].pid = ret;
		if (!ret) {
			for (j = 0; j != i; ++j)
				close(player[j].fd);
			close(pfds[1]);
			play(pfds[0]);
			close(pfds[0]);
			return;
		}
	}

	if (!fail) {
		gzFile zfd = gzopen(input_file_name, "rb");
		if (zfd) {
			ERR("Start playing\n");
			__play_pids(zfd, player, pool_size);
			for (i = 0; i != pool_size; ++i)
				close(player[i].fd);
			gzclose(zfd);
		} else {
			ERR("Cannot allocate enough memory for zlib\n");
		}
	}

	for (i = 0; i != pool_size; ++i)
		waitpid(player[i].pid, NULL, 0);
}

static void find_and_play_pids(void)
{
	unsigned long long et[MAX_PLAY_PROCESSES];
	unsigned ps = 0;

	struct blkio_stats stats;
	gzFile zfd = 0;

	zfd = gzopen(input_file_name, "rb");
	if (!zfd) {
		ERR("Cannot allocate enough memory for zlib\n");
		return;
	}

	while (!blkio_zstats_read(zfd, &stats)) {
		const unsigned long pid = stats.pid;

		if (!to_play(pid))
			continue;

		if (!ps || et[0] > stats.begin_time) {
			size_t child = ps++;

			assert(child != MAX_PLAY_PROCESSES &&
					"Too many play processes required");

			et[child] = stats.end_time;
			while (child != 0) {
				const size_t parent = (child + 1) / 2 - 1;
				unsigned long long tmp;

				if (et[child] >= et[parent])
					break;

				tmp = et[parent];
				et[parent] = et[child];
				et[child] = tmp;
				child = parent;
			}
		} else {
			size_t parent = 0;

			et[parent] = stats.end_time;
			while (parent < ps) {
				unsigned long long tmp;
				const size_t l = 2 * (parent + 1) - 1;
				const size_t r = 2 * (parent + 1);
				size_t swap = parent;

				if (l < ps && et[l] < et[swap])
					swap = l;

				if (r < ps && et[r] < et[swap])
					swap = r;

				if (swap == parent)
					break;

				tmp = et[parent];
				et[parent] = et[swap];
				et[swap] = tmp;
				parent = swap;
			}
		}
	}

	gzclose(zfd);
	play_pids(ps);
}

int main(int argc, char **argv)
{
	if (parse_args(argc, argv))
		return 1;

	srand(time(NULL));
	find_and_play_pids();

	return 0;
}
