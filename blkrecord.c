#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <byteswap.h>

#include "object_cache.h"
#include "blktrace_api.h"
#include "blkrecord.h"
#include "algorithm.h"
#include "file_io.h"
#include "common.h"
#include "debug.h"

static const char *input_file_name;
static const char *output_file_name;
static unsigned min_time_interval = 5000u;
static unsigned long min_batch_size = 10000ul;
static unsigned sector_size = 512u;
static int binary = 1;
static int per_process = 0;

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		"[-f <input file>    | --file=<input file>]\n" \
		"[-o <output file>   | --output=<output file>]\n" \
		"[-i <time interval> | --interval=<time interval>]\n" \
		"[-b <batch size>    | --batch=<batch size>]\n" \
		"[-s <sector size>   | --sector=<sector size>]\n" \
		"[-t                 | --text]\n" \
		"[-p                 | --per-process]\n" \
		"\t-f Use specified blktrace file. Default: stdin\n" \
		"\t-o Ouput file. Default: stdout\n" \
		"\t-i Minimum sampling time interval in ms. Default: 5000\n" \
		"\t-b Minimum io batch size. Default: 10000\n" \
		"\t-s Sector size. Default: 512\n" \
		"\t-t Output in text format, by default output is binary.\n" \
		"\t-p Use per process stats.\n";

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
			.name = "output",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'o'
		},
		{
			.name = "interval",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'i'
		},
		{
			.name = "batch",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'b'
		},
		{
			.name = "sector",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 's'
		},
		{
			.name = "text",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 't'
		},
		{
			.name = "per-process",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 'p'
		},
		{
			.name = NULL
		}
	};
	static const char *opts = "f:o:i:b:s:tp";

	long i;
	int c;

	while ((c = getopt_long(argc, argv, opts, long_opts, NULL)) >= 0) {
		switch (c) {
		case 'f':
			input_file_name = optarg;
			break;
		case 'o':
			output_file_name = optarg;
			break;
		case 'i':
			i = atol(optarg);
			if (i <= 0) {
				ERR("Time interval must be positive\n");
				return 1;
			}
			min_time_interval = i;
			break;
		case 'b':
			i = atol(optarg);
			if (i <= 0) {
				ERR("Batch size must be positive\n");
				return 1;
			}
			min_batch_size = i;
			break;
		case 's':
			i = atol(optarg);
			if (i <= 0) {
				ERR("Sector size must be positive\n");
				return 1;
			}
			sector_size = i;
			break;
		case 't':
			binary = 0;
			break;
		case 'p':
			per_process = 1;
			break;
		default:
			show_usage(argv[0]);
			return 1;
		}
	}
	return 0;
}

static int blk_io_trace_to_cpu(struct blk_io_trace *trace)
{
	if ((trace->magic & 0xFFFFFF00ul) == BLK_IO_TRACE_MAGIC)
		return 0;

	trace->magic = __bswap_32(trace->magic);
	if ((trace->magic & 0xFFFFFF00ul) == BLK_IO_TRACE_MAGIC) {
		ERR("Bad blkio event\n");
		return 1;
	}

	trace->time = __bswap_64(trace->time);
	trace->sector = __bswap_64(trace->sector);
	trace->bytes = __bswap_32(trace->bytes);
	trace->action = __bswap_32(trace->action);
	trace->pdu_len = __bswap_16(trace->pdu_len);
	trace->pid = __bswap_32(trace->pid);
	/* Other fields aren't interesting so far */
	return 0;
}

/**
 * blkio_event_read - reads struct blk_io_trace and converts
 * it to a struct blkio_event.
 *
 * fd - input file descriptor
 * event - blkio_event to read to
 *
 * Returns 0, if succes.
 */
static int blkio_event_read(int fd, struct blkio_event *event)
{
	struct blk_io_trace trace;
	size_t to_skip;

	if (myread(fd, (void *)&trace, sizeof(trace)))
		return 1;

	if (blk_io_trace_to_cpu(&trace))
		return 1;

	to_skip = trace.pdu_len;
	while (to_skip) {
		char buf[256];

		if (myread(fd, buf, MIN(to_skip, sizeof(buf))))
			return 1;
		to_skip -= MIN(to_skip, sizeof(buf)); 
	}

	event->time = trace.time;
	event->sector = trace.sector;
	event->length = (trace.bytes + sector_size - 1) / sector_size;
	event->action = trace.action;
	event->pid = per_process ? trace.pid : 0;
	return 0;
}

static int is_queue_event(const struct blkio_event *event)
{
	return ((event->action & 0xFFFF) == __BLK_TA_QUEUE) &&
		(event->action & BLK_TC_ACT(BLK_TC_QUEUE));
}

static int is_complete_event(const struct blkio_event *event)
{
	return ((event->action & 0xFFFF) == __BLK_TA_COMPLETE) &&
		(event->action & BLK_TC_ACT(BLK_TC_COMPLETE));
}

static int is_write_event(const struct blkio_event *event)
{
	return (event->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;
}

static int accept_event(const struct blkio_event *event)
{
	if (!event->length)
		return 0;

	return is_queue_event(event) || is_complete_event(event);
}

static int blkio_event_time_compare(const struct blkio_event *l,
			const struct blkio_event *r)
{
	if (l->time < r->time)
		return -1;
	if (l->time > r->time)
		return 1;
	return 0;
}

static int blkio_event_offset_compare(const struct blkio_event *l,
			const struct blkio_event *r)
{
	if (l->sector < r->sector)
		return -1;
	if (l->sector > r->sector)
		return 1;
	return 0;
}

static int blkio_event_pid_compare(const struct blkio_event *l,
			const struct blkio_event *r)
{
	if (l->pid < r->pid)
		return -1;
	if (l->pid > r->pid)
		return 1;
	return 0;
}

static int blkio_event_pid_time_compare(const struct blkio_event *l,
			const struct blkio_event *r)
{
	const int ret = blkio_event_pid_compare(l, r);
	if (ret)
		return ret;
	return blkio_event_time_compare(l, r);
}

/**
 * blkio_events_sort_by_offset - sort events by offset in ascending order
 */
static void blkio_events_sort_by_offset(struct blkio_event *events, size_t size)
{
	sort(events, size, &blkio_event_offset_compare);
}

/**
 * blkio_events_sort_by_pid_and_time - sort events by pair (pid, time) in
 *                                     ascending order.
 */
static void blkio_events_sort_by_pid_time(struct blkio_event *events,
			size_t size)
{
	sort(events, size, &blkio_event_pid_time_compare);
}

static int blkio_stats_dump(int fd, const struct blkio_stats *stats)
{
	unsigned long long first = ~0ull, last = 0ull;
	char buffer[512];

	if (stats->reads + stats->writes == 0)
		return 0;

	if (binary)
		return mywrite(fd, (const char *)stats, sizeof(*stats));

	if (stats->reads) {
		first = MIN(first, stats->reads_layout.first_sector);
		last = MAX(last, stats->reads_layout.last_sector);
	}

	if (stats->writes) {
		first = MIN(first, stats->writes_layout.first_sector);
		last = MAX(last, stats->writes_layout.last_sector);
	}

	snprintf(buffer, 512, "pid=%lu begin=%llu end=%llu "
				"inversions=%llu reads=%lu writes=%lu "
				"avg_iodepth=%lu avg_batch=%lu "
				"first_sec=%llu last_sec=%llu\n",
				(unsigned long)stats->pid,
				(unsigned long long)stats->begin_time,
				(unsigned long long)stats->end_time,
				(unsigned long long)stats->inversions,
				(unsigned long)stats->reads,
				(unsigned long)stats->writes,
				(unsigned long)stats->iodepth,
				(unsigned long)stats->batch,
				first, last);

	return mywrite(fd, buffer, strlen(buffer));
}

/**
 * __ci_merge - merges two sorted arrays and count number of
 *              inversions. Place result in buf array, so it
 *              it should be of size at least lsz + rsz.
 *
 * NOTE: buf MUST not overlap with l or r.
 */
static unsigned long long __ci_merge(struct blkio_event *l, size_t lsz,
			struct blkio_event *r, size_t rsz,
			struct blkio_event *buf)
{
	unsigned long long invs = 0;
	size_t i = 0, j = 0;

	while (i != lsz && j != rsz) {
		if (r[j].sector < l[i].sector) {
			memcpy(buf + i + j, r + j, sizeof(*r));
			invs += lsz - i;
			++j;
		} else {
			memcpy(buf + i + j, l + i, sizeof(*l));
			++i;
		}
	}

	memcpy(buf + i + j, l + i, (lsz - i) * sizeof(*l));
	memcpy(buf + i + j, r + j, (rsz - j) * sizeof(*r));
	return invs;
}

/**
 * __ci_merge_sort - sorts events by sector and counts number of
 *                   inversions.
 *
 * events - array of events to sort and count inversions
 * size - number of items in events
 * buf - buffer at least as large as events array.
 *
 * NOTE: buf MUST not overlap with events.
 */
static unsigned long long __ci_merge_sort(struct blkio_event *events,
			size_t size, struct blkio_event *buf)
{
	const size_t half = size / 2;
	unsigned long long invs = 0;

	if (size < 2)
		return 0;

	invs = __ci_merge_sort(events, half, buf);
	invs += __ci_merge_sort(events + half, size - half, buf);
	invs += __ci_merge(events, half, events + half, size - half, buf);
	memcpy(events, buf, size * sizeof(*buf));
	return invs;
}

static unsigned ilog2(unsigned long long x)
{
	unsigned power = 0;
	while (x >>= 1)
		++power;
	return power;
}

/**
 * __account_disk_layout - account information about block size, first and
 *                         last accessed sectors, size of merged blocks and
 *                         distance between merged blocks.
 */
static void __account_disk_layout(struct blkio_disk_layout *layout,
			const struct blkio_event *events, size_t size)
{
	__u32 *ss = layout->io_size;
	__u32 *ms = layout->merged_size;
	__u32 *so = layout->spot_offset;
	unsigned long long begin, end;
	unsigned long long off, len;
	size_t i;

	if (!size)
		return;

	begin = events[0].sector;
	end = begin + events[0].length;
	layout->first_sector = begin;
	for (i = 0; i != size; ++i) {
		off = events[i].sector;
		len = events[i].length;

		assert(len && "Empty operations aren't permitted here");

		++ss[MIN(ilog2(len), SECTOR_SIZE_BITS - 1)];
		if (off > end) {
			++ms[MIN(ilog2(end - begin), SECTOR_SIZE_BITS - 1)];
			++so[MIN(ilog2(off - end), SPOT_OFFSET_BITS - 1)];

			begin = off;
			end = begin + len;
		}
		end = MAX(end, off + len);
	}

	layout->last_sector = end;
	++ms[MIN(ilog2(end - begin), SECTOR_SIZE_BITS - 1)];
}

static int account_disk_layout_stats(struct blkio_stats *stats,
			const struct blkio_event *events, size_t size)
{
	struct blkio_event *buffer = calloc(2 * size, sizeof(*events));
	size_t i, j;

	if (!buffer) {
		ERR("Cannot allocate buffer for merge sort\n");
		return 1;
	}

	for (i = 0, j = 0; i != size; ++i) {
		if (!is_queue_event(events + i))
			continue;
		memcpy(buffer + j++, events + i, sizeof(*buffer));
	}
	stats->inversions = __ci_merge_sort(buffer, j, buffer + j);

	for (i = 0, j = 0; i != size; ++i) {
		if (!is_queue_event(events + i) || is_write_event(events + i))
			continue;
		memcpy(buffer + j++, events + i, sizeof(*buffer));
	}
	blkio_events_sort_by_offset(buffer, j);
	__account_disk_layout(&stats->reads_layout, buffer, j);

	for (i = 0, j = 0; i != size; ++i) {
		if (!is_queue_event(events + i) || !is_write_event(events + i))
			continue;
		memcpy(buffer + j++, events + i, sizeof(*buffer));
	}
	blkio_events_sort_by_offset(buffer, j);
	__account_disk_layout(&stats->writes_layout, buffer, j);

	free(buffer);
	return 0;
}

static int account_general_stats(struct blkio_stats *stats,
			const struct blkio_event *events, size_t size)
{
	unsigned long total_iodepth = 0, iodepth = 0, count = 0;
	unsigned long long begin = ~0ull, end = 0;
	unsigned long reads = 0, writes = 0, rw_bursts = 0;
	size_t i;

	for (i = 0; i != size; ++i) {
		if (is_queue_event(events + i)) {
			if (is_write_event(events + i))
				++writes;
			else
				++reads;
			++iodepth;
			begin = MIN(begin, events[i].time);
			end = MAX(end, events[i].time);
		} else {
			if (i && is_queue_event(events + i - 1)) {
				total_iodepth += iodepth;
				++rw_bursts;
				++count;
			}
			if (iodepth)
				--iodepth;
		}
	}

	if (reads + writes == 0)
		return 0;

	if (is_queue_event(events + size - 1))
		++rw_bursts;

	stats->batch = (reads + writes + rw_bursts - 1) / rw_bursts;

	if (iodepth) {
		total_iodepth += iodepth;
		++count;
	}

	stats->iodepth = MAX(1, (total_iodepth + count - 1) / count);
	stats->begin_time = begin;
	stats->end_time = end;
	stats->reads = reads;
	stats->writes = writes;

	return 0;
}

static int account_events(int fd, const struct blkio_event *events,
			size_t size)
{
	struct blkio_stats stats;

	if (!size)
		return 0;

	memset(&stats, 0, sizeof(stats));
	stats.pid = events->pid;

	if (account_general_stats(&stats, events, size))
		return 1;

	if (account_disk_layout_stats(&stats, events, size))
		return 1;

	return blkio_stats_dump(fd, &stats);
}

struct blkio_node {
	struct rb_node link;
	struct blkio_event event;
};

static struct object_cache *blkio_node_cache;

static struct blkio_queue_node *blkio_node_alloc(void)
{
	struct blkio_queue_node *node = object_cache_alloc(blkio_node_cache);

	if (!node)
		return 0;

	memset(node, 0, sizeof(*node));
	return node;
}

static void blkio_node_free(struct blkio_queue_node *node)
{
	object_cache_free(blkio_node_cache, node);
}

static struct blkio_queue_node *blkio_queue_lower(struct blkio_queue *queue,
			unsigned long long sector)
{
	struct blkio_queue_node *low = 0;
	struct blkio_queue_node *node;
	struct rb_node *p = queue->rb_root.rb_node;

	while (p) {
		node = rb_entry(p, struct blkio_queue_node, rb_node);

		if (node->event.sector < sector) {
			p = p->rb_right;
		} else {
			low = node;
			p = p->rb_left;
		}
	}
	return low;
}

static struct blkio_queue_node *blkio_queue_next(struct blkio_queue_node *node)
{
	struct rb_node *next = rb_next(&node->rb_node);

	if (!next)
		return 0;

	return rb_entry(next, struct blkio_queue_node, rb_node);
}

static void __blkio_queue_insert(struct blkio_queue *queue,
			struct blkio_queue_node *node)
{
	const unsigned long long sector = node->event.sector;

	struct rb_node **p = &queue->rb_root.rb_node;
	struct rb_node *parent = 0;
	struct blkio_queue_node *io;

	while (*p) {
		parent = *p;
		io = rb_entry(parent, struct blkio_queue_node, rb_node);

		if (sector < io->event.sector)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	rb_link_node(&node->rb_node, parent, p);
	rb_insert_color(&node->rb_node, &queue->rb_root);
	++queue->size;
}

static int blkio_queue_insert(struct blkio_queue *queue,
			struct blkio_event *event)
{
	unsigned long long from, to;
	struct blkio_queue_node *pos, *node;
	struct rb_node *list = 0;
	int ret = 0, write;

	if (is_queue_event(event)) {
		node = blkio_node_alloc();
		if (!node) {
			ERR("Cannot allocate blkio_queue_node\n");
			return 1;
		}
		node->event = *event;
		__blkio_queue_insert(queue, node);
		return 0;
	}

	from = event->sector;
	to = from + event->length;
	write = is_write_event(event);

	pos = blkio_queue_lower(queue, from);
	for (; pos && pos->event.sector < to; pos = blkio_queue_next(pos)) {
		const unsigned long long begin = pos->event.sector;
		const unsigned long long end = begin + pos->event.length;

		if (to < end
				|| is_complete_event(&pos->event)
				|| is_write_event(&pos->event) != write)
			continue;

		node = blkio_node_alloc();
		if (!node) {
			ERR("Cannot allocate blkio_queue_node\n");
			ret = 1;
			break;
		}
		node->event = *event;
		node->event.pid = pos->event.pid;
		node->event.sector = pos->event.sector;
		node->event.length = pos->event.length;
		node->rb_node.rb_right = list;
		list = &node->rb_node;
	}

	while (list) {
		node = rb_entry(list, struct blkio_queue_node, rb_node);
		list = list->rb_right;
		__blkio_queue_insert(queue, node);
	}
	return ret;
}

static void __blkio_queue_clear(struct rb_node *node)
{
	struct blkio_queue_node *io;

	while (node) {
		io = rb_entry(node, struct blkio_queue_node, rb_node);
		__blkio_queue_clear(node->rb_right);
		node = node->rb_left;
		blkio_node_free(io);
	}
}

static void blkio_queue_clear(struct blkio_queue *queue)
{
	__blkio_queue_clear(queue->rb_root.rb_node);
	memset(queue, 0, sizeof(*queue));
}

static int blkio_queue_handle_events(int fd, struct blkio_queue *queue)
{
	struct blkio_queue_node *node;
	struct rb_node *pos;
	int ret = 0;

	struct blkio_event *events = calloc(queue->size,
				sizeof(struct blkio_event));
	unsigned long size = 0, i, min_i;

	if (!events) {
		ERR("Cannot allocate array of blkio_event\n");
		return 1;
	}

	pos = rb_first(&queue->rb_root);
	while (pos) {
		node = rb_entry(pos, struct blkio_queue_node, rb_node);
		events[size++] = node->event;
		pos = rb_next(pos);
	}
	blkio_queue_clear(queue);

	/**
	 * Things a bit complicated when we take time into account, we want
	 * PID with minimum start time goes first, so we find it first, and
	 * then dump stats in two steps: starting from min PID and then from
	 * first PID in the array.
	 */
	blkio_events_sort_by_pid_time(events, size);
	min_i = 0;
	for (i = 0; !ret && i != size; ) {
		const unsigned long pid = events[i].pid;
		const unsigned long j = i;

		for (; i != size && events[i].pid == pid; ++i);
		if (events[j].time < events[min_i].time)
			min_i = j;
	}

	for (i = min_i; !ret && i != size; ) {
		const unsigned long pid = events[i].pid;
		const unsigned long j = i;

		for (; i != size && events[i].pid == pid; ++i);
		ret = account_events(fd, events + j, i - j);
	}

	for (i = 0; !ret && i != min_i; ) {
		const unsigned long pid = events[i].pid;
		const unsigned long j = i;

		for (; i != size && events[i].pid == pid; ++i);
		ret = account_events(fd, events + j, i - j);
	}

	free(events);
	return ret;
}

static void blkrecord(int ifd, int ofd)
{
	const unsigned long long NS = 1000000ull;
	const unsigned long long TI = NS * min_time_interval;
	const unsigned long BS = min_batch_size;

	unsigned long long start_time = 0ull;
	unsigned long long end_time = 0ull;

	struct blkio_queue queue;
	struct blkio_event event;

	memset(&queue, 0, sizeof(queue));

	while (!blkio_event_read(ifd, &event)) {
		if (!accept_event(&event))
			continue;

		if (event.time < start_time) {
			ERR("Out of order event, skip it\n");
			continue;
		}

		if (blkio_queue_insert(&queue, &event))
			break;

		end_time = MAX(end_time, event.time);
		if (queue.size < BS && end_time - start_time < TI)
			continue;

		start_time = end_time;
		if (blkio_queue_handle_events(ofd, &queue))
			break;
	}

	if (queue.size)
		blkio_queue_handle_events(ofd, &queue);
}

int main(int argc, char **argv)
{
	int ifd = 0, ofd = 1;

	if (parse_args(argc, argv))
		return 1;

	if (input_file_name && strcmp("-", input_file_name)) {
		ifd = open(input_file_name, 0);
		if (ifd < 0) {
			perror("Cannot open input file");
			return 1;
		}
	}

	if (output_file_name && strcmp("-", output_file_name)) {
		ofd = open(output_file_name, O_CREAT | O_TRUNC | O_WRONLY,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
		if (ofd < 0) {
			close(ifd);
			perror("Cannot open output file");
			return 1;
		}
	}

	blkio_node_cache = object_cache_create(sizeof(struct blkio_queue_node));
	if (blkio_node_cache) {
		blkrecord(ifd, ofd);
		object_cache_destroy(blkio_node_cache);
	} else {
		ERR("Cannot create blkio_queue_node cache\n");
	}

	close(ofd);
	close(ifd);

	return 0;
}
