#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <byteswap.h>

#include "blktrace_api.h"
#include "blkrecord.h"
#include "algorithm.h"
#include "blkqueue.h"
#include "file_io.h"
#include "common.h"
#include "debug.h"

static const unsigned sector_size = 512u;

static const char *input_file_name;
static const char *output_file_name;
static unsigned min_time_interval = 1000u;
static int binary = 1;
static int per_process = 0, per_cpu = 0;

static volatile sig_atomic_t done = 0;

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		"[-f <input file>    | --file=<input file>]\n" \
		"[-o <output file>   | --output=<output file>]\n" \
		"[-i <time interval> | --interval=<time interval>]\n" \
		"[-c                 | --per-cpu]\n" \
		"[-t                 | --text]\n" \
		"[-p                 | --per-process]\n" \
		"\t-f Use specified blktrace file. Default: stdin\n" \
		"\t-o Ouput file. Default: stdout\n" \
		"\t-i Minimum sampling time interval in ms. Default: 1000\n" \
		"\t-c Gather per CPU stats.\n" \
		"\t-t Output in text format, by default output is binary.\n" \
		"\t-p Gather per process stats.\n";

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
			.name = "per-cpu",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 'c'
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
	static const char *opts = "f:o:i:ctp";

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
		case 'c':
			per_cpu = 1;
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
	trace->cpu = __bswap_32(trace->cpu);
	/* Other fields aren't interesting so far */
	return 0;
}

/**
 * blk_io_trace_read - reads struct blk_io_trace
 *
 * ctx - initialized blkio_record_context
 * trace - blk_io_trace buffer to read to
 *
 * Returns 0, if succes.
 */
static int blk_io_trace_read(struct blkio_record_context *ctx,
			struct blk_io_trace *trace)
{
	size_t to_skip;

	if (myread(ctx->ifd, (void *)trace, sizeof(*trace)))
		return 1;

	if (blk_io_trace_to_cpu(trace))
		return 1;

	to_skip = trace->pdu_len;
	while (to_skip) {
		char buf[512];

		if (myread(ctx->ifd, buf, MIN(to_skip, sizeof(buf))))
			return 1;
		to_skip -= MIN(to_skip, sizeof(buf)); 
	}
	return 0;
}

static int blk_io_trace_queue_event(const struct blk_io_trace *trace)
{
	return ((trace->action & BLK_TC_ACT(BLK_TC_QUEUE)) &&
		((trace->action & 0xFFFFu) == __BLK_TA_QUEUE));
}

static int blk_io_trace_complete_event(const struct blk_io_trace *trace)
{
	return ((trace->action & 0xFFFFu) == __BLK_TA_ISSUE) &&
		(trace->action & BLK_TC_ACT(BLK_TC_ISSUE));
}

static int blk_io_trace_write_event(const struct blk_io_trace *trace)
{
	return (trace->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;
}

static int blk_io_trace_sync_event(const struct blk_io_trace *trace)
{
	return (trace->action & BLK_TC_ACT(BLK_TC_SYNC)) != 0;
}

static int blk_io_trace_accept_event(const struct blk_io_trace *trace)
{
	if (!trace->bytes)
		return 0;

	return blk_io_trace_queue_event(trace) ||
				blk_io_trace_complete_event(trace);
}

static unsigned char blk_io_trace_type(const struct blk_io_trace *trace)
{
	unsigned char type = 0;

	if (blk_io_trace_queue_event(trace))
		type |= QUEUE_MASK;
	if (blk_io_trace_write_event(trace))
		type |= WRITE_MASK;
	if (blk_io_trace_sync_event(trace))
		type |= SYNC_MASK;
	return type;
}

static int blkio_event_offset_compare(const struct blkio_event *l,
			const struct blkio_event *r)
{
	if (l->from < r->from)
		return -1;
	if (l->from > r->from)
		return 1;
	return 0;
}

/**
 * blkio_events_sort_by_offset - sort events by offset in ascending order
 */
static void blkio_events_sort_by_offset(struct blkio_event *events, size_t size)
{ sort(events, size, &blkio_event_offset_compare); }

static int mygzwrite(gzFile zfd, const char *buf, size_t size)
{
	size_t written = 0;

	while (written != size) {
		int ret = gzwrite(zfd, buf + written, size - written);

		if (!ret) {
			int gzerr = 0;
			const char *msg = gzerror(zfd, &gzerr);

			if (gzerr != Z_ERRNO)
				ERR("zlib write failed: %s\n", msg);
			else
				perror("Write failed");
			return 1;
		}
		written += ret;
	}
	return 0;
}

static int blkio_stats_dump(struct blkio_record_context *ctx,
			const struct blkio_stats *st)
{
	unsigned long long first = ~0ull, last = 0ull;
	char buffer[512];

	if (st->reads + st->writes == 0)
		return 0;

	if (binary)
		return mygzwrite(ctx->zofd, (const char *)st, sizeof(*st));

	if (st->reads) {
		first = MIN(first, st->reads_layout.first_sector);
		last = MAX(last, st->reads_layout.last_sector);
	}

	if (st->writes) {
		first = MIN(first, st->writes_layout.first_sector);
		last = MAX(last, st->writes_layout.last_sector);
	}

	snprintf(buffer, 512, "pid=%lu cpu=%lu begin=%llu end=%llu "
				"inversions=%llu reads=%lu writes=%lu "
				"avg_iodepth=%lu avg_batch=%lu "
				"first_sec=%llu last_sec=%llu\n",
				(unsigned long)st->pid,
				(unsigned long)st->cpu,
				(unsigned long long)st->begin_time,
				(unsigned long long)st->end_time,
				(unsigned long long)st->inversions,
				(unsigned long)st->reads,
				(unsigned long)st->writes,
				(unsigned long)st->iodepth,
				(unsigned long)st->batch,
				first, last);

	return mywrite(ctx->ofd, buffer, strlen(buffer));
}

struct blkio_run {
	const struct blkio_event *first;
	const struct blkio_event *last;
};

static int blkio_run_offset_compare(const struct blkio_run *l,
			const struct blkio_run *r)
{
	if (l->last->from < r->first->from)
		return -1;
	if (l->first->from > r->last->from)
		return 1;
	return 0;
}

/**
 * __ci_merge - merges two sorted arrays and count number of
 *              inversions. Place result in buf array, so it
 *              it should be of size at least lsz + rsz.
 *
 * NOTE: buf MUST not overlap with l or r.
 */
static unsigned long long __ci_merge(struct blkio_run *l, size_t lsz,
			struct blkio_run *r, size_t rsz,
			struct blkio_run *buf)
{
	unsigned long long invs = 0;
	size_t i = 0, j = 0;

	while (i != lsz && j != rsz) {
		if (blkio_run_offset_compare(r + j, l + i) < 0) {
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
static unsigned long long __ci_merge_sort(struct blkio_run *events,
			size_t size, struct blkio_run *buf)
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
 * __account_disk_layout - gather information about IO size, first and
 *                         last accessed sectors, distance between IOs.
 *
 * NOTE: events array must be sorted by sector field
 */
static void __account_disk_layout(struct blkio_disk_layout *layout,
			const struct blkio_event *events, size_t size)
{
	__u32 *ss = layout->io_size;
	__u32 *so = layout->io_offset;
	unsigned long long begin, end;
	size_t i;

	if (!size)
		return;

	begin = events[0].from;
	end = events[0].to;
	layout->first_sector = begin;
	for (i = 0; i != size; ++i) {
		const unsigned long long off = events[i].from;
		const unsigned long len = events[i].to - events[i].from;

		if (off > end)
			++so[MIN(1 + ilog2(off - end), IO_OFFSET_BITS - 1)];
		else
			++so[0];

		if (IS_SYNC(events[i].type))
			++layout->sync;

		++ss[MIN(ilog2(len), IO_SIZE_BITS - 1)];
		end = MAX(end, off + len);
	}
	layout->last_sector = end;
}

static size_t fill_runs(const struct blkio_event *events, size_t size,
			struct blkio_run *runs)
{
	size_t count = 1, i;

	if (!size)
		return 0;

	runs[0].first = runs[0].last = events;
	for (i = 1; i != size; ++i) {
		const unsigned long long pbeg = events[i - 1].from;
		const unsigned long long pend = events[i - 1].to;

		const unsigned long long beg = events[i].from;

		if (pbeg <= beg && pend >= beg) {
			runs[count - 1].last = events + i;
		} else {
			runs[count].first = runs[count].last = events + i;
			++count;
		}
	}

	return count;
}

static int account_disk_layout_stats(struct blkio_stats *stats,
			const struct blkio_event *events, size_t size)
{
	struct blkio_event *buf = calloc(size, sizeof(*events));
	struct blkio_run *runs;
	size_t total;
	size_t i, j, k;

	if (!buf) {
		ERR("Cannot allocate buffer for queue events\n");
		return 1;
	}

	runs = calloc(size * 2, sizeof(*runs));
	if (!runs) {
		ERR("Cannot allocate buffer for event runs\n");
		free(runs);
		return 1;
	}

	for (i = 0, j = 0; i != size; ++i) {
		const struct blkio_event *e = events + i;

		if (!IS_QUEUE(e->type))
			continue;
		memcpy(buf + j++, e, sizeof(*buf));
	}
	total = fill_runs(buf, j, runs);
	stats->inversions = __ci_merge_sort(runs, total, runs + total);

	for (i = 0, j = 0; i != size; ++i) {
		const struct blkio_event *e = events + i;

		if (!IS_QUEUE(e->type) || !IS_WRITE(e->type))
			continue;
		memcpy(buf + j++, e, sizeof(*buf));
	}
	blkio_events_sort_by_offset(buf, j);
	__account_disk_layout(&stats->writes_layout, buf, j);

	for (i = 0, k = j; i != size; ++i) {
		const struct blkio_event *e = events + i;

		if (!IS_QUEUE(e->type) || IS_WRITE(e->type))
			continue;
		memcpy(buf + k++, e, sizeof(*buf));
	}
	blkio_events_sort_by_offset(buf + j, k - j);
	__account_disk_layout(&stats->reads_layout, buf + j, k - j);

	free(runs);
	free(buf);
	return 0;
}

static int account_general_stats(struct blkio_stats *stats,
			const struct blkio_event *events, size_t size)
{
	static unsigned long long BURST_TIME = 1000000ull;
	static unsigned long BURST_MAX_SIZE = 1024ul;

	unsigned long long begin = ~0ull, end = 0;
	unsigned long long burst_end_time = 0, total_iodepth = 0;
	unsigned long reads = 0, writes = 0, queues;
	unsigned long burst = 0, bursts = 0;
	unsigned long iodepth = 0;
	size_t i;

	for (i = 0; i != size; ++i) {
		if (burst == BURST_MAX_SIZE || burst_end_time < events[i].time)
			burst = 0;

		if (IS_QUEUE(events[i].type)) {
			if (IS_WRITE(events[i].type)) ++writes;
			else ++reads;

			if (!burst) {
				burst_end_time = events[i].time + BURST_TIME;
				++bursts;
			}

			total_iodepth += ++iodepth;
			++burst;

			begin = MIN(begin, events[i].time);
			end = MAX(end, events[i].time);
		} else {
			if (iodepth)
				--iodepth;
		}
	}

	queues = reads + writes;
	if (!queues)
		return 0;

	stats->batch = (queues + bursts - 1) / bursts;
	stats->iodepth = (total_iodepth + queues - 1) / queues;
	stats->begin_time = begin;
	stats->end_time = end;
	stats->reads = reads;
	stats->writes = writes;

	return 0;
}

static int account_events(struct blkio_record_context *ctx,
			const struct blkio_event *events, size_t size)
{
	struct blkio_stats stats;

	if (!size)
		return 0;

	memset(&stats, 0, sizeof(stats));
	stats.pid = events->pid;
	stats.cpu = events->cpu;

	if (account_general_stats(&stats, events, size))
		return 1;

	if (account_disk_layout_stats(&stats, events, size))
		return 1;

	return blkio_stats_dump(ctx, &stats);
}

static int process_info_append(struct process_info *pi,
			const struct blkio_event *event)
{
	static const unsigned long grow_n = 3;
	static const unsigned long grow_d = 2;

	if (pi->size == pi->capacity) {
		unsigned long new_capacity = (pi->capacity * grow_n) / grow_d;
		struct blkio_event *events = realloc(pi->events,
					sizeof(*event) * new_capacity);

		if (!events) {
			ERR("process_info events reallocation failed\n");
			return 1;
		}

		pi->capacity = new_capacity;
		pi->events = events;
	}
	pi->events[pi->size++] = *event;
	return 0;
}

static struct process_info *process_info_alloc(void)
{
	static unsigned long CAPACITY = 512;

	struct process_info *pi = malloc(sizeof(struct process_info));

	if (!pi) {
		ERR("Process info allocation failed\n");
		return 0;
	}

	pi->events = calloc(CAPACITY, sizeof(*pi->events));
	if (!pi->events) {
		ERR("blkio_event per process array allocation failed\n");
		free(pi);
		return 0;
	}

	pi->capacity = CAPACITY;
	pi->size = 0;
	return pi;
}

static void process_info_free(struct process_info *pi)
{
	free(pi->events);
	free(pi);
}

static void process_info_dump(struct blkio_record_context *ctx,
			struct process_info *pi)
{ account_events(ctx, pi->events, pi->size); }

static void blkio_record_context_dump(struct blkio_record_context *ctx,
			unsigned long long time)
{
	static const unsigned long long NS = 1000000ull;
	const unsigned long long TI = NS * min_time_interval;

	struct list_head *head = &ctx->head;
	struct list_head *pos = head->next;

	while (pos != head) {
		struct process_info *pi;

		pi = PROCESS_INFO(pos);
		pos = pos->next;

		if (pi->events->time + TI > time)
			break;

		process_info_dump(ctx, pi);
		list_unlink(&pi->head);
		process_info_free(pi);
	}
}

static void blkio_event_handle_queue(struct blkio_record_context *ctx,
			const struct blkio_event *event)
{
	struct blkio_queue *q = IS_WRITE(event->type)
				? &ctx->write : &ctx->read;
	struct blkio *io = blkio_alloc(q);
	struct list_head *head, *pos;
	int found;

	if (!io)
		return;

	io->from = event->from;
	io->to = event->to;
	io->pid = event->pid;
	io->cpu = event->cpu;

	if (blkio_insert(q, io)) {
		blkio_free(q, io);
		return;
	}

	head = &ctx->head;
	pos = head->next;
	found = 0;

	for (; pos != head; pos = pos->next) {
		struct process_info *pi = PROCESS_INFO(pos);

		if (pi->pid == event->pid && pi->cpu == event->cpu) {
			process_info_append(pi, event);
			found = 1;
			break;
		}
	}

	if (!found) {
		struct process_info *pi = process_info_alloc();

		if (!pi)
			return;

		pi->pid = event->pid;
		pi->cpu = event->cpu;
		list_link_before(head, &pi->head);
		process_info_append(pi, event);
	}
}

static void blkio_event_handle_complete(struct blkio_record_context *ctx,
			const struct blkio_event *event)
{
	struct blkio_queue *q = IS_WRITE(event->type)
				? &ctx->write : &ctx->read;
	struct blkio *first, *last;

	blkio_lookup(q, event->from, event->to, &first, &last);

	while (first != last) {
		struct list_head *head, *pos;
		struct blkio *queue = first;

		const unsigned long long from = queue->from;
		const unsigned long long to = queue->to;
		const unsigned long pid = queue->pid;
		const unsigned long cpu = queue->cpu;

		first = BLKIO(rb_next(&first->rb_node));

		if (from < event->from && to > event->to) {
			struct blkio *tail = blkio_alloc(q);

			queue->to = event->from;

			if (!tail)
				continue;

			tail->from = event->to;
			tail->to = to;
			tail->pid = pid;
			tail->cpu = cpu;

			if (blkio_insert(q, tail)) {
				ERR("Cannot insert tail after split\n");
				blkio_free(q, tail);
			}
		} else if (from >= event->from && to <= event->to) {
			blkio_remove(q, queue);
		} else if (from < event->from) {
			queue->to = event->from;
		} else if (to > event->to) {
			queue->from = event->to;
		}
		
		head = &ctx->head;
		pos = head->next;

		for (; pos != head; pos = pos->next) {
			struct process_info *pi = PROCESS_INFO(pos);

			if (pi->pid == queue->pid && pi->cpu == queue->cpu) {
				process_info_append(pi, event);
				break;
			}
		}
	}
}

static void blkio_event_handle(struct blkio_record_context *ctx,
			const struct blkio_event *event)
{
	blkio_record_context_dump(ctx, event->time);
	if (IS_QUEUE(event->type))
		blkio_event_handle_queue(ctx, event);
	else
		blkio_event_handle_complete(ctx, event);
}

static void blkrecord(struct blkio_record_context *ctx)
{
	unsigned long events_total = 0, queues = 0;
	struct blk_io_trace trace;

	while (!done && !blk_io_trace_read(ctx, &trace)) {
		struct blkio_event event;

		if (!blk_io_trace_accept_event(&trace))
			continue;

		event.time = trace.time;
		event.from = trace.sector;
		event.to = event.from + MAX(1, trace.bytes / sector_size);
		event.pid = per_process ? trace.pid : 0;
		event.cpu = per_cpu ? trace.cpu : 0;
		event.type = blk_io_trace_type(&trace);


		if (IS_QUEUE(event.type))
			++queues;

		blkio_event_handle(ctx, &event);
		++events_total;
	}
	blkio_record_context_dump(ctx, ~0ull);
	ERR("total events processed: %lu\n", events_total);
	ERR("queues: %lu\n", queues);
	ERR("completes: %lu\n", events_total - queues);
}

static void handle_signal(int sig)
{
	(void)sig;
	done = 1;
}

int main(int argc, char **argv)
{
	struct blkio_record_context ctx;
	int ifd = 0, ofd = 1;
	gzFile zofd = NULL;

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

	if (binary) {
		zofd = gzdopen(ofd, "wb");

		if (!zofd) {
			ERR("Cannot allocate enough memory for zlib\n");
			close(ifd);
			close(ofd);
			return 1;
		}
	}


	signal(SIGINT, handle_signal);
	signal(SIGHUP, handle_signal);
	signal(SIGTERM, handle_signal);
	signal(SIGALRM, handle_signal);

	blkio_record_context_init(&ctx);
	ctx.zofd = zofd;
	ctx.ifd = ifd;
	ctx.ofd = ofd;
	blkrecord(&ctx);
	blkio_record_context_finit(&ctx);

	if (zofd)
		gzclose(zofd);
	else
		close(ofd);
	close(ifd);

	return 0;
}
