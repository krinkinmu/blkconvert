#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <byteswap.h>

#include "blktrace_api.h"
#include "blkrecord.h"
#include "algorithm.h"
#include "file_io.h"
#include "common.h"
#include "debug.h"

static const char *input_file_name;
static const char *output_file_name;
static unsigned long max_time_interval = 1000ul;
static unsigned long max_batch_size = 10000ul;
static unsigned long sector_size = 512ul;
static int binary = 1;

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		"[-f <input file>    | --file=<input file>]\n" \
		"[-o <output file>   | --output=<output file>]\n" \
		"[-i <time interval> | --interval=<time interval>]\n" \
		"[-b <batch size>    | --batch=<batch size>]\n" \
		"[-s <sector size>   | --sector=<sector size>]\n" \
		"[-t                 | --text]\n" \
		"\t-f Use specified blktrace file. Default: stdin\n" \
		"\t-o Ouput file. Default: stdout\n" \
		"\t-i Maximum sampling time interval in ms. Default: 1000\n" \
		"\t-b Maximum io batch size. Default: 10000\n" \
		"\t-s Sector size. Default: 512\n" \
		"\t-t Output in text format, by default output is binary.\n";

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
			.name = NULL
		}
	};
	static const char *opts = "f:o:i:b:t";

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
			max_time_interval = i;
			break;
		case 'b':
			i = atol(optarg);
			if (i <= 0) {
				ERR("Batch size must be positive\n");
				return 1;
			}
			max_batch_size = i;
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

	trace->time    = __bswap_64(trace->time);
	trace->sector  = __bswap_64(trace->sector);
	trace->bytes   = __bswap_32(trace->bytes);
	trace->action  = __bswap_32(trace->action);
	trace->pdu_len = __bswap_16(trace->pdu_len);
	/* Other fields aren't interesting so far */
	return 0;
}

struct blkio_event {
	unsigned long long time;
	unsigned long long sector;
	unsigned long      length;
	unsigned long      action;
};

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

		if (myread(fd, buf, MIN(to_skip, 256)))
			return 1;
		to_skip -= MIN(to_skip, 256); 
	}

	event->time    = trace.time;
	event->sector  = trace.sector;
	event->length = (trace.bytes + sector_size - 1) / sector_size;
	event->action  = trace.action;

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

static int accept_event(const struct blkio_event *event)
{
	/* Drop notify, SCSI and empty events */
	if (event->action & BLK_TC_ACT(BLK_TC_NOTIFY))
		return 0;

	if (event->action & BLK_TC_ACT(BLK_TC_PC))
		return 0;

	if (!event->length)
		return 0;

	return is_queue_event(event) || is_complete_event(event);
}

/**
 * blkio_events_read - read up to count interesting events. Event
 *                     is interesting if accept_event returns true.
 *
 * fd - input file descriptor
 * events - array of blkio_event structs
 * count - number of events to read
 *
 * Returns number of read events. If return value less than count
 * than error occured or reached end of file.
 */
static size_t blkio_events_read(int fd, struct blkio_event *events,
			size_t count)
{
	size_t size = 0;

	while (size != count && !blkio_event_read(fd, events + size)) {
		if (accept_event(events + size))
			++size;
	}
	return size;
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

/**
 * blkio_events_sort - sorts events by time in ascending order
 */
static void blkio_events_sort(struct blkio_event *events, size_t size)
{
	sort(events, size, &blkio_event_time_compare);
}

/**
 * blkio_events_find - searches first event with time equal or greater
 *                     than time. events array must be sorted by time.
 *                     Returns position of such event in array ot size,
 *                     if no such event found. (a. k. a. lower_bound).
 */
static size_t blkio_events_find(const struct blkio_event *events, size_t size,
			__u64 time)
{
	const struct blkio_event key = { .time = time };

	return lower_bound(events, size, key, &blkio_event_time_compare);
}

static int blkio_stats_dump(int fd, const struct blkio_stats *stats)
{
	char buffer[512];
	int ret;

	if (binary)
		return mywrite(fd, (const char *)stats, sizeof(*stats));

	#define STAT_FMT "%llu %llu %llu %llu %lu %lu %lu %lu %lu\n"
	ret = snprintf(buffer, 512, STAT_FMT,
				(unsigned long long)stats->q2q_time,
				(unsigned long long)stats->min_sector,
				(unsigned long long)stats->max_sector,
				(unsigned long long)stats->inversions,
				(unsigned long)stats->reads,
				(unsigned long)stats->writes,
				(unsigned long)stats->sectors,
				(unsigned long)stats->merged_sectors,
				(unsigned long)stats->iodepth);
	#undef STAT_FMT
	if (ret < 0) {
		ERR("Error while formating text output\n");
		return 1;
	}
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

/**
 * __cm_avg_block_size - merges contigous events and calculate average
 *                        size of merged block. Note that function makes
 *                        no difference between reads and writes, queue
 *                        and complete events.
 * 
 * events - array of events sorted by offset in ascending order
 * size - number of items in events.
 */
static unsigned long __cm_avg_merged_block_size(
			const struct blkio_event *events, size_t size)
{
	unsigned long long begin, end;
	unsigned long total_size = 0;
	size_t i, count = 0;

	if (!size)
		return 0;

	begin = events[0].sector;
	end = begin + events[0].length;
	for (i = 0; i != size; ++i) {
		const unsigned long long off = events[i].sector;
		const unsigned long len = events[i].length;

		if (off > end) {
			total_size += end - begin;
			++count;
			begin = off;
			end = off + len;
			continue;
		}
		end = MAX(end, off + len);
	}

	total_size += end - begin;
	++count;

	return total_size / count;
}

static int account_disk_layout_stats(struct blkio_stats *stats,
			const struct blkio_event *events, size_t size)
{
	struct blkio_event *buffer = calloc(2 * size, sizeof(*events));
	unsigned long long low = ~0ull, high = 0ull;
	unsigned long total_sectors = 0, count = 0;
	size_t i, j;

	if (!buffer) {
		ERR("Cannot allocate buffer for merge sort\n");
		return 1;
	}

	for (i = 0, j = 0; i != size; ++i) {
		if (!is_queue_event(events + i))
			continue;
		memcpy(buffer + j, events + i, sizeof(*buffer));
		total_sectors += events[i].length;
		++count;
		high = MAX(high, events[i].sector + events[i].length);
		low = MIN(low, events[i].sector);
		++j;
	}

	if (!j)
		return 0;

	stats->inversions = __ci_merge_sort(buffer, j, buffer + j);
	stats->merged_sectors = __cm_avg_merged_block_size(buffer, j);
	stats->sectors = total_sectors / count;
	stats->min_sector = low;
	stats->max_sector = high;
	free(buffer);
	return 0;
}

static int account_general_stats(struct blkio_stats *stats,
			const struct blkio_event *events, size_t size)
{
	unsigned long total_iodepth = 0, iodepth = 0, count = 0;
	unsigned long long begin = ~0ull, end = 0;
	unsigned long reads = 0, writes = 0;
	size_t i;

	for (i = 0; i != size; ++i) {
		if (is_queue_event(events + i)) {
			if (events[i].action & BLK_TC_ACT(BLK_TC_WRITE))
				++writes;
			else
				++reads;
			++iodepth;
			begin = MIN(begin, events[i].time);
			end = MAX(end, events[i].time);
		} else if (iodepth) {
			if (is_queue_event(events + i - 1)) {
				total_iodepth += iodepth;
				++count;
			}
			--iodepth;
		}
	}

	if (iodepth) {
		total_iodepth += iodepth;
		++count;
	}

	stats->iodepth = MAX(1, total_iodepth / count);
	stats->q2q_time = (end - begin) / (reads + writes);
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
	if (account_disk_layout_stats(&stats, events, size) ||
			account_general_stats(&stats, events, size))
		return 1;

	return blkio_stats_dump(fd, &stats);
}

static void blkrecord(int ifd, int ofd)
{
	const unsigned long long NS = 1000000ul;
	const unsigned long long TI = max_time_interval * NS;
	const unsigned long BS = max_batch_size;

	size_t size = 0, read = 0;
	unsigned long long time = 0;
	struct blkio_event *events = calloc(BS, sizeof(*events));

	if (!events) {
		ERR("Cannot allocate event buffer\n");
		return;
	}

	while ((read = blkio_events_read(ifd, events + size, BS - size))) {
		size_t count;

		size += read;
		blkio_events_sort(events, size);
		count = blkio_events_find(events, size, time);
		if (count) {
			ERR("Discarded %lu unordered requests\n",
						(unsigned long)count);
			size -= count;
			memmove(events, events + count, sizeof(*events) * size);
			continue;
		}

		count = blkio_events_find(events, size, events[0].time + TI);
		if (account_events(ofd, events, count)) {
			free(events);
			return;
		}
		time = events[count - 1].time;
		size -= count;
		memmove(events, events + count, sizeof(*events) * size);
	}


	while (size) {
		size_t count;

		count = blkio_events_find(events, size, events[0].time + TI);
		if (account_events(ofd, events, count)) {
			free(events);
			return;
		}
		size -= count;
		memmove(events, events + count, sizeof(*events) * size);
	}
	free(events);
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

	blkrecord(ifd, ofd);

	close(ofd);
	close(ifd);

	return 0;
}
