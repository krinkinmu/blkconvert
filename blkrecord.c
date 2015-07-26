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
static int binary = 1;

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		"[-f <input file>    | --file=<input file>]\n" \
		"[-o <output file>   | --output=<output file>]\n" \
		"[-i <time interval> | --interval=<time interval>]\n" \
		"[-b <batch size>    | --batch=<batch size>]\n" \
		"[-t                 | --text]\n" \
		"\t-f Use specified blktrace file. Default: stdin\n" \
		"\t-o Ouput file. Default: stdout\n" \
		"\t-i Maximum sampling time interval in ms. Default: 1000\n" \
		"\t-b Maximum io batch size. Default: 10000\n" \
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

struct blkio_event {
	__u64 time;
	__u64 sector;
	__u32 sectors;
	__u32 action;
};

static int trace_to_cpu(struct blk_io_trace *trace)
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

static int read_event(int ifd, struct blkio_event *event)
{
	const __u32 sector_size = 512;

	struct blk_io_trace trace;
	size_t to_skip;

	if (myread(ifd, (void *)&trace, sizeof(trace)))
		return 1;

	if (trace_to_cpu(&trace))
		return 1;

	to_skip = trace.pdu_len;
	while (to_skip) {
		char buf[256];

		if (myread(ifd, buf, MIN(to_skip, 256)))
			return 1;
		to_skip -= MIN(to_skip, 256); 
	}

	event->time    = trace.time;
	event->sector  = trace.sector;
	event->sectors = (trace.bytes + sector_size - 1) / sector_size;
	event->action  = trace.action;

	return 0;
}

static int queue_event(const struct blkio_event *event)
{
	return ((event->action & 0xFFFF) == __BLK_TA_QUEUE) &&
		(event->action & BLK_TC_ACT(BLK_TC_QUEUE));
}

static int complete_event(const struct blkio_event *event)
{
	return ((event->action & 0xFFFF) == __BLK_TA_COMPLETE) &&
		(event->action & BLK_TC_ACT(BLK_TC_COMPLETE));
}

static int accept_event(const struct blkio_event *event)
{
	if (event->action & BLK_TC_ACT(BLK_TC_NOTIFY))
		return 0;

	if (event->action & BLK_TC_ACT(BLK_TC_PC))
		return 0;

	if (!event->sectors)
		return 0;

	if (!queue_event(event) && !complete_event(event))
		return 0;

	return 1;
}

static size_t read_events(int ifd, struct blkio_event *events, size_t count)
{
	size_t size = 0;

	while (size != count && !read_event(ifd, events + size)) {
		if (accept_event(events + size))
			++size;
	}
	return size;
}

static int time_compare(const struct blkio_event *l,
			const struct blkio_event *r)
{
	if (l->time < r->time)
		return -1;
	if (l->time > r->time)
		return 1;
	return 0;
}

static void sort_events_by_time(struct blkio_event *events, size_t size)
{
	sort(events, size, &time_compare);
}

static size_t find_event_by_time(const struct blkio_event *events, size_t size,
			__u64 time)
{
	const struct blkio_event key = { .time = time };
	return lower_bound(events, size, key, &time_compare);
}

static int dump_stats(int ofd, const struct blkio_stats *stats)
{
	char buffer[512];
	int ret;

	if (!(stats->reads + stats->writes))
		return 0;

	if (binary)
		return mywrite(ofd, (const char *)stats, sizeof(*stats));

	#define STAT_FMT "%llu %llu %llu %llu %llu %lu %lu %lu %lu %lu\n"
	ret = snprintf(buffer, 512, STAT_FMT,
				(unsigned long long)stats->first_time,
				(unsigned long long)stats->last_time,
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
	return mywrite(ofd, buffer, strlen(buffer));
}

static __u64 merge_invs(struct blkio_event *lhs, size_t lcount,
			struct blkio_event *rhs, size_t rcount,
			struct blkio_event *buf)
{
	size_t l = 0, r = 0;
	__u64 invs = 0;

	while (l != lcount && r != rcount) {
		if (rhs[r].sector < lhs[l].sector) {
			buf[r + l] = rhs[r];
			invs += lcount - l;
			++r;
		} else {
			buf[r + l] = lhs[l];
			++l;
		}
	}

	memcpy(buf + r + l, lhs + l, (lcount - l) * sizeof(*lhs));
	memcpy(buf + r + l, rhs + r, (rcount - r) * sizeof(*rhs));

	return invs;
}

static __u64 count_invs(struct blkio_event *events, size_t size,
				struct blkio_event *buf)
{
	size_t half;
	__u64 invs;

	if (size < 2)
		return 0;

	half = size / 2;
	invs = count_invs(events, half, buf);
	invs += count_invs(events + half, size - half, buf);
	invs += merge_invs(events, half, events + half, size - half, buf);
	memcpy(events, buf, size * sizeof(*buf));
	return invs;
}

static __u32 count_merged_sectors(struct blkio_event *events, size_t size)
{
	__u64 sectors = 0;
	__u32 count = 0;
	__u64 begin = 0, end = 0;
	size_t i;

	for (i = 0; i != size; ++i) {
		if (events[i].sector > end) {
			sectors += end - begin;
			++count;
			begin = events[i].sector;
			end = begin + events[i].sectors;
		} else {
			begin = MIN(begin, events[i].sector);
			end = MAX(end, events[i].sector + events[i].sectors);
		}
	}

	sectors += end - begin;
	++count;

	return sectors / count;
}

static int account_events(int ofd, struct blkio_event *events, size_t size)
{
	struct blkio_event *buf;
	struct blkio_stats stats;
	__u64 total_sectors = 0, total_iodepth = 0;
	__u32 id_events = 0, iodepth = 0;
	size_t i;

	if (!size)
		return 0;

	memset(&stats, 0, sizeof(stats));
	stats.first_time = events[0].time;
	stats.last_time = events[size - 1].time;
	assert(stats.first_time <= stats.last_time);
	stats.min_sector = ~((__u64)0);
	for (i = 0; i != size; ++i) {
		if (queue_event(events + i)) {
			stats.min_sector = MIN(stats.min_sector,
						events[i].sector);
			stats.max_sector = MAX(stats.max_sector,
						events[i].sector);
			total_sectors += events[i].sectors;

			++iodepth;

			if (events[i].action & BLK_TC_ACT(BLK_TC_WRITE))
				++stats.writes;
			else
				++stats.reads;
		} else if (complete_event(events + i)) {
			if (!iodepth)
				continue;

			/* Account only local maximums */
			if (queue_event(events + i - 1)) {
				total_iodepth += iodepth;
				++id_events;
			}
			--iodepth;
		}
	}

	if (!(stats.reads + stats.writes))
		return 0;

	if (iodepth) {
		total_iodepth += iodepth;
		++id_events;
	}

	stats.sectors = total_sectors / (stats.reads + stats.writes);
	stats.iodepth = total_iodepth / id_events;
	size = remove_if(events, size, complete_event);
	buf = calloc(size, sizeof(*buf));
	if (!buf) {
		ERR("Cannot allocate buffer for merge sort\n");
		return 1;
	}

	stats.inversions = count_invs(events, size, buf);
	free(buf);
	stats.merged_sectors = count_merged_sectors(events, size);

	return dump_stats(ofd, &stats);
}

static void blkrecord(int ifd, int ofd)
{
	const size_t buffer_size = max_batch_size;
	const __u64 NS = 1000000ul;
	const __u64 TI = max_time_interval * NS;

	size_t size = 0, read = 0;
	__u64 time = 0;
	struct blkio_event *events = calloc(buffer_size, sizeof(*events));

	if (!events) {
		ERR("Cannot allocate event buffer\n");
		return;
	}

	while ((read = read_events(ifd, events + size, buffer_size - size))) {
		size_t count;

		size += read;
		sort_events_by_time(events, size);

		count = find_event_by_time(events, size, time);
		if (count) {
			ERR("Discarded %lu unordered requests\n",
						(unsigned long)count);
			size -= count;
			memmove(events, events + count, sizeof(*events) * size);
			continue;
		}

		count = find_event_by_time(events, size, events[0].time + TI);
		if (account_events(ofd, events, count)) {
			free(events);
			return;
		}
		time = events[count - 1].time;
		size -= count;
		memmove(events, events + count, sizeof(*events) * size);
	}


	while (size) {
		size_t count = find_event_by_time(events, size,
					events[0].time + TI);
		assert(count <= size);
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
