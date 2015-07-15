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

static const char *input_file_name;
static const char *output_file_name;
static unsigned long max_time_interval = 1000ul;
static unsigned long max_batch_size = 10000ul;
static int binary = 1;

#define ERR(...)  fprintf(stderr, __VA_ARGS__)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

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
	__u32 bytes;
	__u32 action;
};

static int myread(int ifd, char *buf, size_t size)
{
	size_t rd = 0;

	while (rd != size) {
		ssize_t ret = read(ifd, buf + rd, size - rd);
		if (ret < 0) {
			perror("Error while reading input");
			return 1;
		}
		if (!ret)
			return 1;
		rd += ret;
	}
	return 0;
}

static int mywrite(int ofd, const char *buf, size_t size)
{
	size_t wr = 0;

	while (wr != size) {
		ssize_t ret = write(ofd, buf + wr, size - wr);
		if (ret < 0) {
			perror("Error while writing output");
			return 1;
		}
		wr += ret;
	}
	return 0;
}

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

	event->time   = trace.time;
	event->sector = trace.sector;
	event->bytes  = trace.bytes;
	event->action = trace.action;

	return 0;
}

static int queue_event(const struct blkio_event *event)
{
	if (((event->action & 0xFFFF) != __BLK_TA_QUEUE) ||
			!(event->action & BLK_TC_ACT(BLK_TC_QUEUE)))
		return 0;
	return event->bytes != 0;
}

static int complete_event(const struct blkio_event *event)
{
	if (((event->action & 0xFFFF) != __BLK_TA_COMPLETE) ||
			!(event->action & BLK_TC_ACT(BLK_TC_COMPLETE)))
		return 0;
	return event->bytes != 0;
}

static int accept_event(const struct blkio_event *event)
{
	if (event->action & BLK_TC_ACT(BLK_TC_NOTIFY))
		return 0;

	if (event->action & BLK_TC_ACT(BLK_TC_PC))
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

typedef int (*comparison_fn_t)(const void *, const void *);

static void sort_events_by_time(struct blkio_event *events, size_t size)
{
	comparison_fn_t cmp = (comparison_fn_t)&time_compare;
	qsort(events, size, sizeof(*events), cmp);
}

static const void *lower_bound(const void *key, const void *base, size_t num,
			size_t size, comparison_fn_t cmp)
{
	size_t len = num;
	const char *b = base;

	while (len) {
		const size_t half = len / 2;
		const char * const m = b + half * size;

		if (cmp(m, key) < 0) {
			b = m + size;
			len = len - half - 1;
		} else {
			len = half;
		}
	}
	return b;
}

static size_t find_event_by_time(const struct blkio_event *events, size_t size,
			__u64 time)
{
	comparison_fn_t cmp = (comparison_fn_t)&time_compare;
	const struct blkio_event key = { .time = time };

	const struct blkio_event *event = (const struct blkio_event *)
			lower_bound(&key, events, size, sizeof(*events), cmp);
	return event - events;
}

static int dump_stats(int ofd, const struct blkio_stats *stats)
{
	char buffer[512];
	int ret;

	if (!(stats->reads + stats->writes))
		return 0;

	if (binary)
		return mywrite(ofd, (const char *)stats, sizeof(*stats));

	ret = snprintf(buffer, 512, "%llu %llu %llu %llu %lu %lu %lu %lu\n",
				(unsigned long long)stats->first_time,
				(unsigned long long)stats->last_time,
				(unsigned long long)stats->min_sector,
				(unsigned long long)stats->max_sector,
				(unsigned long)stats->reads,
				(unsigned long)stats->writes,
				(unsigned long)stats->bytes,
				(unsigned long)stats->iodepth);
	if (ret < 0) {
		ERR("Error while formating text output\n");
		return 1;
	}
	return mywrite(ofd, buffer, strlen(buffer));
}

static int account_events(int ofd, const struct blkio_event *events,
			size_t size)
{
	struct blkio_stats stats;
	__u64 total_bytes = 0, total_iodepth = 0;
	__u32 rw_events = 0, id_events = 0, iodepth = 0;
	size_t i;

	if (!size)
		return 0;

	memset(&stats, 0, sizeof(stats));
	stats.first_time = events[0].time;
	stats.last_time = events[size - 1].time;
	for (i = 0; i != size; ++i) {
		if (queue_event(events + i)) {
			if (rw_events == 1) {
				stats.min_sector = events[i].sector;
				stats.max_sector = events[i].sector;
			}

			stats.min_sector = MIN(stats.min_sector,
						events[i].sector);
			stats.max_sector = MAX(stats.max_sector,
						events[i].sector);
			total_bytes += events[i].bytes;

			++rw_events;
			++iodepth;

			if (events[i].action & BLK_TC_ACT(BLK_TC_WRITE))
				++stats.writes;
			else
				++stats.reads;
		} else if (complete_event(events + i)) {
			if (!iodepth)
				continue;

			/* Account only local maximums */
			if (i && queue_event(events + i - 1)) {
				total_iodepth += iodepth;
				++id_events;
			}
			--iodepth;
		}
	}

	if (iodepth) {
		total_iodepth += iodepth;
		++id_events;
	}

	if (rw_events)
		stats.bytes = total_bytes / rw_events;

	if (id_events)
		stats.iodepth = total_iodepth / id_events;

	return dump_stats(ofd, &stats);
}

static size_t process_events(int ofd, const struct blkio_event *events,
			size_t size)
{
	const __u64 NS = 1000000ul;
	__u64 end_time;
	size_t pos = 0, count;

	end_time = events[pos].time + max_time_interval * NS;
	count = find_event_by_time(events, size, end_time);
	do {
		if (account_events(ofd, events + pos, count))
			return 0;
		pos += count;
		end_time += max_time_interval * NS;
		count = find_event_by_time(events + pos, size - pos, end_time);
	} while (pos + count != size);

	return pos;
}

static void blkrecord(int ifd, int ofd)
{
	const size_t buffer_size = max_batch_size;

	size_t size = 0, read = 0;
	__u64 start_time = 0;
	struct blkio_event *events = calloc(buffer_size,
				sizeof(struct blkio_event));

	if (!events) {
		ERR("Cannot allocate event buffer\n");
		return;
	}

	while ((read = read_events(ifd, events + size, buffer_size - size))) {
		size_t count;

		size += read;
		sort_events_by_time(events, size);

		count = find_event_by_time(events, size, start_time);
		if (count) {
			ERR("Discarded %lu unordered requests\n",
				(unsigned long)count);
			size -= count;
			memmove(events, events + count, size);
			continue;
		}

		count = process_events(ofd, events, size);
		if (!count) {
			free(events);
			return;
		}
		start_time = events[count - 1].time;
		size -= count;
		memmove(events, events + count, size);
	}
	process_events(ofd, events, size);
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
