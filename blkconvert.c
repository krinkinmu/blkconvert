#include <byteswap.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include "blkioqueue.h"
#include "blktrace_api.h"
#include "common.h"

static const char *input_name;
static const char *output_name;
static unsigned time_interval = 1;
static int binary = 1;

static void show_usage(const char *prog_name)
{
	static const char *usage = "\n\n" \
		"[-f <input file>           | --file=<input file>]\n" \
		"[-o <output file>          | --output=<output file>]\n" \
		"[-i <time interval length> | --interval=<time interval length>]\n" \
		"[-t                        | --text]\n" \
		"\t-f Use specified blktrace file. If not specified stdin is used\n" \
		"\t-o Output file. If not specified stdout is used\n" \
		"\t-i Give time interval to calculate average over, in seconds\n" \
		"\t-t Generate output in text format instead binary.\n";
	fprintf(stderr, "Usage: %s %s", prog_name, usage);
}

static int parse_args(int argc, char **argv)
{
	static struct option l_opts[] = {
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
			.name = "text",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 't'
		},
		{
			.name = NULL
		}
	};

	static const char *opts = "f:o:i:t";
	int c, i;

	while ((c = getopt_long(argc, argv, opts, l_opts, NULL)) >= 0) {
		switch (c) {
		case 'f':
			input_name = optarg;
			break;
		case 'o':
			output_name = optarg;
			break;
		case 'i':
			i = atoi(optarg);
			if (i < 0) {
				fprintf(stderr, "Time interval has to be positive integer\n");
				return 1;
			}
			time_interval = (unsigned)i;
			break;
		case 't':
			binary = 0;
			break;
		default:
			show_usage(argv[0]);
			return 1;
		};
	}
	return 0;
}

static FILE *my_fopen(const char *name, const char *mode)
{
	static char errbuf[MAXPATHLEN + 64];
	FILE *f = fopen(name, mode);

	if (!f) {
		snprintf(errbuf, MAXPATHLEN + 64, "Cannot open file %s", name);
		perror(errbuf);
	}

	return f;
}

static void my_fclose(FILE *f)
{
	fclose(f);
}

static void trace_to_cpu(struct blk_io_trace *t)
{
	if ((t->magic & 0xffffff00) == BLK_IO_TRACE_MAGIC)
		return;

	t->magic = __bswap_32(t->magic);
	t->time = __bswap_64(t->time);
	t->sector = __bswap_64(t->sector);
	t->bytes = __bswap_32(t->bytes);
	t->action = __bswap_32(t->action);
	t->pdu_len = __bswap_16(t->pdu_len);
	/*
	t->sequence = __bswap_32(t->sequence);
	t->pid = __bswap_32(t->pid);
	t->device = __bswap_32(t->device);
	t->cpu = __bswap_32(t->cpu);
	t->error = __bswap_16(t->error);
	*/
}

static int read_next_trace(FILE *file, struct blk_io_trace *trace)
{
	if (fread(trace, sizeof(*trace), 1, file) != 1) {
		assert(feof(file) && "Read error");
		return 1;
	}

	trace_to_cpu(trace);
	assert((trace->magic & 0xffffff00) == BLK_IO_TRACE_MAGIC);

	if (trace->pdu_len) {
		static char skip[256];
		unsigned to_skip = trace->pdu_len;

		while (to_skip) {
			const unsigned count = to_skip < 256 ? to_skip : 256;

			if (fread(skip, 1, count, file) != count) {
				assert(feof(file) && "Read error");
				return 1;
			}
			to_skip -= count;
		}
	}

	return 0;
}

static void dump_stats(FILE *file, const struct blkio_stats *stats)
{
	const struct blkio_stat *rd = &stats->read;
	const struct blkio_stat *wr = &stats->write;

	if (!rd->total_ops && !wr->total_ops)
		return;

	if (binary) {
		fwrite(rd, sizeof(*rd), 1, file);
		fwrite(wr, sizeof(*wr), 1, file);
		return;
	}

	#define STAT_FMT  "%"PRIu64" %"PRIu64 \
			" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64
	fprintf(file, STAT_FMT" "STAT_FMT"\n",
		rd->start, rd->end,
		rd->total_ops, rd->total_bytes,
		rd->min_sector, rd->max_sector,
		wr->start, wr->end,
		wr->total_ops, wr->total_bytes,
		wr->min_sector, wr->max_sector);
	#undef STAT_FMT
}

static void account_io(struct blkio_stat *st, const struct blkio *io)
{
	if (!st->total_ops) {
		st->total_ops = 1;
		st->start = io->time;
		st->end = io->time;
		st->total_bytes = io->bytes;
		st->min_sector = io->sector;
		st->max_sector = io->sector;
		return;
	}

	if (st->min_sector > io->sector)
		st->min_sector = io->sector;
	if (st->max_sector < io->sector)
		st->max_sector = io->sector;
	if (st->start > io->time)
		st->start = io->time;
	if (st->end < io->time)
		st->end = io->time;
	++st->total_ops;
	st->total_bytes += io->bytes;
}

static void dump_queue(FILE *ofile, struct blkio_queue *queue,
			struct blkio_cache *cache, uint64_t time)
{
	struct blkio_stats stats;
	struct blkio *io;

	memset(&stats, 0, sizeof(stats));
	io = queue_front(queue);
	if (!io)
		return;

	while (io && io->time < time) {
		if (io->write)
			account_io(&stats.write, io);
		else
			account_io(&stats.read, io);

		dequeue_blkio(queue);
		blkio_cache_free(cache, io);
		io = queue_front(queue);
	}
	dump_stats(ofile, &stats);
}

static void blkconvert(FILE *ifile, FILE *ofile)
{
	static const uint64_t NS = 1000000000ull;

	struct blkio_cache *cache = create_blkio_cache();
	struct blkio_queue *queue = create_blkio_queue();
	struct blk_io_trace trace;
	uint64_t time = 0;
	uint64_t drop = 0;

	while (!read_next_trace(ifile, &trace)) {
		struct blkio *io;
		uint64_t start_time, end_time;

		if (((trace.action & 0xffff) != __BLK_TA_QUEUE) ||
				!(trace.action & BLK_TC_ACT(BLK_TC_QUEUE)))
			continue;

		if (!trace.bytes)
			continue;

		if (trace.time < time) {
			++drop;
			continue;
		}

		io = blkio_cache_alloc(cache);
		io->time = trace.time;
		io->sector = trace.sector;
		io->bytes = trace.bytes;
		io->write = trace.action & BLK_TC_ACT(BLK_TC_WRITE);

		enqueue_blkio(queue, io);
		start_time = queue_front(queue)->time;
		end_time = queue_back(queue)->time;

		if (end_time - start_time > 2 * time_interval * NS) {
			time = start_time + time_interval * NS;
			dump_queue(ofile, queue, cache, time);
		}
	}

	dump_queue(ofile, queue, cache, UINT64_MAX);
	destory_blkio_queue(queue);
	destory_blkio_cache(cache);
}

int main(int argc, char **argv)
{
	FILE *ifile = NULL, *ofile = NULL;

	if (parse_args(argc, argv))
		return 1;

	if (input_name && strcmp("-", input_name))
		ifile = my_fopen(input_name, "rb");
	else
		ifile = stdin;

	if (output_name && strcmp("-", output_name))
		ofile = my_fopen(output_name, (binary ? "wb" : "w"));
	else
		ofile = stdout;

	if (ifile && ofile)
		blkconvert(ifile, ofile);

	if (ifile && ifile != stdin)
		my_fclose(ifile);

	if (ofile && ofile != stdout)
		my_fclose(ofile);

	return 0;
}
