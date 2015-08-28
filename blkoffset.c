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
#include "file_io.h"
#include "common.h"
#include "debug.h"

static const char *input_file_name;
static const char *output_file_name;
static long pid = -1;
static int binary = 1;

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		"[-f <input file>    | --file=<input file>]\n" \
		"[-o <output file>   | --output=<output file>]\n" \
		"[-p <pid>           | --pid=<pid>]\n" \
		"[-t                 | --text]\n" \
		"\t-f Use specified blktrace file. Default: stdin\n" \
		"\t-o Ouput file. Default: stdout\n" \
		"\t-p Extract timings only for specified process.\n" \
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
			.name = "pid",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'p'
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
	static const char *opts = "f:o:p:t";

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
		case 'p':
			i = atol(optarg);
			if (i <= 0) {
				ERR("Pid cannot be negative\n");
				return 1;
			}
			pid = i;
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

	trace->time = __bswap_64(trace->time);
	trace->sector = __bswap_64(trace->sector);
	trace->bytes = __bswap_32(trace->bytes);
	trace->action = __bswap_32(trace->action);
	trace->pdu_len = __bswap_16(trace->pdu_len);
	trace->pid = __bswap_32(trace->pid);
	/* Other fields aren't interesting so far */
	return 0;
}

static int blk_io_trace_read(int fd, struct blk_io_trace *trace)
{
	size_t to_skip;

	if (myread(fd, (char *)trace, sizeof(*trace)))
		return 1;

	if (blk_io_trace_to_cpu(trace))
		return 1;

	to_skip = trace->pdu_len;
	while (to_skip) {
		char buf[256];

		if (myread(fd, buf, MIN(to_skip, sizeof(buf))))
			return 1;
		to_skip -= MIN(to_skip, sizeof(buf)); 
	}
	return 0;
}

static int is_queue_trace(const struct blk_io_trace *trace)
{
	return ((trace->action & 0xFFFF) == __BLK_TA_QUEUE) &&
		(trace->action & BLK_TC_ACT(BLK_TC_QUEUE));
}

static int accept_trace(const struct blk_io_trace *trace)
{ return trace->bytes && is_queue_trace(trace); }

static void blkoffset(int ifd, int ofd)
{
	struct blk_io_trace trace;

	while (!blk_io_trace_read(ifd, &trace)) {
		if (!accept_trace(&trace))
			continue;

		if (pid != -1 && trace.pid != pid)
			continue;

		if (binary) {
			mywrite(ofd, (char *)&trace.sector, sizeof(trace.sector));
		} else {
			char buf[64];
			snprintf(buf, sizeof(buf), "%llu\n", trace.sector);
			mywrite(ofd, buf, strlen(buf));
		}
	}
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

	blkoffset(ifd, ofd);
	close(ofd);
	close(ifd);

	return 0;
}
