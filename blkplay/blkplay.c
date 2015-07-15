#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <libaio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "iocbcache.h"
#include "blkrecord.h"

static const __u64 sector_size = 512;

static const char *input_file_name;
static const char *device_file_name;
static unsigned number_of_events = 512;

#define ERR(...)  fprintf(stderr, __VA_ARGS__)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		" -d <device>           | --device=<device>\n" \
		"[-f <input file>       | --file=<input file>]\n" \
		"[-e <number of events> | --events=<number of events>]\n" \
		"\t-d Block device file. No default, must be specified.\n" \
		"\t-f Use specified blkrecord file. Default: stdin\n" \
		"\t-e Number of concurrently processing events. Default: 512\n";

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
			.name = NULL
		}
	};
	static const char *opts = "f:d:e:";

	int c, i;

	while ((c = getopt_long(argc, argv, opts, long_opts, NULL)) >= 0) {
		switch (c) {
		case 'f':
			input_file_name = optarg;
			break;
		case 'd':
			device_file_name = optarg;
			break;
		case 'e':
			i = atoi(optarg);
			if (i <= 0) {
				ERR("Number of events must be positive\n");
				return 1;
			}
			number_of_events = (unsigned)i;
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

static int myread(int ifd, char *buf, size_t size)
{
	size_t rd = 0;

	while (rd != size) {
		ssize_t ret = read(ifd, buf + rd, size - rd);
		if (ret < 0) {
			perror("Error while reading input file");
			return 1;
		}
		if (!ret)
			return 1;
		rd += ret;
	}
	return 0;
}

static int read_sample(int ifd, struct blkio_stats *stats)
{
	return myread(ifd, (char *)stats, sizeof(*stats));
}

static unsigned mylog2(__u64 x)
{
	unsigned bits;
	for (bits = 0; x; x >>= 1)
		++bits;
	return bits;
}

static __u64 random_u64(__u64 from, __u64 to)
{
	const unsigned bits = mylog2((__u64)RAND_MAX);
	__u64 value = 0;
	unsigned gen;

	for (gen = 0; gen < 64; gen += bits)
		value |= (unsigned)rand() << gen;
	return value % (to - from) + from;
}

static struct iocb *iocb_get(int fd, __u64 off, __u32 len, int rw)
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

static int iocbs_fill(struct iocb **iocbs, int fd,
			const struct blkio_stats *stat)
{
	const __u32 bytes = stat->bytes;
	const __u64 min_sec = stat->min_sector;
	const __u64 max_sec = stat->max_sector + 1;

	size_t reads = stat->reads, writes = stat->writes;
	const size_t ios = reads + writes;
	size_t i;

	for (i = 0; i != ios; ++i) {
		const __u64 off = sector_size * random_u64(min_sec, max_sec);
		const int wr = random_u64(0, reads + writes) < reads;

		iocbs[i] = iocb_get(fd, off, bytes, wr);
		if (!iocbs[i]) {
			iocbs_release(iocbs, i);
			return 1;
		}

		if (wr) --writes;
		else --reads;
	}

	return 0;
}

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

static int check_events(const struct io_event *events, size_t count)
{
	size_t i;

	for (i = 0; i != count; ++i) {
		const struct io_event * const e = events + i;

		if (e->res != e->obj->u.c.nbytes) {
			ERR("AIO failed %ld/%ld\n", e->res, e->res2);
			return 1;
		}
	}
	return 0;
}

static int play_sample(io_context_t ctx, int fd,
			const struct blkio_stats *stat)
{
	const size_t ios = stat->reads + stat->writes;
	const size_t iodepth = MIN(stat->iodepth, number_of_events);
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

	reclaim_i = 0;
	submit_i = 0;
	while (reclaim_i != ios) {
		size_t todo = MIN(ios - submit_i, iodepth);
		size_t running;
		int ret;

		if (iocbs_submit(ctx, iocbs + submit_i, todo)) {
			rc = 1;
			break;
		}

		submit_i += todo;
		running = submit_i - reclaim_i;
		ret = io_getevents(ctx, 1, running, events, NULL);
		if (ret < 0) {
			ERR("Error %d, while reclaiming IO\n", -ret);
			rc = 1;
			break;
		}
		reclaim_i += ret;

		if (check_events(events, ret)) {
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

	iocb_cache_create();

	if ((ret = io_setup(number_of_events, &ctx))) {
		ERR("Cannot initialize AIO context (%d)\n", -ret);
		iocb_cache_destroy();
		return;
	}

	while (!read_sample(ifd, &stat)) {
		if (play_sample(ctx, dfd, &stat))
			break;
	}

	io_destroy(ctx);
	iocb_cache_destroy();
}

int main(int argc, char **argv)
{
	int ifd = 0, dfd = 1;

	if (parse_args(argc, argv))
		return 1;

	if (input_file_name && strcmp("-", input_file_name)) {
		ifd = open(input_file_name, 0);
		if (ifd < 0) {
			perror("Cannot open input file");
			return 1;
		}
	}

	dfd = open(device_file_name, O_RDWR | O_DIRECT);
	if (dfd < 0) {
		close(ifd);
		perror("Cannot open block device file");
		return 1;
	}

	play(ifd, dfd);

	close(dfd);
	close(ifd);

	return 0;
}
