#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <zlib.h>

#include "algorithm.h"
#include "blkrecord.h"
#include "io_engine.h"
#include "generator.h"
#include "usio_engine.h"
#include "aio_engine.h"
#include "file_io.h"
#include "common.h"
#include "debug.h"

static const unsigned long long NS = 1000000000ull;

static const char *input_file_name;
static const char *block_device_name;
static const char *io_engine_name = "usio";
static const struct io_engine *io_engine;
static int number_of_events = 512;
static int time_accurate;
static int keep_io_delay;

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
		"[-p <pid>              | --pid=<pid>]\n" \
		"[-g <io engine>        | --engine=<io engine>]\n"
		"[-i                    | --keep_io_delay]\n" \
		"[-t                    | --time]\n" \
		"\t-d Block device file. Must be specified.\n" \
		"\t-f Use specified blkrecord file. Default: stdin\n" \
		"\t-e Max number of concurrently processing events. Default: 512\n" \
		"\t-p Process PID to play.\n" \
		"\t-g IO engine to play. Default: usio.\n" \
		"\t-i Keep time interval between IO.\n" \
		"\t-t Time accurate playing.\n";

	ERR("Usage: %s %s", name, usage);
}

static const struct io_engine *io_engine_find(const char *name)
{
	const char *names[] = { "usio", "aio" };
	const const struct io_engine *engines[] = { usio_engine, aio_engine };

	for (int i = 0; i != sizeof(names)/sizeof(names[0]); ++i)
		if (!strcmp(names[i], name))
			return engines[i];
	return 0;
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
			.name = "pid",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'p'
		},
		{
			.name = "events",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'e'
		},
		{
			.name = "engine",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'g'
		},
		{
			.name = "keep_io_delay",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 'i'
		},
		{
			.name = "time",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 't'
		},
		{
			.name = NULL
		}
	};
	static const char *opts = "d:e:f:p:g:it";

	unsigned j;
	long i;
	int c, found;

	while ((c = getopt_long(argc, argv, opts, long_opts, NULL)) >= 0) {
		switch (c) {
		case 'd':
			block_device_name = optarg;
			break;
		case 'f':
			input_file_name = optarg;
			break;
		case 'e':
			i = atol(optarg);
			if (i < 0) {
				ERR("Number of events must be positive\n");
				return 1;
			}

			number_of_events = i;
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
		case 'g':
			io_engine_name = optarg;
			break;
		case 'i':
			keep_io_delay = 1;
			break;
		case 't':
			time_accurate = 1;
			break;
		default:
			show_usage(argv[0]);
			return 1;
		}
	}

	if (!input_file_name) {
		ERR("You must specify input file name\n");
		show_usage(argv[0]);
		return 1;
	}

	if (!block_device_name) {
		ERR("You must specify block device name\n");
		show_usage(argv[0]);
		return 1;
	}

	io_engine = io_engine_find(io_engine_name);
	if (!io_engine) {
		ERR("Unsupported io engine %s\n", io_engine_name);
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

static void delay(unsigned long long ns)
{
	struct timespec wait;

	if (!ns)
		return;

	if (ns < NS) wait.tv_sec = 0;
	else wait.tv_sec = ns / NS;

	wait.tv_nsec = ns % NS;
	nanosleep(&wait, 0);
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
static int blkio_stats_play(struct io_context *ctx,
			const struct blkio_stats *stat)
{
	const int ios = stat->reads + stat->writes;
	const int iodepth = MIN(stat->iodepth, ctx->size);
	const int batch = MIN(iodepth, stat->batch);

	unsigned long long wait = 0;

	if (keep_io_delay && ios > 1)
		wait = (stat->end_time - stat->begin_time) / (ios - 1);

	struct bio *bios = calloc(ios, sizeof(*bios));

	if (!bios) {
		ERR("Cannot allocate array of bio structures\n");
		return 1;
	}

	if (bio_generate(bios, stat)) {
		free(bios);
		return 1;
	}

	int ret = 0;

	for (int s = 0; s != ios;) {
		int todo = 0;

		if (ctx->running < iodepth)
			todo = MIN(ios - s, iodepth - ctx->running);

		int rc = io_engine_submit(ctx, bios + s, todo);

		if (rc < todo) {
			ret = 1;
			break;
		}

		if (keep_io_delay)
			delay(rc * wait);

		s += rc;

		int next = MIN(ios - s, batch);

		todo = 1;
		if (ctx->running > iodepth - next)
			todo = ctx->running - iodepth + next;

		rc = io_engine_reclaim(ctx, todo, INT_MAX);
		if (rc < 0) {
			ret = 1;
			break;
		}
	}
	free(bios);

	return ret;
}

static void play(int fd)
{
	struct blkio_stats stats;
	struct io_context ctx;

	int rc = io_engine_setup(&ctx, io_engine, block_device_name,
				number_of_events);
	if (rc) {
		ERR("Cannot create io context\n");
		return;
	}

	while (!blkio_stats_read(fd, &stats)) {
		if (blkio_stats_play(&ctx, &stats))
			break;
	}
	io_engine_release(&ctx);
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

			if (r_elapsed > p_elapsed)
				delay(r_elapsed - p_elapsed);
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
