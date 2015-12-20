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
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

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
#include "utils.h"
#include "network.h"

static const unsigned long long NS = 1000000000ull;

static const char *input_file_name;
static const char *block_device_name;
static const char *io_engine_name = "usio";
static const struct io_engine *io_engine;
static int number_of_events = 512;
static int time_accurate;
static int keep_io_delay;

static volatile sig_atomic_t done;

enum blkplay_mode {
	BM_HOST,
	BM_SERVER,
	BM_CLIENT
};

static int play_mode;
static const char *node;
static const char *service;

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
		"[-h <host>             | --host=<host>]\n" \
		"[-s <port>             | --port=<port>]\n" \
		"[-i                    | --keep_io_delay]\n" \
		"[-t                    | --time]\n" \
		"[-c                    | --client]\n" \
		"[-b                    | --server]\n" \
		"\t-d Block device file. Must be specified.\n" \
		"\t-f Use specified blkrecord file. Default: stdin\n" \
		"\t-e Max number of concurrently processing events. Default: 512\n" \
		"\t-p Process PID to play.\n" \
		"\t-g IO engine to play. Default: usio.\n" \
		"\t-h Host name/address to use with client/server options.\n" \
		"\t-s Port to use with client/server options.\n" \
		"\t-i Keep time interval between IO.\n" \
		"\t-t Time accurate playing.\n" \
		"\t-c Client mode.\n" \
		"\t-b Server mode.\n";

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
			.name = "host",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'h'
		},
		{
			.name = "port",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 's'
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
			.name = "client",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 'c'
		},
		{
			.name = "server",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 'b'
		},
		{
			.name = NULL
		}
	};
	static const char *opts = "d:e:f:p:g:h:s:itcb";

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
		case 'h':
			node = optarg;
			break;
		case 's':
			service = optarg;
			break;
		case 'i':
			keep_io_delay = 1;
			break;
		case 't':
			time_accurate = 1;
			break;
		case 'c':
			play_mode = BM_CLIENT;
			break;
		case 'b':
			play_mode = BM_SERVER;
			break;
		default:
			show_usage(argv[0]);
			return 1;
		}
	}

	if (play_mode == BM_SERVER) {
		if (!service) {
			ERR("You must specify port in server mode\n");
			show_usage(argv[0]);
			return 1;
		}
		return 0;
	}

	if (play_mode == BM_CLIENT && (!service || !node)) {
		ERR("You must specify remote host and port in client mode\n");
		show_usage(argv[0]);
		return 1;
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

static int blkio_zstats_write(gzFile zfd, const struct blkio_stats *stats)
{
	const size_t size = sizeof(*stats);
	const char *buf = (const char *)stats;
	size_t written = 0;

	while (written != size) {
		int ret = gzwrite(zfd, buf + written, size - written);

		if (ret <= 0) {
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
	pid_t pid;
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
			const size_t l = 2 * (parent + 1) - 1;
			const size_t r = 2 * (parent + 1);
			size_t swap = parent;

			if (l < size && p[l].end_time < p[swap].end_time)
				swap = l;

			if (r < size && p[r].end_time < p[swap].end_time)
				swap = r;

			if (swap == parent)
				break;

			struct play_process tmp = p[parent];

			p[parent] = p[swap];
			p[swap] = tmp;
			parent = swap;
		}
	}	
}

static void play_pids(gzFile zfd, int pool_size)
{
	struct play_process player[MAX_PLAY_PROCESSES];
	int fail = 0;

	for (int i = 0; i != pool_size; ++i) {
		player[i].end_time = 0;
		player[i].fd = -1;
		player[i].pid = -1;
	}

	for (int i = 0; i != pool_size; ++i) {
		int pfds[2];

		if (pipe(pfds)) {
			perror("Cannot create pipe for play process");
			fail = 1;
			for (int j = 0; j != i; ++j)
				close(player[j].fd);
			break;
		}

		player[i].fd = pfds[1];
		player[i].pid = fork();
		if (player[i].pid < 0) {
			perror("Cannot create play process");
			fail = 1;
			close(pfds[0]);
			close(pfds[1]);
			for (int j = 0; j != i; ++j)
				close(player[j].fd);
			break;
		}

		if (!player[i].pid) {
			for (int j = 0; j != i; ++j)
				close(player[j].fd);
			close(pfds[1]);
			play(pfds[0]);
			close(pfds[0]);
			return;
		}
	}

	if (!fail) {
		ERR("Start playing\n");
		__play_pids(zfd, player, pool_size);
		ERR("Finished\n");
		for (int i = 0; i != pool_size; ++i)
			close(player[i].fd);
	}

	for (int i = 0; i != pool_size; ++i) {
		if (player[i].pid < 0)
			break;
		waitpid(player[i].pid, NULL, 0);
	}
}

static int count_pool_size(gzFile zfd)
{
	unsigned long long et[MAX_PLAY_PROCESSES];
	struct blkio_stats stats;
	int ps = 0;

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
			int parent = 0;

			et[parent] = stats.end_time;
			while (parent < ps) {
				unsigned long long tmp;
				const int l = 2 * (parent + 1) - 1;
				const int r = 2 * (parent + 1);
				int swap = parent;

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

	return ps;
}

static void find_and_play_pids(void)
{
	gzFile zfd = gzopen(input_file_name, "rb");
	if (!zfd) {
		ERR("Cannot allocate enough memory for zlib\n");
		return;
	}

	const int ps = count_pool_size(zfd);

	gzrewind(zfd);
	play_pids(zfd, ps);
	gzclose(zfd);
}

static void finish_blkplay(int sig)
{
	(void)sig;
	done = 1;
}

static void reclaim_child(int sig)
{
	(void) sig;

	while (1) {
		int status;
		pid_t pid = waitpid(-1, &status, WNOHANG);

		if (!pid || (pid == -1 && errno != EINTR))
			break;
	}
}

#define PLAY_CMD_MAX_LENGTH    4096

struct play_cmd_header {
	__u32 size;
	__u32 events;
	__u32 pool;
	__u32 engine;
	__u32 device;
	__u32 accurate;
	__u32 delay;
};

static void handle_connection(int fd)
{
	const int sz = sizeof(struct play_cmd_header);
	char buffer[PLAY_CMD_MAX_LENGTH];

	ERR("Handle input connection\n");
	if (myread(fd, buffer, sz)) {
		ERR("Cannot read command header\n");
		close(fd);
		return;
	}

	struct play_cmd_header header;

	memcpy((char *)&header, buffer, sz);

	header.size = le32toh(header.size);
	header.events = le32toh(header.events);
	header.pool = le32toh(header.pool);
	header.engine = le32toh(header.engine);
	header.device = le32toh(header.device);
	header.accurate = le32toh(header.device);
	header.delay = le32toh(header.delay);

	if (myread(fd, buffer + sz, header.size - sz)) {
		ERR("Cannot read command header\n");
		close(fd);
		return;
	}

	block_device_name = buffer + header.device;
	io_engine_name = buffer + header.engine;
	number_of_events = header.events;
	time_accurate = (header.accurate != 0);
	keep_io_delay = (header.delay != 0);

	io_engine = io_engine_find(io_engine_name);
	if (!io_engine) {
		ERR("Engine %s is'n supported\n", io_engine_name);
		close(fd);
		return;
	}

	if (header.pool >= MAX_PLAY_PROCESSES) {
		ERR("Requested pool is too large\n");
		close(fd);
		return;
	}

	ERR("device: %s\n", block_device_name);
	ERR("engine: %s\n", io_engine_name);
	ERR("events: %d\n", number_of_events);
	ERR("pool: %d\n", header.pool);
	ERR("accurate: %d\n", time_accurate);
	ERR("io delay: %d\n", keep_io_delay);

	gzFile izfd = gzdopen(fd, "rb");
	if (izfd) {
		play_pids(izfd, header.pool);
		gzclose(izfd);
	} else {
		ERR("Cannot allocate zlib buffer\n");
		close(fd);
	}
}

static void blkplay_server(void)
{
	int fd = server_socket(service, SOCK_STREAM);

	if (fd == -1) {
		ERR("Cannot create server socket\n");
		return;
	}

	if (listen(fd, 1)) {
		perror("Listen failed\n");
		return;
	}

	ERR("blkplayd started\n");
	while (!done) {
		struct sockaddr_storage addr;
		socklen_t len = sizeof(addr);

		int cfd = accept(fd, (struct sockaddr *)&addr, &len);

		if (cfd != -1) {
			pid_t pid = fork();

			if (pid < 0)
				ERR("Failed to fork worker process\n");

			if (pid == 0) {
				close(fd);
				handle_connection(cfd);
				return;
			}
			close(cfd);
		}
	}
	close(fd);
	ERR("blkplayd finished\n");
}

static void run_server(void)
{
	pid_t pid = fork();

	if (pid < 0) {
		ERR("Cannot create daemon process\n");
		return;
	}

	if (pid > 0)
		return;

	pid_t sid = setsid();

	if (sid < 0) {
		ERR("Cannot create a new session\n");
		return;
	}

	fclose(stdin);
	fclose(stdout);

	handle_signal(SIGINT, finish_blkplay);
	handle_signal(SIGHUP, finish_blkplay);
	handle_signal(SIGTERM, finish_blkplay);
	handle_signal(SIGALRM, finish_blkplay);
	handle_signal(SIGCHLD, reclaim_child);

	openlog("blkplayd", 0, 0);
	redirect_to_syslog(&stderr);
	if (chdir("/"))
		ERR("Cannot change dir to \"/\" (%d)", errno);
	else
		blkplay_server();
	closelog();
}

static void send_stats(gzFile izfd, gzFile ozfd)
{
	struct blkio_stats stats;

	while (!blkio_zstats_read(izfd, &stats)) {
		const unsigned long pid = stats.pid;

		if (!to_play(pid))
			continue;

		if (blkio_zstats_write(ozfd, &stats))
			break;
	}
}

static void run_client(void)
{
	const int sz = sizeof(struct play_cmd_header);
	char buffer[PLAY_CMD_MAX_LENGTH];
	struct play_cmd_header header;

	int dev_len = strlen(block_device_name);
	int engine_len = strlen(io_engine_name);
	int size = sz + dev_len + engine_len + 2;

	memset(buffer, 0, PLAY_CMD_MAX_LENGTH);
	header.size = htole32(size);
	header.events = htole32(number_of_events);
	header.accurate = time_accurate;
	header.delay = keep_io_delay;
	header.device = htole32(sz);
	header.engine = htole32(sz + dev_len + 1);

	gzFile zfd = gzopen(input_file_name, "rb");

	if (!zfd) {
		ERR("Cannot allocate zlib buffer\n");
		return;
	}

	header.pool = htole32(count_pool_size(zfd));
	gzrewind(zfd);

	memcpy(buffer, &header, sz);
	memcpy(buffer + sz, block_device_name, dev_len + 1);
	memcpy(buffer + sz + dev_len + 1, io_engine_name, engine_len + 1);

	int fd = client_socket(node, service, SOCK_STREAM);

	if (fd == -1) {
		ERR("Cannot connect to server\n");
		gzclose(zfd);
		return;
	}

	if (mywrite(fd, buffer, size)) {
		ERR("Failed to send play commad\n");
		gzclose(zfd);
		close(fd);
		return;
	}

	gzFile ozfd = gzdopen(fd, "wb");
	if (ozfd) {
		send_stats(zfd, ozfd);
		gzclose(ozfd);
	} else {
		ERR("Cannot allocate zlib buffer\n");
	}
	gzclose(zfd);
}

int main(int argc, char **argv)
{
	if (parse_args(argc, argv))
		return 1;

	srand(time(NULL));

	switch (play_mode) {
	case BM_SERVER:
		run_server();
		break;
	case BM_CLIENT:
		run_client();
		break;
	case BM_HOST:
		find_and_play_pids();
		break;
	}

	return 0;
}
