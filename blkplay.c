#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <endian.h>
#include <fcntl.h>

#include <zlib.h>

#include "usio_engine.h"
#include "aio_engine.h"
#include "algorithm.h"
#include "io_engine.h"
#include "generator.h"
#include "account.h"
#include "file_io.h"
#include "network.h"
#include "deamon.h"
#include "common.h"
#include "debug.h"
#include "utils.h"
#include "list.h"


struct blkplay_config {
	const char *input_file_name;
	const char *block_device_name;
	const char *io_engine_name;
	const struct io_engine *io_engine;
	int number_of_events;
	int time_accurate;
	int keep_io_delay;
	int pool_size;

	unsigned long *pid;
	size_t pid_size;
};

enum blkplay_mode {
	BM_HOST,
	BM_SERVER,
	BM_CLIENT
};

static const unsigned long long NS = 1000000000ull;
static volatile sig_atomic_t done;
static int play_mode;
static const char *node;
static const char *service;


static void blkplay_config_add_pid(struct blkplay_config *conf,
			unsigned long pid)
{
	static unsigned long default_pids_array[4096];

	if (!conf->pid)
		conf->pid = default_pids_array;

	if (conf->pid_size != 4096)
		conf->pid[conf->pid_size++] = pid;
}

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		" -d <device>           | --device=<device>\n" \
		" -f <input file>       | --file=<input file>\n" \
		"-e <number of events> | --events=<number of events>\n" \
		"-p <pid>              | --pid=<pid>\n" \
		"-g <io engine>        | --engine=<io engine>\n"
		"-h <host>             | --host=<host>\n" \
		"-s <port>             | --port=<port>\n" \
		"-i                    | --keep_io_delay\n" \
		"-t                    | --time\n" \
		"-c                    | --client\n" \
		"-b                    | --server\n" \
		"\t-d Block device file. Must be specified.\n" \
		"\t-f Use specified blkrecord file. Default: stdin\n" \
		"\t-e Max number of concurrently processing events. Default: 512\n" \
		"\t-p Process PID to play.\n" \
		"\t-g IO engine to play. Default: usio.\n" \
		"\t-h Host name/address to connect.\n" \
		"\t-s Port to connect/listen.\n" \
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

static int parse_args(struct blkplay_config *conf, int argc, char **argv)
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

	long i;
	int c;

	memset(conf, 0, sizeof(*conf));
	while ((c = getopt_long(argc, argv, opts, long_opts, NULL)) >= 0) {
		switch (c) {
		case 'd':
			conf->block_device_name = optarg;
			break;
		case 'f':
			conf->input_file_name = optarg;
			break;
		case 'e':
			i = atol(optarg);
			if (i < 0) {
				ERR("Number of events must be positive\n");
				return 1;
			}
			conf->number_of_events = i;
			break;
		case 'p':
			i = atol(optarg);
			if (i < 0) {
				ERR("PID cannot be negative\n");
				return 1;
			}

			blkplay_config_add_pid(conf, i);
			break;
		case 'g':
			conf->io_engine_name = optarg;
			break;
		case 'h':
			node = optarg;
			break;
		case 's':
			service = optarg;
			break;
		case 'i':
			conf->keep_io_delay = 1;
			break;
		case 't':
			conf->time_accurate = 1;
			break;
		case 'c':
			play_mode = BM_CLIENT;
			break;
		case 'b':
			play_mode = BM_SERVER;
			break;
		default:
			return 1;
		}
	}

	if (play_mode == BM_SERVER) {
		if (!service) {
			ERR("You must specify port in server mode\n");
			return 1;
		}
		return 0;
	}

	if (play_mode == BM_CLIENT && (!service || !node)) {
		ERR("You must specify remote host and port in client mode\n");
		return 1;
	}

	if (!conf->input_file_name) {
		ERR("You must specify input file name\n");
		return 1;
	}

	if (!conf->block_device_name) {
		ERR("You must specify block device name\n");
		return 1;
	}

	conf->io_engine = io_engine_find(conf->io_engine_name);
	if (!conf->io_engine) {
		ERR("Unsupported io engine %s\n", conf->io_engine_name);
		return 1;
	}

	if (conf->pid)
		sort(conf->pid, conf->pid_size, &pid_compare);

	return 0;
}

static int to_play(const struct blkplay_config *conf, unsigned long pid)
{
	size_t pos;

	if (!conf->pid_size)
		return 1;

	pos = lower_bound(conf->pid, conf->pid_size, pid, &pid_compare);
	if (pos == conf->pid_size || conf->pid[pos] != pid)
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
			return -1;
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
			return -1;
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
static int blkio_stats_play(const struct blkplay_config *conf,
			struct io_context *ctx,
			const struct blkio_stats *stat)
{
	const int ios = stat->reads + stat->writes;
	const int iodepth = MIN(stat->iodepth, ctx->size);
	const int batch = MIN(iodepth, stat->batch);

	unsigned long long wait = 0;

	if (conf->keep_io_delay && ios > 1)
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

		if (conf->keep_io_delay)
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

static void play(const struct blkplay_config *conf, int fd)
{
	struct blkio_stats stats;
	struct io_context ctx;

	int rc = io_engine_setup(&ctx, conf->io_engine, conf->block_device_name,
				conf->number_of_events);
	if (rc) {
		ERR("Cannot create io context\n");
		return;
	}

	while (!blkio_stats_read(fd, &stats)) {
		if (blkio_stats_play(conf, &ctx, &stats))
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

struct play_queue {
	int pfd[2];
};

static int play_queue_in(struct play_queue *queue)
{ return queue->pfd[0]; }

static int play_queue_out(struct play_queue *queue)
{ return queue->pfd[1]; }

static int play_queue_setup(struct play_queue *queue)
{
	if (pipe(queue->pfd))
		return errno;
	return 0;
}


struct play_worker {
	struct list_head link;
	struct play_queue queue;
	unsigned long long time;
	pid_t pid;
};

static int play_worker_setup(const struct blkplay_config *conf,
			struct play_worker *worker)
{
	int ret = play_queue_setup(&worker->queue);

	if (ret)
		return ret;

	worker->time = 0;
	worker->pid = fork();

	if (worker->pid < 0) {
		close(play_queue_in(&worker->queue));
		close(play_queue_out(&worker->queue));
		return errno;
	}

	if (worker->pid == 0) {
		close(play_queue_out(&worker->queue));
		play(conf, play_queue_in(&worker->queue));
		close(play_queue_in(&worker->queue));
		exit(0);
	} else {
		close(play_queue_in(&worker->queue));
	}

	return 0;
}

static void play_worker_release(struct play_worker *worker)
{
	close(play_queue_out(&worker->queue));

	int status;

	do {
		waitpid(worker->pid, &status, 0);
	} while (!WIFEXITED(status) || errno != ECHILD);
}

struct play_pool {
	struct list_head head;
	struct play_worker *worker;
	size_t size;
};

static void play_pool_release(struct play_pool *pool)
{
	struct list_head *head = &pool->head;

	for (struct list_head *ptr = head->next; ptr != head; ptr = ptr->next) {
		struct play_worker *worker = list_entry(ptr, struct play_worker,
					link);

		play_worker_release(worker);
	}
	free(pool->worker);
}

static int play_pool_setup(const struct blkplay_config *conf,
			struct play_pool *pool)
{
	pool->worker = calloc(conf->pool_size + 1, sizeof(*pool->worker));

	if (!pool->worker)
		return ENOMEM;

	list_head_init(&pool->head);
	for (int i = 0; i != conf->pool_size; ++i) {
		int ret = play_worker_setup(conf, pool->worker + i);

		if (ret) {
			ERR("Cannot setup play process\n");
			play_pool_release(pool);
			return ret;
		}
		list_link_after(&pool->head, &pool->worker[i].link);
	}
	pool->size = conf->pool_size;

	return 0;
}

static int play_pool_submit(struct play_pool *pool,
			const struct blkio_stats *stats)
{
	struct play_worker *worker = pool->worker;

	for (size_t i = 0; i != pool->size; ++i) {
		if (pool->worker[i].time < worker->time)
			worker = &pool->worker[i];
	}

	worker->time = stats->end_time;

	if (blkio_stats_write(play_queue_out(&worker->queue), stats)) {
		ERR("Submit failed\n");
		return 1;
	}
	return 0;
}

static void __play_pids(const struct blkplay_config *conf,
			gzFile zfd, struct play_pool *pool)
{
	const unsigned long long play_time = current_time();

	unsigned long long record_time = ~0ull;
	struct blkio_stats stats;

	while (!blkio_zstats_read(zfd, &stats)) {
		const unsigned long pid = stats.pid;

		if (!to_play(conf, pid))
			continue;

		if (record_time > stats.begin_time)
			record_time = stats.begin_time;

		if (conf->time_accurate) {
			const unsigned long long p_elapsed =
						current_time() - play_time;
			const unsigned long long r_elapsed =
						stats.begin_time - record_time;

			if (r_elapsed > p_elapsed)
				delay(r_elapsed - p_elapsed);
		}

		play_pool_submit(pool, &stats);
	}	
}

static void play_pids(const struct blkplay_config *conf, gzFile zfd)
{
	struct play_pool pool;

	if (play_pool_setup(conf, &pool)) {
		ERR("Cannot create pool of play processes\n");
		return;
	}

	ERR("Start playing\n");
	__play_pids(conf, zfd, &pool);
	ERR("Release resources\n");
	play_pool_release(&pool);
	ERR("Finished\n");
}

static int count_pool_size(const struct blkplay_config *conf, gzFile zfd)
{
	static const int default_play_processes = 4;

	unsigned long long *end_time = calloc(default_play_processes,
				sizeof(*end_time));

	if (!end_time) {
		ERR("Cannot count number of processes\n");
		return default_play_processes;
	}

	struct blkio_stats stats;
	int size = 0, capacity = default_play_processes;

	while (!blkio_zstats_read(zfd, &stats)) {
		const unsigned long pid = stats.pid;

		if (!to_play(conf, pid))
			continue;

		unsigned long long time = ~0ull;
		int min_idx = 0;

		for (int i = 0; i != size; ++i) {
			if (end_time[min_idx] < time) {
				time = end_time[min_idx];
				min_idx = i;
			}
		}

		if (time < stats.begin_time) {
			end_time[min_idx] = stats.end_time;
			continue;
		}

		if (size == capacity) {
			unsigned long long *et = realloc(end_time,
					2 * capacity * sizeof(*end_time));

			if (!et) {
				ERR("Cannot count number of processes\n");
				free(end_time);
				return size;
			}
			capacity *= 2;
			end_time = et;
		}
		end_time[size++] = stats.end_time;
	}
	free(end_time);
	return size;
}

static void blkplay_host(struct blkplay_config *config)
{
	gzFile zfd = gzopen(config->input_file_name, "rb");
	if (!zfd) {
		ERR("Cannot allocate enough memory for zlib\n");
		return;
	}

	config->pool_size = count_pool_size(config, zfd);

	ERR("device: %s\n", config->block_device_name);
	ERR("engine: %s\n", config->io_engine_name);
	ERR("processes: %d\n", config->pool_size);
	ERR("events: %d\n", config->number_of_events);
	ERR("time accurate: %d\n", config->time_accurate);
	ERR("keep io delay: %d\n", config->keep_io_delay);

	gzrewind(zfd);
	play_pids(config, zfd);
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

#define PLAY_CMD_MSG_TYPE      1

struct blkplay_msg_header {
	__u32 type;
	__u32 size;
} __attribute__((packed));

struct blkplay_play_cmd {
	struct blkplay_msg_header header;
	__u32 events;
	__u32 pool;
	__u32 engine;
	__u32 device;
	__u32 accurate;
	__u32 delay;
} __attribute__((packed));

static int blkplay_send_play_cmd(int fd, const struct blkplay_config *conf)
{
	static const int sz = sizeof(struct blkplay_play_cmd);
	static char buffer[4096];

	const int dev_len = strlen(conf->block_device_name) + 1;
	const int engine_len = strlen(conf->io_engine_name) + 1;
	const int size = sz + dev_len + engine_len;

	if (size > 4096)
		return 0;

	struct blkplay_play_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));

	cmd.header.type = htole32(PLAY_CMD_MSG_TYPE);
	cmd.header.size = htole32(size);
	cmd.pool = htole32(conf->pool_size);
	cmd.events = htole32(conf->number_of_events);
	cmd.accurate = conf->time_accurate;
	cmd.delay = conf->keep_io_delay;
	cmd.device = htole32(sz);
	cmd.engine = htole32(sz + dev_len);

	memcpy(buffer, &cmd, size);
	memcpy(buffer + sz, conf->block_device_name, dev_len);
	memcpy(buffer + sz + dev_len, conf->io_engine_name, engine_len);

	return mywrite(fd, buffer, size);
}

static int blkplay_read_play_cmd(int fd, struct blkplay_config *config)
{
	static const int sz = sizeof(struct blkplay_play_cmd);
	static char buffer[4096];

	struct blkplay_play_cmd cmd;

	if (myread(fd, (void *)&cmd, sz)) {
		ERR("Cannot read header\n");
		return 1;
	}

	if (myread(fd, buffer + sz, le32toh(cmd.header.size) - sz)) {
		ERR("Cannot read data\n");
		return 1;
	}

	memset(config, 0, sizeof(*config));

	config->block_device_name = buffer + le32toh(cmd.device);
	config->io_engine_name = buffer + le32toh(cmd.engine);
	config->number_of_events = le32toh(cmd.events);
	config->pool_size = le32toh(cmd.pool);
	config->time_accurate = cmd.accurate;
	config->keep_io_delay = cmd.delay;

	if (!config->pool_size) {
		ERR("Recevied pool size is zero, use number of cpus instead\n");
		config->pool_size = sysconf(_SC_NPROCESSORS_CONF);
		if (config->pool_size < 0) {
			ERR("Cannot get number of CPUs\n");
			return 1;
		}
	}

	config->io_engine = io_engine_find(config->io_engine_name);
	if (!config->io_engine) {
		ERR("Cannot find io engine %s\n", config->io_engine_name);
		return 1;
	}

	return 0;
}

static void handle_connection(int fd)
{
	struct blkplay_config config;

	ERR("Input connection\n");
	if (blkplay_read_play_cmd(fd, &config)) {
		ERR("Cannot read play configuration\n");
		close(fd);
		return;
	}

	ERR("device: %s\n", config.block_device_name);
	ERR("engine: %s\n", config.io_engine_name);
	ERR("processes: %d\n", config.pool_size);
	ERR("events: %d\n", config.number_of_events);
	ERR("time accurate: %d\n", config.time_accurate);
	ERR("keep io delay: %d\n", config.keep_io_delay);

	gzFile izfd = gzdopen(fd, "rb");
	if (izfd) {
		play_pids(&config, izfd);
		gzclose(izfd);
	} else {
		ERR("Cannot allocate zlib buffer\n");
		close(fd);
	}
}

static void blkplay_server(void)
{
	handle_signal(SIGINT, finish_blkplay);
	handle_signal(SIGHUP, finish_blkplay);
	handle_signal(SIGTERM, finish_blkplay);
	handle_signal(SIGALRM, finish_blkplay);
	handle_signal(SIGCHLD, reclaim_child);

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

static void send_stats(const struct blkplay_config *config, gzFile izfd,
			gzFile ozfd)
{
	struct blkio_stats stats;

	while (!blkio_zstats_read(izfd, &stats)) {
		const unsigned long pid = stats.pid;

		if (!to_play(config, pid))
			continue;

		if (blkio_zstats_write(ozfd, &stats))
			break;
	}
}

static void blkplay_client(struct blkplay_config *config)
{
	gzFile zfd = gzopen(config->input_file_name, "rb");

	if (!zfd) {
		ERR("Cannot allocate zlib buffer\n");
		return;
	}

	config->pool_size = count_pool_size(config, zfd);
	gzrewind(zfd);

	int fd = client_socket(node, service, SOCK_STREAM);

	if (fd == -1) {
		ERR("Cannot connect to server\n");
		gzclose(zfd);
		return;
	}

	if (blkplay_send_play_cmd(fd, config)) {
		ERR("Failed to send play configuration\n");
		gzclose(zfd);
		close(fd);
		return;
	}

	gzFile ozfd = gzdopen(fd, "wb");
	if (ozfd) {
		send_stats(config, zfd, ozfd);
		gzclose(ozfd);
	} else {
		ERR("Cannot allocate zlib buffer\n");
		close(fd);
	}
	gzclose(zfd);
}

int main(int argc, char **argv)
{
	struct blkplay_config config;

	if (parse_args(&config, argc, argv)) {
		show_usage(argv[0]);
		return 1;
	}

	srand(time(NULL));

	switch (play_mode) {
	case BM_SERVER:
		if (deamon("blkplayd", &blkplay_server))
			ERR("Cannot run deamon process (%d)\n", errno);
		break;
	case BM_CLIENT:
		blkplay_client(&config);
		break;
	case BM_HOST:
		blkplay_host(&config);
		break;
	}

	return 0;
}
