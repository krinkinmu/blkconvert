#include <sys/types.h>
#include <sys/wait.h>
#include <endian.h>
#include <unistd.h>

#include <getopt.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "trace_net.h"
#include "trace.h"
#include "network.h"
#include "file_io.h"
#include "deamon.h"
#include "utils.h"


static const char *debugfs = "/sys/kernel/debug";
static const char *port;
static int background;
static int sock;
static volatile sig_atomic_t done;


static void finish_tracing(int sig)
{
	(void) sig;
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

static int blkio_net_read(int fd, void *data)
{
	struct blkio_net_hdr *hdr = data;
	char *buffer = data;

	if (myread(fd, hdr, sizeof(*hdr)))
		return -1;

	const size_t size = le32toh(hdr->size);

	if (myread(fd, buffer + sizeof(*hdr), size - sizeof(*hdr)))
		return -1;
	return 0;
}

static void blkio_net_status(int fd, int error, int drops)
{
	struct blkio_net_status status;

	status.hdr.type = BLKIO_MSG_STATUS;
	status.hdr.size = sizeof(status);
	status.error = htole32(error);
	status.drops = htole32(drops);
	mywrite(fd, &status, sizeof(status));
}

struct blkio_send_stats_handler {
	struct blkio_stats_handler handler;
	int fd;
};

static void blkio_send_stats(struct blkio_stats_handler *handler,
			struct blkio_stats *stats)
{
	struct blkio_net_stats stats_msg;
	struct blkio_send_stats_handler *send =
				(struct blkio_send_stats_handler *)handler;

	stats_msg.hdr.type = htole32(BLKIO_MSG_STATS);
	stats_msg.hdr.size = htole32(sizeof(stats_msg));
	memcpy(&stats_msg.stats, stats, sizeof(*stats));
	mywrite(send->fd, &stats_msg, sizeof(stats_msg));
}

static void blkio_net_server(int fd)
{
	struct blkio_record_conf conf;
	char device_path[BLKIO_MAX_PATH];
	union blkio_net_storage buffer;

	if (blkio_net_read(fd, &buffer)) {
		fprintf(stderr, "Error while reading msg\n");
		blkio_net_status(fd, BLKIO_STATUS_ERROR, 0);
		close(fd);
		return;
	}

	struct blkio_net_start *start_msg = &buffer.start;

	if (le32toh(start_msg->hdr.type) != BLKIO_MSG_START) {
		fprintf(stderr, "Unexpected message type\n");
		blkio_net_status(fd, BLKIO_STATUS_ERROR, 0);
		close(fd);
		return;
	}

	conf.debugfs = debugfs;
	conf.buffer_size = le32toh(start_msg->buffer_size);
	conf.buffer_count = le32toh(start_msg->buffer_count);
	conf.events_count = le32toh(start_msg->events_count);
	conf.poll_timeout = le32toh(start_msg->poll_timeout);
	memcpy(device_path, start_msg->device, BLKIO_MAX_PATH);
	conf.device = device_path;
	
	struct blkio_send_stats_handler handler = {{&blkio_send_stats}, fd};
	struct blkio_record_ctx ctx;

	if (blkio_record_ctx_setup(&ctx, &handler.handler, &conf)) {
		fprintf(stderr, "blkio_record_ctx_setup failed\n");
		blkio_net_status(fd, BLKIO_STATUS_ERROR, 0);
		close(fd);
		return;
	}
	blkio_trace_start(&ctx);

	myread(fd, &buffer, sizeof(struct blkio_net_stop));

	blkio_trace_stop(&ctx);
	blkio_net_status(fd, BLKIO_STATUS_OK, blkio_trace_drops(&ctx));
	blkio_record_ctx_release(&ctx);
	close(fd);
}

static void blkio_listen(void)
{
	handle_signal(SIGINT, finish_tracing);
	handle_signal(SIGHUP, finish_tracing);
	handle_signal(SIGTERM, finish_tracing);
	handle_signal(SIGCHLD, reclaim_child);

	while (!done) {
		struct sockaddr_storage addr;
		socklen_t len = sizeof(addr);

		int client = accept(sock, (struct sockaddr *)&addr, &len);

		if (client < 0) {
			if (errno != EINTR)
				perror("Accept failed");
			continue;
		}

		pid_t pid = fork();
		if (pid < 0) {
			perror("Fork failed");
			continue;
		}

		if (pid == 0) {
			blkio_net_server(client);
			return;
		}
		close(client);
	}
}

static int parse_args(int argc, char **argv)
{
	static const char *opts = "f:t:d";
	static struct option long_opts[] = {
		{
			.name = "debugfs",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'f'
		},
		{
			.name = "port",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 't'
		},
		{
			.name = "daemon",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 'd'
		},
		{
			.name = NULL
		}
	};

	int c;

	while ((c = getopt_long_only(argc, argv, opts, long_opts, 0)) != -1) {
		switch (c) {
		case 'f':
			debugfs = optarg;
			break;
		case 't':
			port = optarg;
			break;
		case 'd':
			background = 1;
			break;
		default:
			fprintf(stderr, "unrecognized option: %s\n", optarg);
			return -1;
		}
	}

	if (!port) {
		fprintf(stderr, "you must specify port\n");
		return -1;
	}

	return 0;
}

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		"-f --debugfs - debugfs path [default=/sys/kernel/debug]\n" \
		"-t --port - port to listen input connections [mandatory]\n" \
		"-d --daemon - run server in background\n";
	fprintf(stderr, "%s %s", name, usage);
}

int main(int argc, char **argv)
{
	if (parse_args(argc, argv)) {
		show_usage(argv[0]);
		return 1;
	}

	sock = server_socket(port, SOCK_STREAM);

	if (sock < 0) {
		perror("Cannot create server socket");
		return 1;
	}

	if (listen(sock, 1)) {
		perror("Listen failed");
		close(sock);
		return 1;
	}

	if (background)
		deamon("blkrecordd", &blkio_listen);
	else
		blkio_listen();

	close(sock);

	return 0;
}
