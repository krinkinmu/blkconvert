#include <sys/types.h>
#include <byteswap.h>
#include <unistd.h>

#include <getopt.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "blkrecord_new.h"
#include "network.h"
#include "file_io.h"
#include "utils.h"


static volatile sig_atomic_t done;

static void finish_tracing(int sig)
{
	(void) sig;
	done = 1;
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

static void blkio_net_server(const struct blkio_record_conf *df, int fd)
{
	struct blkio_record_conf conf = *df;
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

	conf.buffer_size = le32toh(start_msg->buffer_size);
	conf.buffer_count = le32toh(start_msg->buffer_count);
	conf.events_count = le32toh(start_msg->events_count);
	conf.poll_timeout = le32toh(start_msg->poll_timeout);
	memcpy(device_path, start_msg->device, BLKIO_MAX_PATH);
	conf.device = device_path;
	
	struct blkio_record_ctx ctx;

	if (blkio_record_ctx_setup(&ctx, &conf)) {
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

struct blkio_server_conf {
	struct blkio_record_conf conf;
	const char *port;
};

static const char *debugfs = "/sys/kernel/debug";

static int parse_args(int argc, char **argv, struct blkio_server_conf *conf)
{
	static const char *opts = "f:t:";
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
			.name = NULL
		}
	};

	/* fill in deafults */
	memset(conf, 0, sizeof(*conf));
	conf->conf.debugfs = debugfs;

	int c;

	while ((c = getopt_long_only(argc, argv, opts, long_opts, 0)) != -1) {
		switch (c) {
		case 'f':
			conf->conf.debugfs = optarg;
			break;
		case 't':
			conf->port = optarg;
			break;
		default:
			fprintf(stderr, "unrecognized option: %s\n", optarg);
			return -1;
		}
	}

	if (!conf->port) {
		fprintf(stderr, "you must specify port\n");
		return -1;
	}

	return 0;
}

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		"-f --debugfs - debugfs path [default=/sys/kernel/debug]\n" \
		"-t --port - port to listen input connections [mandatory]\n";
	fprintf(stderr, "%s %s", name, usage);
}

int main(int argc, char **argv)
{
	struct blkio_server_conf conf;

	if (parse_args(argc, argv, &conf)) {
		show_usage(argv[0]);
		return 1;
	}

	int fd = server_socket(conf.port, SOCK_STREAM);

	if (fd < 0) {
		perror("Cannot create server socket");
		return 1;
	}

	if (listen(fd, 1)) {
		perror("Listen failed");
		close(fd);
		return 1;
	}

	handle_signal(SIGINT, finish_tracing);
	handle_signal(SIGHUP, finish_tracing);
	handle_signal(SIGTERM, finish_tracing);

	while (!done) {
		struct sockaddr_storage addr;
		socklen_t len = sizeof(addr);

		int client = accept(fd, (struct sockaddr *)&addr, &len);

		if (client < 0) {
			if (errno != EINTR)
				perror("Accept failed");
			break;
		}

		blkio_net_server(&conf.conf, client);
	}
	close(fd);

	return 0;
}
