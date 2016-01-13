#include "blkrecord_new.h"
#include "network.h"
#include "file_io.h"
#include "utils.h"

#include <byteswap.h>
#include <unistd.h>

#include <getopt.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static void blkio_print_stats(struct blkio_stats *stats)
{
	printf("%llu-%llu: %lu reads, %lu writes\n",
		(unsigned long long) stats->begin_time,
		(unsigned long long) stats->end_time,
		(unsigned long) stats->reads,
		(unsigned long) stats->writes);
}

static volatile sig_atomic_t done;

static void finish_tracing(int sig)
{
	(void) sig;
	done = 1;
}

static void blkio_net_client(const struct blkio_record_conf *conf, int fd)
{
	union blkio_net_storage buffer;

	struct blkio_net_start *start_msg = &buffer.start;

	memset(start_msg, 0, sizeof(*start_msg));
	start_msg->hdr.type = htole32(BLKIO_MSG_START);
	start_msg->hdr.size = htole32(sizeof(*start_msg));
	start_msg->buffer_size = htole32(conf->buffer_size);
	start_msg->buffer_count = htole32(conf->buffer_count);
	start_msg->events_count = htole32(conf->events_count);
	start_msg->poll_timeout = htole32(conf->poll_timeout);
	strcpy(start_msg->device, conf->device);

	if (mywrite(fd, start_msg, sizeof(*start_msg))) {
		fprintf(stderr, "Cannot start tracing\n");
		close(fd);
	}

	while (!done) {
		if (!blkio_net_read(fd, &buffer)) {
			if (le32toh(buffer.hdr.type) != BLKIO_MSG_STATS)
				break;
			blkio_print_stats(&buffer.stats.stats);
		} else {
			done = 1;
		}
	}

	struct blkio_net_stop *stop_msg = &buffer.stop;

	stop_msg->hdr.type = htole32(BLKIO_MSG_STOP);
	stop_msg->hdr.size = htole32(sizeof(*stop_msg));
	mywrite(fd, &stop_msg, sizeof(*stop_msg));

	while (!blkio_net_read(fd, &buffer)) {
		if (le32toh(buffer.hdr.type) != BLKIO_MSG_STATS)
			break;
		blkio_print_stats(&buffer.stats.stats);
	}

	if (le32toh(buffer.hdr.type) == BLKIO_MSG_STATUS) {
		struct blkio_net_status *status = &buffer.status;

		fprintf(stderr, "Server reported status:\n");
		fprintf(stderr, "\terror: %lu\n",
					(unsigned long)le32toh(status->error));
		fprintf(stderr, "\tdrops: %lu\n",
					(unsigned long)le32toh(status->drops));
	}

	close(fd);
}

struct blkio_client_conf {
	struct blkio_record_conf conf;
	const char *host;
	const char *port;
};

static const size_t buffer_size = 512 * 1024;
static const size_t buffer_count = 4;
static const size_t events_count = 10000;
static const int poll_timeout = 1000;

static int parse_args(int argc, char **argv, struct blkio_client_conf *conf)
{
	static const char *opts = "d:s:c:e:p:h:t:";
	static struct option long_opts[] = {
		{
			.name = "device",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'd'
		},
		{
			.name = "buffer_size",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 's'
		},
		{
			.name = "buffer_count",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'c'
		},
		{
			.name = "events_count",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'e'
		},
		{
			.name = "poll_timeout",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'p'
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
			.val = 't'
		},
		{
			.name = NULL
		}
	};

	/* fill in deafults */
	conf->conf.buffer_size = buffer_size;
	conf->conf.buffer_count = buffer_count;
	conf->conf.events_count = events_count;
	conf->conf.poll_timeout = poll_timeout;
	conf->conf.device = 0;

	int c, i;

	while ((c = getopt_long_only(argc, argv, opts, long_opts, 0)) != -1) {
		switch (c) {
		case 'd':
			conf->conf.device = optarg;
			break;
		case 's':
			i = atoi(optarg);
			if (i > 0) {
				conf->conf.buffer_size = i;
				break;
			}
			fprintf(stderr, "buffer_size must be positive integer\n");
			return -1;
		case 'c':
			i = atoi(optarg);
			if (i > 0) {
				conf->conf.buffer_count = i;
				break;
			}
			fprintf(stderr, "buffer_count must be positive integer\n");
			return -1;
		case 'e':
			i = atoi(optarg);
			if (i > 0) {
				conf->conf.events_count = i;
				break;
			}
			fprintf(stderr, "events_count must be positive integer\n");
			return -1;
		case 'p':
			i = atoi(optarg);
			if (i > 0) {
				conf->conf.poll_timeout = i;
				break;
			}
			fprintf(stderr, "poll_timeout must be positive interger\n");
			return -1;
		case 'h':
			conf->host = optarg;
			break;
		case 't':
			conf->port = optarg;
			break;
		default:
			fprintf(stderr, "unrecognized option: %s\n", optarg);
			return -1;
		}
	}

	return 0;
}

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		"-d --device - block device to trace [mandatory]\n" \
		"-s --buffer_size - blktrace buffer size [default=524288b]\n" \
		"-c --buffer_count - blktrace buffer count [default=4]\n" \
		"-e --events_count - stats account granularity [default=10000]\n" \
		"-p --poll_timeout - blktrace read timeout [deafult=1000ms]\n" \
		"-h --host - server host [mandatory]\n" \
		"-t --port - sever port [mandatory]\n";
	fprintf(stderr, "%s %s", name, usage);
}

int main(int argc, char **argv)
{
	struct blkio_client_conf conf;

	if (parse_args(argc, argv, &conf)) {
		show_usage(argv[0]);
		return 1;
	}

	int fd = client_socket(conf.host, conf.port, SOCK_STREAM);

	if (fd < 0) {
		perror("Cannot connect to server");
		return 1;
	}

	handle_signal(SIGINT, finish_tracing);
	handle_signal(SIGHUP, finish_tracing);
	handle_signal(SIGTERM, finish_tracing);
	blkio_net_client(&conf.conf, fd);

	return 0;
}
