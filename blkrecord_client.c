#include "blkrecord_new.h"
#include "network.h"
#include "file_io.h"
#include "utils.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <byteswap.h>
#include <unistd.h>
#include <fcntl.h>

#include <getopt.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>


static const char *filename;
static const char *host;
static const char *port;
static const char *device;
static size_t buffer_size = 512 * 1024;
static size_t buffer_count = 4;
static size_t events_count = 10000;
static int poll_timeout = 1000;

static void blkio_print_stats(struct blkio_stats *stats)
{
	printf("%llu-%llu: %lu reads, %lu writes\n",
		(unsigned long long) stats->begin_time,
		(unsigned long long) stats->end_time,
		(unsigned long) stats->reads,
		(unsigned long) stats->writes);
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

static volatile sig_atomic_t done;

static void finish_tracing(int sig)
{
	(void) sig;
	done = 1;
}

static void blkio_net_client(int sk, int fd)
{
	union blkio_net_storage buffer;
	struct blkio_net_start *start_msg = &buffer.start;

	memset(start_msg, 0, sizeof(*start_msg));
	start_msg->hdr.type = htole32(BLKIO_MSG_START);
	start_msg->hdr.size = htole32(sizeof(*start_msg));
	start_msg->buffer_size = htole32(buffer_size);
	start_msg->buffer_count = htole32(buffer_count);
	start_msg->events_count = htole32(events_count);
	start_msg->poll_timeout = htole32(poll_timeout);
	strcpy(start_msg->device, device);

	if (mywrite(sk, start_msg, sizeof(*start_msg))) {
		fprintf(stderr, "Cannot start tracing\n");
		return;
	}

	while (!done) {
		if (!blkio_net_read(sk, &buffer)) {
			if (le32toh(buffer.hdr.type) != BLKIO_MSG_STATS)
				break;
			mywrite(fd, &buffer.stats.stats,
						sizeof(buffer.stats.stats));
			blkio_print_stats(&buffer.stats.stats);
		} else {
			done = 1;
		}
	}

	struct blkio_net_stop *stop_msg = &buffer.stop;

	stop_msg->hdr.type = htole32(BLKIO_MSG_STOP);
	stop_msg->hdr.size = htole32(sizeof(*stop_msg));
	mywrite(sk, &stop_msg, sizeof(*stop_msg));

	while (!blkio_net_read(sk, &buffer)) {
		if (le32toh(buffer.hdr.type) != BLKIO_MSG_STATS)
			break;
		mywrite(fd, &buffer.stats.stats, sizeof(buffer.stats.stats));
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
}

static int parse_args(int argc, char **argv)
{
	static const char *opts = "d:o:s:c:e:p:h:t:";
	static struct option long_opts[] = {
		{
			.name = "device",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'd'
		},
		{
			.name = "output",
			.has_arg = required_argument,
			.flag = NULL,
			.val = 'o'
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

	int c, i;

	while ((c = getopt_long_only(argc, argv, opts, long_opts, 0)) != -1) {
		switch (c) {
		case 'd':
			device = optarg;
			break;
		case 'o':
			filename = optarg;
			break;
		case 's':
			i = atoi(optarg);
			if (i > 0) {
				buffer_size = i;
				break;
			}
			fprintf(stderr, "buffer_size must be positive integer\n");
			return -1;
		case 'c':
			i = atoi(optarg);
			if (i > 0) {
				buffer_count = i;
				break;
			}
			fprintf(stderr, "buffer_count must be positive integer\n");
			return -1;
		case 'e':
			i = atoi(optarg);
			if (i > 0) {
				events_count = i;
				break;
			}
			fprintf(stderr, "events_count must be positive integer\n");
			return -1;
		case 'p':
			i = atoi(optarg);
			if (i > 0) {
				poll_timeout = i;
				break;
			}
			fprintf(stderr, "poll_timeout must be positive interger\n");
			return -1;
		case 'h':
			host = optarg;
			break;
		case 't':
			port = optarg;
			break;
		default:
			fprintf(stderr, "unrecognized option: %s\n", optarg);
			return -1;
		}
	}

	if (!device) {
		fprintf(stderr, "you must specify device name\n");
		return -1;
	}

	if (!filename) {
		fprintf(stderr, "you must specify output filename name\n");
		return -1;
	}

	if (!host) {
		fprintf(stderr, "you must specify remote host\n");
		return -1;
	}

	if (!port) {
		fprintf(stderr, "you must specify remote port\n");
		return -1;
	}

	return 0;
}

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		"-d --device - block device to trace [mandatory]\n" \
		"-o --output - output file name [mandatory]\n" \
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
	if (parse_args(argc, argv)) {
		show_usage(argv[0]);
		return 1;
	}

	int fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if (fd < 0) {
		perror("Cannot open output file");
		return 1;
	}

	int sk = client_socket(host, port, SOCK_STREAM);
	if (fd < 0) {
		perror("Cannot connect to server");
		close(fd);
		return 1;
	}

	handle_signal(SIGINT, finish_tracing);
	handle_signal(SIGHUP, finish_tracing);
	handle_signal(SIGTERM, finish_tracing);

	blkio_net_client(sk, fd);

	close(fd);
	close(sk);

	return 0;
}
