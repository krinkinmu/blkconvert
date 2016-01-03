#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <byteswap.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include "blktrace_api.h"
#include "blkrecord.h"
#include "blkqueue.h"
#include "account.h"
#include "network.h"
#include "cbuffer.h"
#include "file_io.h"
#include "common.h"
#include "deamon.h"
#include "debug.h"
#include "utils.h"

static const unsigned sector_size = 512u;
static const int action_mask = BLK_TC_QUEUE | BLK_TC_COMPLETE;
static const char *debugfs_root_path = "/sys/kernel/debug";

static const char *block_device_name;
static const char *input_file_name;
static const char *output_file_name;
static int per_process, per_cpu;

static unsigned long min_time_interval = 1000ul;
static unsigned long buffer_size = 512 * 1024ul;
static unsigned long buffer_count = 4ul;

enum blkrecord_mode {
	BM_HOST,
	BM_SERVER,
	BM_CLIENT
};

static int record_mode;
static const char *node;
static const char *service;

static volatile sig_atomic_t done;

static void show_usage(const char *name)
{
	static const char *usage = "\n\n" \
		"-f <input file>    | --file=<input file>\n" \
		"-d <block device>  | --device=<block device>\n" \
		"-o <output file>   | --output=<output file>\n" \
		"-i <time interval> | --interval=<time interval>\n" \
		"-h <host>          | --host=<host>\n" \
		"-s <port>          | --port=<port>\n" \
		"-u                 | --per-cpu\n" \
		"-p                 | --per-process\n" \
		"-c                 | --client\n" \
		"-b                 | --server\n" \
		"\t-f Use specified blktrace file.\n" \
		"\t-d Block device to trace.\n" \
		"\t-o Ouput file. Default: stdout\n" \
		"\t-i Minimum sampling time interval in ms. Default: 1000\n" \
		"\t-h Host name/address to connect\n" \
		"\t-s Port to connect/listen\n" \
		"\t-u Gather per CPU stats.\n" \
		"\t-p Gather per process stats.\n" \
		"\t-c Client mode.\n" \
		"\t-b Server mode.\n";

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
			.name = "per-cpu",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 'u'
		},
		{
			.name = "per-process",
			.has_arg = no_argument,
			.flag = NULL,
			.val = 'p'
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
	static const char *opts = "f:d:o:i:h:s:upcb";

	long i;
	int c;

	while ((c = getopt_long(argc, argv, opts, long_opts, NULL)) >= 0) {
		switch (c) {
		case 'f':
			input_file_name = optarg;
			break;
		case 'd':
			block_device_name = optarg;
			break;
		case 'o':
			output_file_name = optarg;
			break;
		case 'i':
			i = atol(optarg);
			if (i <= 0) {
				ERR("Time interval must be positive\n");
				return 1;
			}
			min_time_interval = i;
			break;
		case 'h':
			node = optarg;
			break;
		case 's':
			service = optarg;
			break;
		case 'u':
			per_cpu = 1;
			break;
		case 'p':
			per_process = 1;
			break;
		case 'c':
			record_mode = BM_CLIENT;
			break;
		case 'b':
			record_mode = BM_SERVER;
			break;
		default:
			return 1;
		}
	}

	if (record_mode == BM_SERVER) {
		if (!service) {
			ERR("You must specify port in server mode\n");
			show_usage(argv[0]);
			return 1;
		}
		return 0;
	}

	if (record_mode == BM_CLIENT && (!service || !node)) {
		ERR("You must specify remote host and port in client mode\n");
		show_usage(argv[0]);
		return 1;
	}

	if (record_mode == BM_CLIENT && !block_device_name) {
		ERR("You must specify block device\n");
		show_usage(argv[0]);
		return 1;
	}

	if (record_mode == BM_HOST &&
				(!block_device_name && !input_file_name)) {
		ERR("Specify either input file or block device\n");
		show_usage(argv[0]);
		return 1;
	}

	if ((record_mode == BM_CLIENT || record_mode == BM_HOST) &&
				!output_file_name) {
		ERR("You must specify output file name\n");
		show_usage(argv[0]);
		return 1;
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
	trace->cpu = __bswap_32(trace->cpu);
	/* Other fields aren't interesting so far */
	return 0;
}

static int blk_io_trace_read(int fd, struct blk_io_trace *trace)
{
	size_t to_skip;

	if (myread(fd, (void *)trace, sizeof(*trace)))
		return 1;

	if (blk_io_trace_to_cpu(trace))
		return 1;

	to_skip = trace->pdu_len;
	while (to_skip) {
		char buf[512];

		if (myread(fd, buf, MIN(to_skip, sizeof(buf))))
			return 1;
		to_skip -= MIN(to_skip, sizeof(buf)); 
	}
	return 0;
}

static int blk_io_trace_queue_event(const struct blk_io_trace *trace)
{
	return ((trace->action & BLK_TC_ACT(BLK_TC_QUEUE)) &&
		((trace->action & 0xFFFFu) == __BLK_TA_QUEUE));
}

static int blk_io_trace_complete_event(const struct blk_io_trace *trace)
{
	return ((trace->action & 0xFFFFu) == __BLK_TA_COMPLETE) &&
		(trace->action & BLK_TC_ACT(BLK_TC_COMPLETE));
}

static int blk_io_trace_write_event(const struct blk_io_trace *trace)
{
	return (trace->action & BLK_TC_ACT(BLK_TC_WRITE)) != 0;
}

static int blk_io_trace_sync_event(const struct blk_io_trace *trace)
{
	return (trace->action & BLK_TC_ACT(BLK_TC_SYNC)) != 0;
}

static int blk_io_trace_fua_event(const struct blk_io_trace *trace)
{
	return (trace->action & BLK_TC_ACT(BLK_TC_FUA)) != 0;
}

static int blk_io_trace_accept_event(const struct blk_io_trace *trace)
{
	if (!trace->bytes)
		return 0;

	return blk_io_trace_queue_event(trace) ||
				blk_io_trace_complete_event(trace);
}

static unsigned char blk_io_trace_type(const struct blk_io_trace *trace)
{
	unsigned char type = 0;

	if (blk_io_trace_queue_event(trace))
		type |= QUEUE_MASK;
	if (blk_io_trace_write_event(trace))
		type |= WRITE_MASK;
	if (blk_io_trace_sync_event(trace))
		type |= SYNC_MASK;
	if (blk_io_trace_fua_event(trace))
		type |= FUA_MASK;
	return type;
}

static int mygzwrite(gzFile zfd, const char *buf, size_t size)
{
	size_t written = 0;

	while (written != size) {
		int ret = gzwrite(zfd, buf + written, size - written);

		if (!ret) {
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

static int process_info_append(struct process_info *pi,
			const struct blkio_event *event)
{
	static const unsigned long grow_n = 3;
	static const unsigned long grow_d = 2;

	if (pi->size == pi->capacity) {
		unsigned long new_capacity = (pi->capacity * grow_n) / grow_d;
		struct blkio_event *events = realloc(pi->events,
					sizeof(*event) * new_capacity);

		if (!events) {
			ERR("process_info events reallocation failed\n");
			return 1;
		}

		pi->capacity = new_capacity;
		pi->events = events;
	}
	pi->events[pi->size++] = *event;
	return 0;
}

static struct process_info *process_info_alloc(void)
{
	static unsigned long CAPACITY = 512;

	struct process_info *pi = malloc(sizeof(struct process_info));

	if (!pi) {
		ERR("Process info allocation failed\n");
		return 0;
	}

	pi->events = calloc(CAPACITY, sizeof(*pi->events));
	if (!pi->events) {
		ERR("blkio_event per process array allocation failed\n");
		free(pi);
		return 0;
	}

	pi->capacity = CAPACITY;
	pi->size = 0;
	return pi;
}

static void process_info_free(struct process_info *pi)
{
	free(pi->events);
	free(pi);
}

static void process_info_dump(struct blkio_record_context *ctx,
			struct process_info *pi)
{
	struct blkio_stats st;

	if (!account_events(pi->events, pi->size, &st)) {
		if (st.reads + st.writes == 0)
			return;

		mygzwrite(ctx->zofd, (const char *)&st, sizeof(st));
	}	
}

static void blkio_record_context_dump(struct blkio_record_context *ctx,
			unsigned long long time)
{
	static const unsigned long long NS = 1000000ull;
	const unsigned long long TI = NS * min_time_interval;

	struct list_head *head = &ctx->head;
	struct list_head *pos = head->next;

	while (pos != head) {
		struct process_info *pi;

		pi = PROCESS_INFO(pos);
		pos = pos->next;

		if (pi->events->time + TI > time)
			break;

		process_info_dump(ctx, pi);
		list_unlink(&pi->head);
		process_info_free(pi);
	}
}

static void blkio_event_handle_queue(struct blkio_record_context *ctx,
			const struct blkio_event *event)
{
	struct blkio_queue *q = IS_WRITE(event->type)
				? &ctx->write : &ctx->read;
	struct blkio *io = blkio_alloc(q);
	struct list_head *head, *pos;
	int found;

	if (!io)
		return;

	io->from = event->from;
	io->to = event->to;
	io->pid = event->pid;
	io->cpu = event->cpu;

	if (blkio_insert(q, io)) {
		blkio_free(q, io);
		return;
	}

	head = &ctx->head;
	pos = head->next;
	found = 0;

	for (; pos != head; pos = pos->next) {
		struct process_info *pi = PROCESS_INFO(pos);

		if (pi->pid == event->pid && pi->cpu == event->cpu) {
			process_info_append(pi, event);
			found = 1;
			break;
		}
	}

	if (!found) {
		struct process_info *pi = process_info_alloc();

		if (!pi)
			return;

		pi->pid = event->pid;
		pi->cpu = event->cpu;
		list_link_before(head, &pi->head);
		process_info_append(pi, event);
	}
}

static void blkio_event_handle_complete(struct blkio_record_context *ctx,
			const struct blkio_event *event)
{
	struct blkio_queue *q = IS_WRITE(event->type)
				? &ctx->write : &ctx->read;
	struct blkio *first, *last;

	blkio_lookup(q, event->from, event->to, &first, &last);

	while (first != last) {
		struct list_head *head, *pos;
		struct blkio *queue = first;

		const unsigned long long from = queue->from;
		const unsigned long long to = queue->to;
		const unsigned long pid = queue->pid;
		const unsigned long cpu = queue->cpu;

		first = BLKIO(rb_next(&first->rb_node));

		if (from < event->from && to > event->to) {
			struct blkio *tail = blkio_alloc(q);

			queue->to = event->from;

			if (!tail)
				continue;

			tail->from = event->to;
			tail->to = to;
			tail->pid = pid;
			tail->cpu = cpu;

			if (blkio_insert(q, tail)) {
				ERR("Cannot insert tail after split\n");
				blkio_free(q, tail);
			}
		} else if (from >= event->from && to <= event->to) {
			blkio_remove(q, queue);
		} else if (from < event->from) {
			queue->to = event->from;
		} else if (to > event->to) {
			queue->from = event->to;
		}
		
		head = &ctx->head;
		pos = head->next;

		for (; pos != head; pos = pos->next) {
			struct process_info *pi = PROCESS_INFO(pos);

			if (pi->pid == queue->pid && pi->cpu == queue->cpu) {
				process_info_append(pi, event);
				break;
			}
		}
	}
}

static void blkio_event_handle(struct blkio_record_context *ctx,
			const struct blkio_event *event)
{
	blkio_record_context_dump(ctx, event->time);
	if (IS_QUEUE(event->type))
		blkio_event_handle_queue(ctx, event);
	else
		blkio_event_handle_complete(ctx, event);
}

static void blktrace_submit(struct blkio_record_context *ctx,
			const struct blk_io_trace *trace)
{
	if (!blk_io_trace_accept_event(trace))
		return;

	struct blkio_event event;

	event.time = trace->time;
	event.from = trace->sector;
	event.to = event.from + MAX(1, trace->bytes / sector_size);
	event.pid = per_process ? trace->pid : 0;
	event.cpu = per_cpu ? trace->cpu : 0;
	event.type = blk_io_trace_type(trace);

	blkio_event_handle(ctx, &event);
}

static void blkrecord(struct blkio_record_context *ctx, int fd)
{
	struct blk_io_trace trace;

	while (!done && !blk_io_trace_read(fd, &trace))
		blktrace_submit(ctx, &trace);
}

static void finish_blkrecord(int sig)
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

static void traces_from_file(struct blkio_record_context *ctx)
{
	int ifd = open(input_file_name, 0);

	if (ifd < 0) {
		perror("Cannot open input file");
		return;
	}

	blkrecord(ctx, ifd);
	close(ifd);
}

static int blkio_record_context_setup(struct blkio_record_context *ctx)
{
	int ofd = open(output_file_name, O_CREAT | O_TRUNC | O_WRONLY,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if (ofd < 0) {
		perror("Cannot open output file");
		return 1;
	}

	gzFile zofd = gzdopen(ofd, "wb");

	if (!zofd) {
		ERR("Cannot allocate enough memory for zlib\n");
		close(ofd);
		return 1;
	}

	blkio_record_context_init(ctx);
	ctx->zofd = zofd;
	return 0;
}

static void blkio_record_context_release(struct blkio_record_context *ctx)
{
	blkio_record_context_dump(ctx, ~0ull);
	blkio_record_context_finit(ctx);
	gzclose(ctx->zofd);
}

struct blktrace_ctx {
	struct blk_user_trace_setup conf;
	struct pollfd *pfds;
	struct cbuffer *bufs;
	int cpus;
	int fd;
};

static int blktrace_start(struct blktrace_ctx *ctx)
{
	if (ioctl(ctx->fd, BLKTRACESTART) < 0) {
		ERR("BLKTRACESTART failed with error (%d)\n", errno);
		return 1;
	}

	return 0;
}

static void blktrace_stop(struct blktrace_ctx *ctx)
{ ioctl(ctx->fd, BLKTRACESTOP); }

static void blktrace_ctx_release(struct blktrace_ctx *ctx)
{
	if (ctx->fd <= 0)
		return;

	blktrace_stop(ctx);
	ioctl(ctx->fd, BLKTRACETEARDOWN);

	if (ctx->pfds) {
		for (int i = 0; i != ctx->cpus; ++i) {
			if (ctx->pfds[i].fd <= 0)
				break;
			close(ctx->pfds[i].fd);
		}
		free(ctx->pfds);
	}

	if (ctx->bufs) {
		for (int i = 0; i != ctx->cpus; ++i)
			cbuffer_release(ctx->bufs + i);
		free(ctx->bufs);
	}

	close(ctx->fd);
}

static int blktrace_ctx_setup(struct blktrace_ctx *ctx, int fd)
{
	char filename[MAXPATHLEN + 64];

	memset(ctx, 0, sizeof(*ctx));
	ctx->conf.act_mask = action_mask;
	ctx->conf.buf_size = buffer_size;
	ctx->conf.buf_nr = buffer_count;

	ctx->cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (ctx->cpus < 0) {
		ERR("sysconf(_SC_NPROCESSORS_CONF) failed with %d\n", errno);
		return 1;
	}

	ctx->fd = open(block_device_name, O_RDONLY | O_NONBLOCK);
	if (ctx->fd < 0) {
		ERR("Cannot open device %s (%d)\n", block_device_name, errno);
		return 1;
	}

	ctx->pfds = calloc(ctx->cpus + 1, sizeof(*ctx->pfds));
	if (!ctx->pfds) {
		ERR("Cannot allocate poll descriptors\n");
		blktrace_ctx_release(ctx);
		return 1;
	}

	ctx->bufs = calloc(ctx->cpus, sizeof(*ctx->bufs));
	if (!ctx->bufs) {
		ERR("Cannot allocate read buffers\n");
		blktrace_ctx_release(ctx);
		return 1;
	}

	for (int i = 0; i != ctx->cpus; ++i) {
		if (cbuffer_setup(ctx->bufs + i, buffer_size)) {
			ERR("Cannot allocate read buffers\n");
			blktrace_ctx_release(ctx);
			return 1;
		}
	}

	if (ioctl(ctx->fd, BLKTRACESETUP, &ctx->conf) < 0) {
		ERR("Cannot setup blktrace\n");
		blktrace_ctx_release(ctx);
		return 1;
	}

	for (int i = 0; i != ctx->cpus; ++i) {
		snprintf(filename, sizeof(filename), "%s/block/%s/trace%d",
			debugfs_root_path, ctx->conf.name, i);

		ctx->pfds[i].fd = open(filename, O_RDONLY | O_NONBLOCK);
		if (ctx->pfds[i].fd < 0) {
			blktrace_ctx_release(ctx);
			return 1;
		}
		ctx->pfds[i].events = POLLIN;
	}

	ctx->pfds[ctx->cpus].fd = fd;
	ctx->pfds[ctx->cpus].events = POLLIN;

	return 0;
}

static int dump_device_traces(struct cbuffer *buffer,
			struct blkio_record_context *rctx)
{
	int ret = 0;

	while (1) {
		struct blk_io_trace trace;
		const size_t sz = sizeof(trace);

		if (cbuffer_read(buffer, &trace, sz) != sz)
			break;

		if (blk_io_trace_to_cpu(&trace)) {
			done = 1;
			ret = 1;
			break;
		}

		if (cbuffer_size(buffer) < sz + trace.pdu_len)
			break;

		cbuffer_advance(buffer, sz + trace.pdu_len);
		blktrace_submit(rctx, &trace);
	}

	return ret;
}

static void read_device_traces(struct blktrace_ctx *tctx,
			struct blkio_record_context *rctx, bool force)
{
	struct pollfd *pfd = tctx->pfds;
	struct cbuffer *buf = tctx->bufs;

	for (int i = 0; i != tctx->cpus; ++i) {
		if (!force && (pfd[i].revents & POLLIN) == 0)
			continue;

		ssize_t ret = cbuffer_fill(buf + i, pfd[i].fd);

		while (ret > 0) {
			if (cbuffer_full(buf + i))
				if (dump_device_traces(buf + i, rctx))
					return;

			ret = cbuffer_fill(buf + i, pfd[i].fd);
		}

		if (ret != 0 && errno != EAGAIN) {
			pfd[i].events = 0;
			pfd[i].revents = 0;
		}

		if (dump_device_traces(buf + i, rctx))
			return;
	}
}

static void traces_from_device(struct blkio_record_context *rctx, int fd)
{
	const int timeout = 500;
	struct blktrace_ctx tctx;

	if (blktrace_ctx_setup(&tctx, fd))
		return;
	
	if (!blktrace_start(&tctx)) {
		while (!done) {
			int ret = poll(tctx.pfds, tctx.cpus + 1, timeout);

			if (ret <= 0)
				continue;

			if ((tctx.pfds[tctx.cpus].revents & POLLIN) != 0) {
				ERR("Finishing\n");
				break;
			}

			read_device_traces(&tctx, rctx, false);
		}
		blktrace_stop(&tctx);
		read_device_traces(&tctx, rctx, true);
	}
	blktrace_ctx_release(&tctx);
}

#define RECORD_CMD_MAX_LENGTH 4096

struct record_cmd_header {
	__u32 size;
	__u32 device;
	__u32 interval;
	__u32 per_process;
	__u32 per_cpu;
};

static void handle_connection(int fd)
{
	const int sz = sizeof(struct record_cmd_header);
	static char buffer[RECORD_CMD_MAX_LENGTH];

	ERR("Handle input connection\n");
	if (myread(fd, buffer, sz)) {
		ERR("Cannot read command header\n");
		close(fd);
		return;
	}

	struct record_cmd_header header;

	memcpy((char *)&header, buffer, sz);

	header.size = le32toh(header.size);
	header.device = le32toh(header.device);
	header.interval = le32toh(header.interval);
	header.per_process = le32toh(header.per_process);
	header.per_cpu = le32toh(header.per_cpu);

	if (myread(fd, buffer + sz, header.size - sz)) {
		ERR("Cannot read command header\n");
		close(fd);
		return;
	}

	block_device_name = buffer + header.device;
	per_process = (header.per_process != 0);
	per_cpu = (header.per_cpu != 0);

	gzFile zofd = gzdopen(fd, "wb");
	if (zofd) {
		struct blkio_record_context ctx;
		
		blkio_record_context_init(&ctx);
		ctx.zofd = zofd;

		traces_from_device(&ctx, fd);

		blkio_record_context_dump(&ctx, ~0ull);
		blkio_record_context_finit(&ctx);
		gzclose(zofd);
	} else {
		ERR("Cannot allocate zlib buffer\n");
		close(fd);
	}
	ERR("Input connection closed\n");
}

static void blkrecord_server(void)
{
	handle_signal(SIGINT, finish_blkrecord);
	handle_signal(SIGHUP, finish_blkrecord);
	handle_signal(SIGTERM, finish_blkrecord);
	handle_signal(SIGALRM, finish_blkrecord);
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

	ERR("blkrecordd started\n");
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
	ERR("blkrecordd finished\n");
}

static void run_client(void)
{
	const int sz = sizeof(struct record_cmd_header);
	char buffer[RECORD_CMD_MAX_LENGTH];

	int dev_len = strlen(block_device_name);
	int size = sz + dev_len + 1;

	memset(buffer, 0, RECORD_CMD_MAX_LENGTH);

	struct record_cmd_header header;

	header.size = htole32(size);
	header.device = htole32(sz);
	header.interval = htole32(min_time_interval);
	header.per_process = htole32(per_process);
	header.per_cpu = htole32(per_cpu);

	memcpy(buffer, &header, sz);
	memcpy(buffer + sz, block_device_name, dev_len + 1);

	int ofd = open(output_file_name, O_CREAT | O_TRUNC | O_WRONLY,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);

	if (ofd == -1) {
		ERR("Cannot create output file\n");
		return;
	}

	int ifd = client_socket(node, service, SOCK_STREAM);

	if (ifd == -1) {
		ERR("Cannot connect to server\n");
		close(ofd);
		return;
	}

	if (mywrite(ifd, buffer, size)) {
		ERR("Failed to send record command\n");
		close(ifd);
		close(ofd);
		return;
	}

	handle_signal(SIGINT, finish_blkrecord);
	handle_signal(SIGHUP, finish_blkrecord);
	handle_signal(SIGTERM, finish_blkrecord);
	handle_signal(SIGALRM, finish_blkrecord);

	char buf[4096];
	int ret;

	while (!done) {
		ret = read(ifd, buf, sizeof(buf));
		if (ret == 0) {
			ERR("Remote connection closed\n");
			break;
		}

		if (ret > 0 && mywrite(ofd, buf, ret)) {
			ERR("Failed to write received data to the file\n");
			break;
		}
	}

	ERR("Finishing\n");
	mywrite(ifd, buffer, size);
	ret = read(ifd, buf, sizeof(buf));
	while (ret > 0) {
		if (mywrite(ofd, buf, ret)) {
			ERR("Failed to write received data to the file\n");
			break;
		}
		ret = read(ifd, buf, sizeof(buf));
	}
	ERR("Finished\n");

	close(ifd);
	close(ofd);
}

int main(int argc, char **argv)
{
	if (parse_args(argc, argv)) {
		show_usage(argv[0]);
		return 1;
	}

	switch (record_mode) {
	case BM_HOST: {
		handle_signal(SIGINT, finish_blkrecord);
		handle_signal(SIGHUP, finish_blkrecord);
		handle_signal(SIGTERM, finish_blkrecord);
		handle_signal(SIGALRM, finish_blkrecord);

		struct blkio_record_context ctx;

		if (!blkio_record_context_setup(&ctx)) {
			if (input_file_name)
				traces_from_file(&ctx);
			else
				traces_from_device(&ctx, -1);
			blkio_record_context_release(&ctx);
		}

		break;
	}
	case BM_CLIENT:
		run_client();
		break;
	case BM_SERVER:
		if (deamon("blkrecordd", &blkrecord_server))
			ERR("Cannot run deamon process (%d)\n", errno);
		break;
	}

	return 0;
}
