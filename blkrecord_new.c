#include "blkrecord_new.h"
#include "blktrace_api.h"
#include "utils.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <byteswap.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>


static struct blkio_buffer *blkio_alloc_buffer(size_t size)
{
	void *ptr = malloc(sizeof(struct blkio_buffer) + size);

	if (!ptr)
		return 0;

	struct blkio_buffer *buffer = ptr;

	memset(buffer, 0, sizeof(*buffer));
	list_head_init(&buffer->head);
	buffer->data = (void *)(buffer + 1);
	return buffer;
}

static void blkio_free_buffer(struct blkio_buffer *buf)
{ free(buf); }

static struct blkio_tracer *blkio_alloc_tracer(void)
{
	struct blkio_tracer *tracer = malloc(sizeof(struct blkio_tracer));

	if (!tracer)
		return 0;

	list_head_init(&tracer->link);
	list_head_init(&tracer->bufs);
	assert(!pthread_mutex_init(&tracer->lock, NULL));
	assert(!pthread_cond_init(&tracer->cond, NULL));
	CPU_ZERO(&tracer->cpuset);
	tracer->state = TRACE_WAIT;
	tracer->fd = -1;
	return tracer;
}

static void blkio_free_tracer(struct blkio_tracer *tracer)
{
	assert(!pthread_mutex_destroy(&tracer->lock));
	assert(!pthread_cond_destroy(&tracer->cond));
	free(tracer);
}

static void blkio_tracer_wait(struct blkio_tracer *tracer)
{
	pthread_mutex_lock(&tracer->lock);
	while (tracer->state == TRACE_WAIT)
		pthread_cond_wait(&tracer->cond, &tracer->lock);
	pthread_mutex_unlock(&tracer->lock);
}

static void blkio_processor_wait(struct blkio_processor *proc)
{
	pthread_mutex_lock(&proc->lock);
	while (proc->state == TRACE_WAIT)
		pthread_cond_wait(&proc->cond, &proc->lock);
	pthread_mutex_unlock(&proc->lock);
}

static void blkio_processor_insert_buffer(struct blkio_processor *proc,
			struct blkio_buffer *buf)
{
	struct rb_node **plink = &proc->buffers.rb_node;
	struct rb_node *parent = 0;

	while (*plink) {
		struct blkio_buffer *b = rb_entry(*plink, struct blkio_buffer,
					node);

		parent = *plink;

		if (b->timestamp <= buf->timestamp)
			plink = &parent->rb_right;
		else
			plink = &parent->rb_left;
	}

	rb_link_node(&buf->node, parent, plink);
	rb_insert_color(&buf->node, &proc->buffers);
}

static void blkio_processor_populate_list(struct blkio_processor *proc,
			struct list_head *head)
{
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_buffer *buf = list_entry(ptr, struct blkio_buffer,
					head);

		ptr = ptr->next;
		blkio_processor_insert_buffer(proc, buf);
	}
}

static void blkio_processor_populate(struct blkio_processor *proc)
{
	struct blkio_record_ctx *ctx = proc->ctx;
	struct list_head *head = &ctx->tracers;
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_tracer *tracer = list_entry(ptr,
					struct blkio_tracer, link);

		ptr = ptr->next;

		struct list_head buffers;

		list_head_init(&buffers);

		pthread_mutex_lock(&tracer->lock);
		list_splice(&buffers, &tracer->bufs);
		pthread_mutex_unlock(&tracer->lock);

		blkio_processor_populate_list(proc, &buffers);
	}
}

static struct blkio_buffer *blkio_processor_peek(struct blkio_processor *proc)
{
	struct rb_node *first = rb_first(&proc->buffers);

	if (!first)
		return 0;

	return rb_entry(first, struct blkio_buffer, node);
}

static void blkio_processor_unlink(struct blkio_processor *proc,
			struct blkio_buffer *buf)
{ rb_erase(&buf->node, &proc->buffers); }

static int blkio_trace_to_cpu(struct blk_io_trace *trace)
{
	if ((trace->magic & 0xFFFFFF00ul) == BLK_IO_TRACE_MAGIC)
		return 0;

	trace->magic = __bswap_32(trace->magic);
	if ((trace->magic & 0xFFFFFF00ul) != BLK_IO_TRACE_MAGIC)
		return -1;

	trace->time = __bswap_64(trace->time);
	trace->sector = __bswap_64(trace->sector);
	trace->bytes = __bswap_32(trace->bytes);
	trace->action = __bswap_32(trace->action);
	trace->pdu_len = __bswap_16(trace->pdu_len);
	trace->pid = __bswap_32(trace->pid);
	trace->cpu = __bswap_32(trace->cpu);
	return 0;
}

static void blkio_print_trace(struct blk_io_trace *trace)
{
	printf("time: %llu, sector: %llu, bytes: %lu, pid: %lu, cpu: %lu\n",
		(unsigned long long) trace->time,
		(unsigned long long) trace->sector,
		(unsigned long) trace->bytes,
		(unsigned long) trace->pid,
		(unsigned long) trace->cpu);
}

static void blkio_processor_handle_buffer(struct blkio_buffer *buf)
{
	for (size_t i = 0; i != buf->count; ++i)
		blkio_print_trace(buf->data + i);
	blkio_free_buffer(buf);
}

static void blkio_processor_handle(struct blkio_processor *proc)
{
	struct blkio_buffer *buf = blkio_processor_peek(proc);

	while (buf) {
		struct rb_node *next = rb_next(&buf->node);

		blkio_processor_unlink(proc, buf);
		blkio_processor_handle_buffer(buf);
		buf = next ? (rb_entry(next, struct blkio_buffer, node)) : 0;
	}
}

static void *blkio_processor_main(void *data)
{
	struct blkio_processor *proc = data;

	blkio_processor_wait(proc);

	while (proc->state == TRACE_RUN) {
		blkio_processor_populate(proc);
		blkio_processor_handle(proc);
		pthread_yield();
	}

	blkio_processor_populate(proc);
	blkio_processor_handle(proc);

	return 0;
}

static void blkio_submit_traces(struct blkio_tracer *tracer,
			struct blkio_buffer *traces)
{
	if (!traces)
		return;

	if (!traces->count) {
		blkio_free_buffer(traces);
		return;
	}

	traces->timestamp = traces->data[0].time;
	pthread_mutex_lock(&tracer->lock);
	list_link_before(&tracer->bufs, &traces->head);
	pthread_mutex_unlock(&tracer->lock);
}

static int blkio_accept_trace(struct blk_io_trace *trace)
{
	if (!trace->bytes)
		return 0;

	if ((trace->action & BLK_TC_ACT(BLK_TC_QUEUE)) &&
	    (trace->action & 0xFFFFu) == __BLK_TA_QUEUE)
		return 1;

	if ((trace->action & BLK_TC_ACT(BLK_TC_COMPLETE)) &&
	    (trace->action & 0xFFFFu) == __BLK_TA_COMPLETE)
		return 1;

	return 0;
}

static int blkio_read_traces(struct blkio_tracer *tracer,
			char *buffer, size_t *size)
{
	const size_t trace_size = sizeof(struct blk_io_trace);
	const size_t buffer_size = tracer->ctx->conf->buffer_size;
	const size_t max_count = buffer_size / trace_size;

	ssize_t rd = read(tracer->fd, buffer + *size, buffer_size);
	struct blkio_buffer *traces = 0;
	size_t pos = 0;

	while (rd > 0) {
		*size += rd;

		while (*size - pos >= trace_size) {
			if (!traces)
				traces = blkio_alloc_buffer(buffer_size);

			if (!traces)
				return -1;

			struct blk_io_trace *trace =
						traces->data + traces->count;

			memcpy(trace, buffer + pos, trace_size);

			if (blkio_trace_to_cpu(trace))
				return -1;

			const size_t skip = trace_size + trace->pdu_len;

			if (skip > *size - pos)
				break;

			pos += skip;

			if (!blkio_accept_trace(trace))
				continue;

			if (++traces->count == max_count) {
				blkio_submit_traces(tracer, traces);
				traces = 0;
			}
		}

		if (pos != *size)
			memmove(buffer, buffer + pos, *size - pos);
		*size -= pos;
		pos = 0;
		rd = read(tracer->fd, buffer + *size, buffer_size);
	}

	blkio_submit_traces(tracer, traces);
	return 0;
}

static void *blkio_tracer_main(void *data)
{
	struct blkio_tracer *tracer = data;
	struct blkio_record_ctx *ctx = tracer->ctx;
	struct pollfd pollfd;

	char *buffer = malloc(3 * ctx->conf->buffer_size);
	size_t size = 0;

	if (!buffer)
		return 0;

	pthread_setaffinity_np(tracer->thread, sizeof(tracer->cpuset),
			&tracer->cpuset);

	pollfd.fd = tracer->fd;
	pollfd.events = POLLIN;
	pollfd.revents = 0;

	blkio_tracer_wait(tracer);
	while (tracer->state == TRACE_RUN) {
		const int rc = poll(&pollfd, 1, 100);

		if (rc < 0) {
			perror("Poll failed: ");
			continue;
		}

		if (!(pollfd.revents & POLLIN))
			continue;

		if (blkio_read_traces(tracer, buffer, &size)) {
			// Everything is bad.. We are out of memory...
			free(buffer);
			return 0;
		}
	}

	blkio_read_traces(tracer, buffer, &size);
	free(buffer);
	return 0;
}

static int blkio_trace_open_cpu(struct blkio_record_ctx *ctx, int cpu)
{
	char filename[PATH_MAX + 64];

	const size_t size = snprintf(filename, sizeof(filename),
				"%s/block/%s/trace%d",
				ctx->conf->debugfs,
				ctx->trace_setup.name,
				cpu);

	assert(size < sizeof(filename));

	return open(filename, O_RDONLY | O_NONBLOCK);
}

static int blkio_start_tracer(struct blkio_record_ctx *ctx,
			struct blkio_tracer *tracer, int cpu)
{
	CPU_SET(cpu, &tracer->cpuset);
	tracer->ctx = ctx;
	tracer->fd = blkio_trace_open_cpu(ctx, cpu);
	if (tracer->fd < 0) {
		perror("Cannot open trace file: ");
		return -1;
	}

	if (pthread_create(&tracer->thread, 0, blkio_tracer_main, tracer)) {
		close(tracer->fd);
		tracer->fd = -1;
		return -1;
	}
	return 0;
}

static int blkio_start_processor(struct blkio_processor *proc)
{
	if (pthread_create(&proc->thread, 0, blkio_processor_main, proc))
		return -1;
	return 0;
}

static void blkio_wait_tracer(struct blkio_tracer *tracer)
{
	assert(!pthread_join(tracer->thread, NULL));
	if (tracer->fd >= 0)
		close(tracer->fd);
	tracer->fd = -1;
}

static void blkio_tracers_set_state(struct blkio_record_ctx *ctx, int state)
{
	struct list_head *head = &ctx->tracers;
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_tracer *tracer = list_entry(ptr,
					struct blkio_tracer, link);

		ptr = ptr->next;

		pthread_mutex_lock(&tracer->lock);
		tracer->state = state;
		pthread_cond_broadcast(&tracer->cond);
		pthread_mutex_unlock(&tracer->lock);
	}
}

static void blkio_stop_tracers(struct blkio_record_ctx *ctx)
{ blkio_tracers_set_state(ctx, TRACE_STOP); }

static void blkio_run_tracers(struct blkio_record_ctx *ctx)
{ blkio_tracers_set_state(ctx, TRACE_RUN); }

static void blkio_run_processor(struct blkio_record_ctx *ctx)
{
	pthread_mutex_lock(&ctx->processor.lock);
	ctx->processor.state = TRACE_RUN;
	pthread_cond_broadcast(&ctx->processor.cond);
	pthread_mutex_unlock(&ctx->processor.lock);
}

static void blkio_stop_processor(struct blkio_record_ctx *ctx)
{
	pthread_mutex_lock(&ctx->processor.lock);
	ctx->processor.state = TRACE_STOP;
	pthread_cond_broadcast(&ctx->processor.cond);
	pthread_mutex_unlock(&ctx->processor.lock);
}

static void blkio_wait_processor(struct blkio_record_ctx *ctx)
{ assert(!pthread_join(ctx->processor.thread, NULL)); }

static void blkio_wait_tracers(struct blkio_record_ctx *ctx)
{
	struct list_head *head = &ctx->tracers;
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_tracer *tracer = list_entry(ptr,
					struct blkio_tracer, link);

		ptr = ptr->next;
		blkio_wait_tracer(tracer);
	}
}

static void blkio_destroy_tracers(struct blkio_record_ctx *ctx)
{
	struct list_head *head = &ctx->tracers;
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_tracer *tracer = list_entry(ptr,
					struct blkio_tracer, link);

		ptr = ptr->next;
		blkio_free_tracer(tracer);
	}
}

static int blkio_create_tracers(struct blkio_record_ctx *ctx)
{
	int rc = 0;

	for (int i = 0; i != ctx->cpus; ++i) {
		struct blkio_tracer *tracer = blkio_alloc_tracer();

		if (!tracer) {
			rc = -1;
			break;
		}

		if (blkio_start_tracer(ctx, tracer, i)) {
			blkio_free_tracer(tracer);
			rc = -1;
			break;
		}

		list_link_before(&ctx->tracers, &tracer->link);
	}

	if (rc) {
		blkio_stop_tracers(ctx);
		blkio_wait_tracers(ctx);
	}

	return rc;
}

static void blkio_destroy_processor(struct blkio_record_ctx *ctx)
{
	assert(!pthread_mutex_destroy(&ctx->processor.lock));
	assert(!pthread_cond_destroy(&ctx->processor.cond));	
}

static int blkio_create_processor(struct blkio_record_ctx *ctx)
{
	assert(!pthread_mutex_init(&ctx->processor.lock, NULL));
	assert(!pthread_cond_init(&ctx->processor.cond, NULL));
	ctx->processor.state = TRACE_WAIT;
	ctx->processor.ctx = ctx;
	return blkio_start_processor(&ctx->processor);
}

static int blkio_trace_start(struct blkio_record_ctx *ctx)
{
	if (ioctl(ctx->fd, BLKTRACESTART))
		return -1;
	blkio_run_processor(ctx);
	blkio_run_tracers(ctx);
	return 0;
}

static void blkio_trace_stop(struct blkio_record_ctx *ctx)
{
	ioctl(ctx->fd, BLKTRACESTOP);
	blkio_stop_tracers(ctx);
	blkio_wait_tracers(ctx);
	blkio_stop_processor(ctx);
	blkio_wait_processor(ctx);
}

static void blkio_record_ctx_release(struct blkio_record_ctx *ctx)
{
	blkio_destroy_tracers(ctx);
	blkio_destroy_processor(ctx);
	if (ctx->fd >= 0) {
		ioctl(ctx->fd, BLKTRACESTOP);
		ioctl(ctx->fd, BLKTRACETEARDOWN);
		close(ctx->fd);
	}
}

static int blkio_record_ctx_setup(struct blkio_record_ctx *ctx,
			struct blkio_record_conf *conf)
{
	memset(ctx, 0, sizeof(*ctx));
	list_head_init(&ctx->tracers);

	ctx->trace_setup.act_mask = BLK_TC_QUEUE | BLK_TC_COMPLETE;
	ctx->trace_setup.buf_size = conf->buffer_size;
	ctx->trace_setup.buf_nr = conf->buffer_count;

	ctx->conf = conf;
	ctx->cpus = -1;
	ctx->fd = -1;

	ctx->cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (ctx->cpus < 0) {
		perror("Cannot get number of cpu: ");
		blkio_record_ctx_release(ctx);
		return -1;
	}

	ctx->fd = open(conf->device, O_RDONLY | O_NONBLOCK);
	if (ctx->fd < 0) {
		perror("Cannot open block device: ");
		blkio_record_ctx_release(ctx);
		return -1;
	}

	if (ioctl(ctx->fd, BLKTRACESETUP, &ctx->trace_setup) < 0) {
		perror("BLKTRACESETUP failed: ");
		blkio_record_ctx_release(ctx);
		return -1;
	}

	if (blkio_create_processor(ctx)) {
		blkio_record_ctx_release(ctx);
		return -1;
	}

	if (blkio_create_tracers(ctx)) {
		blkio_stop_processor(ctx);
		blkio_wait_processor(ctx);
		blkio_record_ctx_release(ctx);
		return -1;
	}

	return 0;
}

static int blkio_get_drops(struct blkio_record_ctx *ctx)
{
	char filename[PATH_MAX + 64];

	const size_t size = snprintf(filename, sizeof(filename),
				"%s/block/%s/dropped",
				ctx->conf->debugfs,
				ctx->trace_setup.name);

	assert(size < sizeof(filename));

	int fd = open(filename, O_RDONLY);

	if (fd < 0) {
		perror("Cannot open drop counter: ");
		return 0;
	}

	char tmp[256];
	int count = 0;

	memset(tmp, 0, sizeof(tmp));
	if (read(fd, tmp, sizeof(tmp) - 1) < 0)
		perror("Failed to read drop counter: ");
	else
		count = atoi(tmp);

	close(fd);
	return count;
}


static volatile sig_atomic_t done;

static void finish_tracing(int sig)
{
	(void) sig;
	done = 1;
}

static int trace_device(struct blkio_record_conf *conf)
{
	struct blkio_record_ctx ctx;

	if (blkio_record_ctx_setup(&ctx, conf))
		return -1;

	blkio_trace_start(&ctx);
	while (!done)
		pause();
	blkio_trace_stop(&ctx);

	fprintf(stderr, "buffers dropped: %d\n", blkio_get_drops(&ctx));
	blkio_record_ctx_release(&ctx);
	return 0;
}

int main()
{
	struct blkio_record_conf conf = {
		"/sys/kernel/debug",
		"/dev/nullb0",
		512 * 1024,
		4
	};

	handle_signal(SIGINT, finish_tracing);
	handle_signal(SIGHUP, finish_tracing);
	handle_signal(SIGTERM, finish_tracing);

	trace_device(&conf);
	return 0;
}
