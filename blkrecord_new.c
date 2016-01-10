#include "blkrecord_new.h"
#include "blktrace_api.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <byteswap.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>


#define BLKIO_BUFFER_SIZE (512 * 1024)
#define DEBUGFS           "/sys/kernel/debug"

static struct blkio_buffer *blkio_alloc_buffer(int size)
{
	void *ptr = malloc(sizeof(struct blkio_buffer) + size);

	if (!ptr)
		return 0;

	struct blkio_buffer *buffer = ptr;

	memset(buffer, 0, sizeof(*buffer));
	list_head_init(&buffer->head);
	buffer->data = (void *)(buffer + 1);
	buffer->size = size;

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
	tracer->prev = 0;
	tracer->state = TRACE_WAIT;
	tracer->fd = -1;
	return tracer;
}

static void blkio_free_tracer(struct blkio_tracer *tracer)
{
	assert(!pthread_mutex_destroy(&tracer->lock));
	assert(!pthread_cond_destroy(&tracer->cond));
	blkio_free_buffer(tracer->prev);
	free(tracer);
}

static unsigned long long blkio_timestamp(void)
{
	static const unsigned long long NS = 1000000000ull;
	struct timespec sp;

	clock_gettime(CLOCK_MONOTONIC_RAW, &sp);
	return sp.tv_sec * NS + sp.tv_nsec;
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

static void blkio_coalesce_buffers(struct blkio_buffer *prev,
			struct blkio_buffer *next)
{
	const int prev_size = prev->size - prev->pos;

	memmove(next->data + prev_size, next->data, next->size);
	memcpy(next->data, prev->data + prev->pos, prev_size);
	next->size += prev_size;
}

static void blkio_trace_to_cpu(struct blk_io_trace *trace)
{
	if ((trace->magic & 0xFFFFFF00ul) == BLK_IO_TRACE_MAGIC)
		return;

	trace->magic = __bswap_32(trace->magic);
	assert((trace->magic & 0xFFFFFF00ul) == BLK_IO_TRACE_MAGIC);

	trace->time = __bswap_64(trace->time);
	trace->sector = __bswap_64(trace->sector);
	trace->bytes = __bswap_32(trace->bytes);
	trace->action = __bswap_32(trace->action);
	trace->pdu_len = __bswap_16(trace->pdu_len);
	trace->pid = __bswap_32(trace->pid);
	trace->cpu = __bswap_32(trace->cpu);
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
	struct blkio_tracer *tracer = buf->tracer;
	struct blkio_buffer *prev = tracer->prev;
	struct blk_io_trace trace;
	char *data = (void *)&trace;

	if (prev) {
		const size_t prev_size = prev->size - prev->pos;
		const size_t curr_size = buf->size;

		if (prev_size + curr_size < sizeof(trace)) {
			blkio_coalesce_buffers(prev, buf);
			tracer->prev = buf;
			blkio_free_buffer(prev);
			return;
		}

		memcpy(data, prev->data + prev->pos, prev_size);
		memcpy(data + prev_size, buf->data, sizeof(trace) - prev_size);
		blkio_trace_to_cpu(&trace);

		if (sizeof(trace) + trace.pdu_len > prev_size + curr_size) {
			blkio_coalesce_buffers(prev, buf);
			tracer->prev = buf;
			blkio_free_buffer(prev);
			return;
		}

		tracer->prev = 0;
		blkio_free_buffer(prev);
		buf->pos += sizeof(trace) + trace.pdu_len - prev_size;
		blkio_print_trace(&trace);
	}

	while (1) {
		if (buf->size - buf->pos < sizeof(trace))
			break;

		memcpy(data, buf->data + buf->pos, sizeof(trace));
		blkio_trace_to_cpu(&trace);

		if (sizeof(trace) + trace.pdu_len > buf->size - buf->pos)
			break;

		buf->pos += sizeof(trace) + trace.pdu_len;

		blkio_print_trace(&trace);
	}

	if (buf->pos != buf->size)
		tracer->prev = buf;
	else
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

static int blkio_tracer_read(struct blkio_tracer *tracer)
{
	struct blkio_buffer *buffer = blkio_alloc_buffer(BLKIO_BUFFER_SIZE);

	if (!buffer) {
		fprintf(stderr, "blkio_buffer allocation failed\n");
		return 1;
	}

	buffer->size = read(tracer->fd, buffer->data, BLKIO_BUFFER_SIZE);
	if (buffer->size <= 0) {
		blkio_free_buffer(buffer);
		return 1;
	}

	buffer->timestamp = blkio_timestamp();
	buffer->tracer = tracer;

	pthread_mutex_lock(&tracer->lock);
	list_link_before(&tracer->bufs, &buffer->head);
	pthread_mutex_unlock(&tracer->lock);

	return 0;
}

static void *blkio_tracer_main(void *data)
{
	struct blkio_tracer *tracer = data;
	struct pollfd pollfd;

	pthread_setaffinity_np(tracer->thread, sizeof(tracer->cpuset),
			&tracer->cpuset);

	pollfd.fd = tracer->fd;
	pollfd.events = POLLIN;
	pollfd.revents = 0;

	blkio_tracer_wait(tracer);

	while (tracer->state == TRACE_RUN) {
		const int rc = poll(&pollfd, 1, 50);

		if (rc < 0) {
			perror("Poll failed: ");
			continue;
		}

		if (!(pollfd.revents & POLLIN))
			continue;

		while (!blkio_tracer_read(tracer));
	}

	while (!blkio_tracer_read(tracer));

	return 0;
}

static int blkio_trace_open_cpu(struct blkio_record_ctx *ctx, int cpu)
{
	char filename[PATH_MAX + 64];

	const size_t size = snprintf(filename, sizeof(filename),
		"%s/block/%s/trace%d", DEBUGFS, ctx->trace_setup.name, cpu);

	assert(size < sizeof(filename));

	return open(filename, O_RDONLY | O_NONBLOCK);
}

static int blkio_start_tracer(struct blkio_record_ctx *ctx,
			struct blkio_tracer *tracer, int cpu)
{
	CPU_SET(cpu, &tracer->cpuset);

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
			const char *block_device_name)
{
	memset(ctx, 0, sizeof(*ctx));;
	list_head_init(&ctx->tracers);

	ctx->trace_setup.act_mask = BLK_TC_QUEUE | BLK_TC_COMPLETE;
	ctx->trace_setup.buf_size = BLKIO_BUFFER_SIZE;
	ctx->trace_setup.buf_nr = 4;

	ctx->cpus = -1;
	ctx->fd = -1;

	ctx->cpus = sysconf(_SC_NPROCESSORS_CONF);
	if (ctx->cpus < 0) {
		perror("Cannot get number of cpu: ");
		blkio_record_ctx_release(ctx);
		return -1;
	}

	ctx->fd = open(block_device_name, O_RDONLY | O_NONBLOCK);
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
		"%s/block/%s/dropped", DEBUGFS, ctx->trace_setup.name);

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

static int trace_device(const char *block_device_name)
{
	struct blkio_record_ctx ctx;

	if (blkio_record_ctx_setup(&ctx, block_device_name))
		return -1;

	blkio_trace_start(&ctx);
	sleep(5);
	blkio_trace_stop(&ctx);

	printf("buffer dropped: %d\n", blkio_get_drops(&ctx));
	blkio_record_ctx_release(&ctx);
	return 0;
}

int main()
{
	trace_device("/dev/nullb0");
	return 0;
}
