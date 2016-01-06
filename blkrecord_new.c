#include "blkrecord_new.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
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


#define BLKIO_BUFFER_SIZE (512 * 1024)

static struct blkio_buffer *blkio_buffer_alloc(int size)
{
	void *ptr = malloc(sizeof(struct blkio_buffer) + size);

	if (!ptr)
		return 0;

	struct blkio_buffer *buffer = ptr;

	list_head_init(&buffer->link);
	buffer->data = (void *)(buffer + 1);
	buffer->pos = 0;
	buffer->size = size;

	return buffer;
}

static void blkio_buffer_free(struct blkio_buffer *buf)
{ free(buf); }

static struct blkio_tracer *blkio_tracer_alloc(struct blkio_record_ctx *ctx)
{
	struct blkio_tracer *tracer = malloc(sizeof(struct blkio_tracer));

	if (!tracer)
		return 0;

	list_head_init(&tracer->link);
	list_head_init(&tracer->bufs);
	assert(!pthread_mutex_init(&tracer->lock, NULL));
	CPU_ZERO(&tracer->cpuset);
	tracer->ctx = ctx;
	tracer->fd = -1;
	return tracer;
}

static void blkio_tracer_free(struct blkio_tracer *tracer)
{
	assert(!pthread_mutex_destroy(&tracer->lock));
	free(tracer);
}

static void blkio_trace_wait(struct blkio_record_ctx *ctx);

static void *blkio_tracer_main(void *data)
{
	struct blkio_tracer *tracer = data;
	struct blkio_record_ctx *ctx = tracer->ctx;
	struct pollfd pollfd;

	pthread_setaffinity_np(tracer->thread, sizeof(tracer->cpuset),
			&tracer->cpuset);

	pollfd.fd = tracer->fd;
	pollfd.events = POLLIN;
	pollfd.revents = 0;

	blkio_trace_wait(ctx);

	while (ctx->state == TRACE_RUN) {
		const int rc = poll(&pollfd, 1, 500);

		if (rc < 0) {
			perror("Poll failed: ");
			continue;
		}

		if (!(pollfd.revents & POLLIN))
			continue;

		struct blkio_buffer *buffer =
			blkio_buffer_alloc(BLKIO_BUFFER_SIZE);

		if (!buffer) {
			fprintf(stderr, "blkio_buffer allocation failed\n");
			continue;
		}

		buffer->size = read(tracer->fd, buffer->data,
			BLKIO_BUFFER_SIZE);
		if (buffer->size <= 0) {
			blkio_buffer_free(buffer);
			continue;
		}

		pthread_mutex_lock(&tracer->lock);
		list_link_before(&tracer->bufs, &buffer->link);
		pthread_mutex_unlock(&tracer->lock);
	}

	return 0;
}

static int blkio_trace_open_cpu(struct blkio_record_ctx *ctx, int cpu)
{
	static const char *debugfs = "/sys/kernel/debug";
	char filename[PATH_MAX + 64];

	const size_t size = snprintf(filename, sizeof(filename),
		"%s/block/%s/trace%d", debugfs, ctx->trace_setup.name, cpu);

	assert(size < sizeof(filename));

	return open(filename, O_RDONLY | O_NONBLOCK);
}

static int blkio_tracer_start(struct blkio_tracer *tracer, int cpu)
{
	CPU_SET(cpu, &tracer->cpuset);

	tracer->fd = blkio_trace_open_cpu(tracer->ctx, cpu);
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

static void blkio_tracer_wait(struct blkio_tracer *tracer)
{
	assert(!pthread_join(tracer->thread, NULL));
	if (tracer->fd >= 0)
		close(tracer->fd);
	tracer->fd = -1;
}

static void blkio_tracers_stop(struct blkio_record_ctx *ctx)
{
	pthread_mutex_lock(&ctx->lock);
	ctx->state = TRACE_STOP;
	pthread_cond_broadcast(&ctx->cond);
	pthread_mutex_unlock(&ctx->lock);
}

static void blkio_tracers_run(struct blkio_record_ctx *ctx)
{
	pthread_mutex_lock(&ctx->lock);
	ctx->state = TRACE_RUN;
	pthread_cond_broadcast(&ctx->cond);
	pthread_mutex_unlock(&ctx->lock);
}

static void blkio_tracers_wait(struct blkio_record_ctx *ctx)
{
	struct list_head *head = &ctx->tracers;
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_tracer *tracer = list_entry(ptr,
					struct blkio_tracer, link);

		ptr = ptr->next;
		blkio_tracer_wait(tracer);
	}
}

static void blkio_tracers_destroy(struct blkio_record_ctx *ctx)
{
	struct list_head *head = &ctx->tracers;
	struct list_head *ptr = head->next;

	while (ptr != head) {
		struct blkio_tracer *tracer = list_entry(ptr,
					struct blkio_tracer, link);

		ptr = ptr->next;
		blkio_tracer_free(tracer);
	}
}

static int blkio_tracers_create(struct blkio_record_ctx *ctx)
{
	for (int i = 0; i != ctx->cpus; ++i) {
		struct blkio_tracer *tracer = blkio_tracer_alloc(ctx);

		if (!tracer) {
			blkio_tracers_stop(ctx);
			blkio_tracers_wait(ctx);
			blkio_tracers_destroy(ctx);
			return -1;
		}

		if (blkio_tracer_start(tracer, i)) {
			blkio_tracer_free(tracer);
			return -1;
		}

		list_link_before(&ctx->tracers, &tracer->link);
	}
	return 0;
}

static void blkio_trace_wait(struct blkio_record_ctx *ctx)
{
	pthread_mutex_lock(&ctx->lock);
	while (ctx->state == TRACE_WAIT)
		pthread_cond_wait(&ctx->cond, &ctx->lock);
	pthread_mutex_unlock(&ctx->lock);
}

static int blkio_trace_start(struct blkio_record_ctx *ctx)
{
	if (ioctl(ctx->fd, BLKTRACESTART))
		return -1;
	blkio_tracers_run(ctx);
	return 0;
}

static void blkio_trace_stop(struct blkio_record_ctx *ctx)
{
	ioctl(ctx->fd, BLKTRACESTOP);
	blkio_tracers_stop(ctx);
	blkio_tracers_wait(ctx);
}

static void blkio_record_ctx_release(struct blkio_record_ctx *ctx)
{
	blkio_tracers_destroy(ctx);
	if (ctx->fd >= 0) {
		ioctl(ctx->fd, BLKTRACESTOP);
		ioctl(ctx->fd, BLKTRACETEARDOWN);
		close(ctx->fd);
	}
	assert(!pthread_mutex_destroy(&ctx->lock));
	assert(!pthread_cond_destroy(&ctx->cond));
}

static int blkio_record_ctx_setup(struct blkio_record_ctx *ctx,
			const char *block_device_name)
{
	list_head_init(&ctx->tracers);
	assert(!pthread_mutex_init(&ctx->lock, NULL));
	assert(!pthread_cond_init(&ctx->cond, NULL));

	memset(&ctx->trace_setup, 0, sizeof(ctx->trace_setup));
	ctx->trace_setup.act_mask = BLK_TC_QUEUE | BLK_TC_COMPLETE;
	ctx->trace_setup.buf_size = BLKIO_BUFFER_SIZE;
	ctx->trace_setup.buf_nr = 4;

	ctx->state = TRACE_WAIT;
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

	if (blkio_tracers_create(ctx)) {
		blkio_record_ctx_release(ctx);
		return -1;
	}

	return 0;
}

static long blkio_release_traces(struct blkio_tracer *tracer)
{
	struct list_head *head = &tracer->bufs;
	struct list_head *ptr = head->next;

	long bytes = 0;

	while (head != ptr) {
		struct blkio_buffer *buf = list_entry(ptr, struct blkio_buffer,
			link);

		ptr = ptr->next;
		bytes += buf->size;
		blkio_buffer_free(buf);
	}

	return bytes;
}

static int trace_device(const char *block_device_name)
{
	struct blkio_record_ctx ctx;

	if (blkio_record_ctx_setup(&ctx, block_device_name))
		return -1;

	blkio_trace_start(&ctx);
	sleep(5);
	blkio_trace_stop(&ctx);


	struct list_head *head = &ctx.tracers;
	struct list_head *ptr = head->next;

	long total_bytes = 0;

	for (; head != ptr; ptr = ptr->next) {
		struct blkio_tracer *tracer = list_entry(ptr,
			struct blkio_tracer, link);

		total_bytes = blkio_release_traces(tracer);
	}

	printf("total bytes read: %ld\n", total_bytes);

	blkio_record_ctx_release(&ctx);
	return 0;
}

int main()
{
	trace_device("/dev/nullb0");
	return 0;
}
