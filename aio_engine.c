#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <libaio.h>

#include "object_cache.h"
#include "aio_engine.h"
#include "debug.h" 

struct aio_ctx {
	io_context_t ctx;
	struct io_event *event;
	struct object_cache *cache;
	int size;
	int fd;
};

static struct iocb *iocb_alloc(struct aio_ctx *ctx)
{ return object_cache_alloc(ctx->cache); }

static void iocb_free(struct aio_ctx *ctx, struct iocb *iocb)
{ object_cache_free(ctx->cache, iocb); }

static struct iocb *iocb_create(struct aio_ctx *ctx, const struct bio *bio)
{
	static const int page_size = 4096;

	struct iocb *iocb = iocb_alloc(ctx);

	if (!iocb) {
		ERR("Cannot allocate iocb structure\n");
		return 0;
	}

	void *buf;

	if (posix_memalign(&buf, page_size, bio->bytes)) {
		ERR("Cannot allocate IO buffer\n");
		iocb_free(ctx, iocb);
		return 0;
	}

	if (bio->flags & BIO_WRITE) {
		io_prep_pwrite(iocb, ctx->fd, buf, bio->bytes, bio->offset);
		memset(buf, 0x13, bio->bytes);
	} else {
		io_prep_pread(iocb, ctx->fd, buf, bio->bytes, bio->offset);
	}

	return iocb;
}

static void iocb_release(struct aio_ctx *ctx, struct iocb *iocb)
{
	free(iocb->u.c.buf);
	iocb_free(ctx, iocb);
}

static void iocbs_release(struct aio_ctx *ctx, struct iocb **iocbs, int count)
{
	for (int i = 0; i != count; ++i)
		iocb_release(ctx, iocbs[i]);
}

static int aio_open(struct io_context *ctx, const char *device_file_name,
			int number_of_events)
{
	int fd = open(device_file_name, O_RDWR | O_DIRECT);

	if (fd < 0) {
		ERR("Cannot open block device file (%d)\n", errno);
		return 1;
	}

	struct aio_ctx *aio = malloc(sizeof(*aio));

	if (!ctx) {
		ERR("Cannot allocate aio_ctx structure\n");
		return 1;
	}

	aio->fd = fd;
	aio->ctx = 0;
	aio->size = number_of_events;

	int ret = io_setup(number_of_events, &aio->ctx);

	if (ret) {
		ERR("Cannot initialize aio context (%d)\n", -ret);
		close(fd);
		free(aio);
		return 1;
	}

	aio->cache = object_cache_create(sizeof(struct iocb));
	if (!aio->cache) {
		ERR("Cannot create iocb cache\n");
		io_destroy(aio->ctx);
		close(fd);
		free(aio);
		return 1;
	}

	aio->event = calloc(aio->size, sizeof(*aio->event));
	if (!aio->event) {
		ERR("Cannot allocate array of io_event structures\n");
		object_cache_destroy(aio->cache);
		io_destroy(aio->ctx);
		close(fd);
		free(aio);
		return 1;
	}
	memset(aio->event, 0, aio->size * sizeof(*aio->event));
	ctx->private = aio;

	return 0;
}

static void aio_close(struct io_context *ctx)
{
	struct aio_ctx *aio = ctx->private;

	object_cache_destroy(aio->cache);
	io_destroy(aio->ctx);
	close(aio->fd);
	free(aio->event);
	free(aio);
}

static int aio_submit(struct io_context *ctx, struct bio *bios, int count)
{
	struct aio_ctx *aio = ctx->private;
	struct iocb **iocbs = calloc(count, sizeof(*iocbs));

	if (!iocbs) {
		ERR("Cannot allocate array of iocb pointers\n");
		return -1;
	}

	for (int i = 0; i != count; ++i) {
		iocbs[i] = iocb_create(aio, bios + i);

		if (!iocbs[i]) {
			iocbs_release(aio, iocbs, i);
			free(iocbs);
			return -1;
		}
	}

	int sb = 0;

	while (sb != count) {
		const int rc = io_submit(aio->ctx, count - sb, iocbs + sb);

		if (rc < 0) {
			ERR("Error %d, while submiting iocb\n", -rc);
			ERR("iocb offset %lld, size %lu, ptr %lx\n",
				iocbs[sb]->u.c.offset,
				iocbs[sb]->u.c.nbytes,
				(unsigned long)iocbs[sb]->u.c.buf);
			free(iocbs);
			return rc;
		}
		sb += rc;
	}
	free(iocbs);

	return count;
}

static int aio_reclaim(struct io_context *ctx, int min, int max)
{
	struct aio_ctx *aio = ctx->private;

	min = MIN(aio->size, min);
	max = MIN(aio->size, max);

	int rc = io_getevents(aio->ctx, min, max, aio->event, NULL);

	if (rc < 0) {
		ERR("Error %d while reclaiming IOs\n", -rc);
		return rc;
	}

	int ret = rc;

	for (int i = 0; i != rc; ++i) {
		struct io_event *e = aio->event + i;
		struct iocb *iocb = e->obj;

		if (e->res != iocb->u.c.nbytes) {
			const char *op = iocb->aio_lio_opcode == IO_CMD_PREAD
						? "read" : "write";

			ERR("%s of %ld bytes at %lld failed (%ld/%ld)\n",
						op,
						iocb->u.c.nbytes,
						iocb->u.c.offset,
						e->res,
						e->res2);
			ret = -1;
		}
		iocb_release(aio, iocb);
	}

	return ret;
}

static const struct io_engine aio = {
	.open = aio_open,
	.close = aio_close,
	.submit = aio_submit,
	.reclaim = aio_reclaim
};

const struct io_engine *aio_engine = &aio;
