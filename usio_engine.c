#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "object_cache.h"
#include "usio_engine.h"
#include "debug.h"
#include "usio.h"

struct usio_ctx {
	struct object_cache *cache;
	struct usio_event *event;
	int size;
	int bfd, ufd;
};


static struct usio_io *usio_io_alloc(struct usio_ctx *ctx)
{ return object_cache_alloc(ctx->cache); }

static void usio_io_free(struct usio_ctx *ctx, struct usio_io *io)
{ object_cache_free(ctx->cache, io); }

static struct usio_io *usio_io_create(struct usio_ctx *ctx,
			const struct bio *bio)
{
	static const int page_size = 4096;

	struct usio_io *io = usio_io_alloc(ctx);

	if (!io) {
		ERR("cannot allocate usio_io structure\n");
		return 0;
	}

	void *buf;

	if (posix_memalign(&buf, page_size, bio->bytes)) {
		ERR("Cannot allocate buffer for IO\n");
		usio_io_free(ctx, io);
		return 0;
	}

	if (bio->flags & BIO_WRITE)
		memset(buf, 0x13, bio->bytes);

	io->data = (unsigned long)buf;
	io->bytes = bio->bytes;
	io->offset = bio->offset;
	io->flags = bio->flags;
	io->fd = ctx->bfd;

	return io;
}

static void usio_io_release(struct usio_ctx *ctx, struct usio_io *io)
{
	free((void *)io->data);
	usio_io_free(ctx, io);
}

static void usio_ios_release(struct usio_ctx *ctx, struct usio_io **ios,
			int count)
{
	for (int i = 0; i != count; ++i)
		usio_io_release(ctx, ios[i]);
}

static int usio_open(struct io_context *ctx, const char *device_file_name,
			int number_of_events)
{
	int bfd = open(device_file_name, O_RDWR | O_DIRECT);

	if (bfd < 0) {
		ERR("Cannot open block device file (%d)\n", errno);
		return 1;
	}

	int ufd = open("/dev/usio", O_RDWR);

	if (ufd < 0) {
		ERR("Cannot open /dev/usio (%d)\n", errno);
		close(bfd);
		return 1;
	}

	struct usio_ctx *usio = malloc(sizeof(*usio));

	if (!usio) {
		ERR("Cannot allocate usio_ctx structure\n");
		return 1;
	}

	usio->bfd = bfd;
	usio->ufd = ufd;
	usio->size = number_of_events;
	usio->cache = object_cache_create(sizeof(struct usio_io));

	if (!usio->cache) {
		ERR("Cannot create usio_io cache\n");
		close(ufd);
		close(bfd);
		free(usio);
		return 1;
	}

	usio->event = calloc(usio->size, sizeof(*usio->event));
	if (!usio->event) {
		ERR("Cannot allocate array of usio_event\n");
		object_cache_destroy(usio->cache);
		close(ufd);
		close(bfd);
		free(usio);
	}

	memset(usio->event, 0, usio->size * sizeof(*usio->event));
	ctx->private = usio;

	return 0;
}

static void usio_close(struct io_context *ctx)
{
	struct usio_ctx *usio = ctx->private;

	close(usio->ufd);
	close(usio->bfd);
	object_cache_destroy(usio->cache);
	free(usio->event);
	free(usio);
	ctx->private = 0;
}

static int usio_submit(struct io_context *ctx, struct bio *bios, int count)
{
	struct usio_ctx *usio = ctx->private;
	struct usio_io **ios = calloc(count, sizeof(*ios));

	if (!ios) {
		ERR("Cannot allocate array of usio_io pointers\n");
		return -1;
	}

	for (int i = 0; i != count; ++i) {
		ios[i] = usio_io_create(usio, bios + i);

		if (!ios[i]) {
			usio_ios_release(usio, ios, i);
			free(ios);
			return -1;
		}
	}

	int sb = 0;

	while (sb != count) {
		struct usio_ios req;

		req.count = count - sb;
		req.ios = ios + sb;

		const int rc = ioctl(usio->ufd, USIO_SUBMIT, &req);

		if (rc < 0) {
			ERR("Error %d, while submiting IO\n", -rc);
			ERR("offset %lld, size %lu, ptr %#lx\n",
				ios[sb]->offset,
				(unsigned long)ios[sb]->bytes,
				(unsigned long)ios[sb]->data);
			free(ios);
			return rc;
		}
		sb += rc;
	}
	free(ios);

	return count;
}

static int usio_reclaim(struct io_context *ctx, int min, int max)
{
	struct usio_ctx *usio = ctx->private;
	struct usio_events events;

	events.min_count = MIN(usio->size, min);
	events.max_count = MIN(usio->size, max);
	events.events = usio->event;

	int rc = ioctl(usio->ufd, USIO_RECLAIM, &events);

	if (rc < 0) {
		ERR("Error %d while reclaiming IO\n", -rc);
		return rc;
	}

	int ret = rc;
	for (int i = 0; i != rc; ++i) {
		struct usio_event *e = usio->event + i;
		struct usio_io *io = (struct usio_io *)e->io;

		if (e->res) {
			const char *op = (io->flags & BIO_WRITE) ?
						"write" : "read";
			ERR("%s of %ld bytes at %lld failed with error %lu\n",
				op,
				(unsigned long)io->bytes,
				(unsigned long long)io->offset,
				(unsigned long)e->res);
			ret = -1;
		}
		usio_io_release(usio, io);
	}

	return ret;
}

static const struct io_engine usio = {
	.open = usio_open,
	.close = usio_close,
	.submit = usio_submit,
	.reclaim = usio_reclaim
};

const struct io_engine *usio_engine = &usio;
