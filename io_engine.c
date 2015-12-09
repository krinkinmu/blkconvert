#include "io_engine.h"

int io_engine_setup(struct io_context *ctx, const struct io_engine *engine,
			const char *block_device_name, int number_of_events)
{
	ctx->engine = engine;
	ctx->running = 0;
	ctx->size = number_of_events;
	ctx->private = 0;

	return engine->open(ctx, block_device_name, number_of_events);
}

void io_engine_release(struct io_context *ctx)
{
	if (ctx->running)
		io_engine_reclaim(ctx, ctx->running, ctx->running);
	ctx->engine->close(ctx);
}

int io_engine_submit(struct io_context *ctx, struct bio *bios, int count)
{
	int rc = ctx->engine->submit(ctx, bios, count);

	if (rc < 0)
		return rc;

	ctx->running += rc;
	return rc;
}

int io_engine_reclaim(struct io_context *ctx, int min, int max)
{
	int rc = ctx->engine->reclaim(ctx, min, max);

	if (rc < 0)
		return rc;

	ctx->running -= rc;
	return rc;
}
