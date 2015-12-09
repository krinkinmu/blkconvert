#ifndef __IO_ENGINE_H__
#define __IO_ENGINE_H__

#include "generator.h"

struct io_context;

struct io_engine {
	int (*open)(struct io_context *, const char *, int);
	int (*submit)(struct io_context *, struct bio *, int);
	int (*reclaim)(struct io_context *, int, int);
	void (*close)(struct io_context *);
};

struct io_context {
	const struct io_engine *engine;
	int running;
	int size;
	void *private;
};

int io_engine_setup(struct io_context *ctx, const struct io_engine *engine,
			const char *block_device_name, int number_of_events);
void io_engine_release(struct io_context *ctx);

int io_engine_submit(struct io_context *ctx, struct bio *bios, int count);
int io_engine_reclaim(struct io_context *ctx, int min, int max);

#endif /*__IO_ENGINE__*/
