#ifndef __BLKRECORD_H__
#define __BLKRECORD_H__

#include <pthread.h>

#include "blktrace_api.h"
#include "list.h"

struct blkio_buffer {
	struct list_head link;
	void *data;
	int pos, size;
};

struct blkio_record_ctx;

struct blkio_tracer {
	struct blkio_record_ctx *ctx;
	struct list_head link;
	struct list_head bufs;
	pthread_t thread;
	pthread_mutex_t lock;
	cpu_set_t cpuset;
	int fd;
};

enum blkio_trace_state {
	TRACE_WAIT,
	TRACE_RUN,
	TRACE_STOP
};

struct blkio_record_ctx {
	struct blk_user_trace_setup trace_setup;
	struct list_head tracers;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	volatile int state;
	int cpus;
	int fd;
};

#endif /*__BLKRECORD_H__*/
