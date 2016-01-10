#ifndef __BLKRECORD_H__
#define __BLKRECORD_H__

#include <pthread.h>

#include "blktrace_api.h"
#include "rbtree.h"
#include "list.h"

struct blkio_tracer;

struct blkio_buffer {
	struct list_head head;
	struct rb_node node;
	unsigned long long timestamp;
	struct blk_io_trace *data;
	size_t count;
};

enum blkio_tracer_state {
	TRACE_WAIT,
	TRACE_RUN,
	TRACE_STOP
};

struct blkio_tracer {
	struct list_head link;
	struct list_head bufs;
	struct blkio_buffer *prev;
	pthread_t thread;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	cpu_set_t cpuset;
	volatile int state;
	int fd;
};

struct blkio_record_ctx;

struct blkio_processor {
	struct blkio_record_ctx *ctx;
	struct rb_root buffers;
	pthread_t thread;	
	pthread_mutex_t lock;
	pthread_cond_t cond;
	volatile int state;
};

struct blkio_record_ctx {
	struct blk_user_trace_setup trace_setup;
	struct blkio_processor processor;
	struct list_head tracers;
	int cpus;
	int fd;
};

#endif /*__BLKRECORD_H__*/
