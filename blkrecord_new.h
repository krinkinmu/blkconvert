#ifndef __BLKRECORD_H__
#define __BLKRECORD_H__

#include <pthread.h>

#include "blktrace_api.h"
#include "account.h"
#include "rbtree.h"
#include "list.h"

struct blkio_buffer {
	struct list_head head;
	unsigned long long timestamp;
	struct blkio_event *data;
	size_t count;
};

struct blkio_event_node {
	struct rb_node node;
	struct blkio_event event;
};

enum blkio_tracer_state {
	TRACE_WAIT,
	TRACE_RUN,
	TRACE_STOP
};

struct blkio_tracer {
	struct blkio_record_ctx *ctx;
	struct list_head link;
	struct list_head bufs;
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
	struct rb_root events;
	pthread_t thread;	
	pthread_mutex_t lock;
	pthread_cond_t cond;
	volatile int state;
};

struct blkio_record_conf {
	const char *debugfs;
	const char *device;
	size_t buffer_size;
	size_t buffer_count;
	int poll_timeout;
};

struct blkio_record_ctx {
	struct blk_user_trace_setup trace_setup;
	struct blkio_processor processor;
	struct list_head tracers;
	struct blkio_record_conf *conf;
	int cpus;
	int fd;
};

#endif /*__BLKRECORD_H__*/
