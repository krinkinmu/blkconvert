#ifndef __TRACE_H__
#define __TRACE_H__

#include <pthread.h>

#include "blktrace_api.h"
#include "account.h"
#include "rbtree.h"
#include "list.h"

struct blkio_process_info {
	struct rb_node node;
	struct list_head link;
	int pid;
	char *name;
};

struct blkio_buffer {
	struct list_head link;
	struct list_head proc;
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

struct blkio_process_data {
	struct rb_node node;
	int pid;
	struct blkio_event *events;
	size_t count;
};

struct blkio_processor {
	struct blkio_record_ctx *ctx;
	struct rb_root events;
	struct rb_root reads;
	struct rb_root writes;
	struct rb_root procs;
	struct rb_root data;
	size_t count, size;
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
	size_t events_count;
	int poll_timeout;
};

struct blkio_stats_handler {
	void (*handle)(struct blkio_stats_handler *, struct blkio_stats *);
};

struct blkio_record_ctx {
	struct blk_user_trace_setup trace_setup;
	struct blkio_processor processor;
	struct list_head tracers;
	struct blkio_stats_handler *handler;
	struct blkio_record_conf *conf;
	int cpus;
	int fd;
};

int blkio_record_ctx_setup(struct blkio_record_ctx *ctx,
			struct blkio_stats_handler *handler,
			struct blkio_record_conf *conf);
int blkio_trace_start(struct blkio_record_ctx *ctx);
void blkio_trace_stop(struct blkio_record_ctx *ctx);
int blkio_trace_drops(struct blkio_record_ctx *ctx);
void blkio_record_ctx_release(struct blkio_record_ctx *ctx);

#endif /*__TRACE_H__*/
