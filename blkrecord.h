#ifndef __BLKRECORD_H__
#define __BLKRECORD_H__

#include <zlib.h>

#include "blkqueue.h"
#include "list.h"


struct process_info {
	struct list_head head;
	struct blkio_event *events;
	unsigned long size, capacity, pid, cpu;
};

static inline struct process_info *PROCESS_INFO(struct list_head *head)
{
	if (!head)
		return 0;
	return list_entry(head, struct process_info, head);
}

struct blkio_record_context {
	struct list_head head;
	struct blkio_queue read, write;
	gzFile zofd;
};

static inline void blkio_record_context_init(struct blkio_record_context *ctx)
{
	list_head_init(&ctx->head);
	blkio_queue_init(&ctx->read);
	blkio_queue_init(&ctx->write);
}

static inline void blkio_record_context_finit(struct blkio_record_context *ctx)
{
	blkio_queue_finit(&ctx->read);
	blkio_queue_finit(&ctx->write);
}

#endif /*__BLKRECORD_H__*/
