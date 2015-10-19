#ifndef __BLKRECORD_H__
#define __BLKRECORD_H__

#include <asm/types.h>
#include <zlib.h>

#include "blkqueue.h"
#include "list.h"

#define IO_SIZE_BITS       16
#define IO_OFFSET_BITS     64

struct blkio_disk_layout {
	__u64 first_sector;
	__u64 last_sector;
	__u32 sync;
	__u32 io_size[IO_SIZE_BITS];
	__u32 io_offset[IO_OFFSET_BITS];
};

struct blkio_stats {
	__u64 begin_time;
	__u64 end_time;
	__u64 inversions;
	__u32 reads;
	__u32 writes;
	__u32 iodepth;
	__u32 batch;
	__u32 pid;
	__u32 cpu;
	struct blkio_disk_layout reads_layout;
	struct blkio_disk_layout writes_layout;
};

#define WRITE_BIT  0
#define WRITE_MASK (1 << WRITE_BIT)

#define QUEUE_BIT  1
#define QUEUE_MASK (1 << QUEUE_BIT)

#define SYNC_BIT   2
#define SYNC_MASK  (1 << SYNC_BIT)

#define IS_WRITE(type) ((type) & WRITE_MASK)
#define IS_QUEUE(type) ((type) & QUEUE_MASK)
#define IS_SYNC(type)  ((type) & SYNC_MASK)

struct blkio_event {
	unsigned long long time;
	unsigned long long from;
	unsigned long long to;
	unsigned long pid;
	unsigned long cpu;
	unsigned char type;
};

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
	int ifd, ofd;
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
