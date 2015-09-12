#ifndef __BLKRECORD_H__
#define __BLKRECORD_H__

#include <asm/types.h>
#include <zlib.h>

#include "rbtree.h"
#include "list.h"

#define IO_SIZE_BITS       256
#define IO_OFFSET_BITS     64

struct blkio_disk_layout {
	__u64 first_sector;
	__u64 last_sector;
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

struct blkio_event {
	unsigned long long time;
	unsigned long long sector;
	unsigned long length;
	unsigned long action;
	unsigned long pid;
	unsigned long cpu;
};

struct blkio_queue_node {
	struct rb_node rb_node;
	struct blkio_event event;
};

struct process_info {
	struct list_head head;
	struct blkio_event *events;
	unsigned long size, capacity, pid, cpu;
};

struct blkio_queue {
	struct list_head head;
	struct rb_root rb_root;
	gzFile zofd;
	int ifd, ofd;
};

static inline void blkio_queue_init(struct blkio_queue *queue)
{
	list_head_init(&queue->head);
	queue->rb_root.rb_node = NULL;
}

#endif /*__BLKRECORD_H__*/
