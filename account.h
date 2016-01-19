#ifndef __ACCOUNT_H__
#define __ACCOUNT_H__

#include <asm/types.h>
#include <stddef.h>

#define IO_SIZE_BITS   16
#define IO_OFFSET_BITS 64


struct blkio_disk_layout {
	__u64 first_sector;
	__u64 last_sector;
	__u32 sync;
	__u32 seq;
	__u32 fua;
	__u32 max_len;
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
	struct blkio_disk_layout reads_layout;
	struct blkio_disk_layout writes_layout;
};

#define WRITE_BIT  0
#define WRITE_MASK (1 << WRITE_BIT)

#define QUEUE_BIT  1
#define QUEUE_MASK (1 << QUEUE_BIT)

#define SYNC_BIT   2
#define SYNC_MASK  (1 << SYNC_BIT)

#define FUA_BIT    3
#define FUA_MASK   (1 << FUA_BIT)

#define IS_WRITE(type) ((type) & WRITE_MASK)
#define IS_QUEUE(type) ((type) & QUEUE_MASK)
#define IS_SYNC(type)  ((type) & SYNC_MASK)
#define IS_FUA(type)   ((type) & FUA_MASK)

struct blkio_event {
	unsigned long long time;
	unsigned long long from;
	unsigned long long to;
	unsigned long pid;
	unsigned char type;
};

int account_events(const struct blkio_event *events, size_t size,
			struct blkio_stats *stats);

#endif /*__ACCOUNT_H__*/
