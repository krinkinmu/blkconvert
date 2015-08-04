#ifndef __BLKRECORD_H__
#define __BLKRECORD_H__

#include <asm/types.h>

#define SECTOR_SIZE_BITS 16
#define SPOT_OFFSET_BITS 64

struct blkio_disk_layout {
	__u64 first_sector;
	__u64 last_sector;
	__u32 io_size[16];
	__u32 merged_size[16];
	__u32 spot_offset[64];
};

struct blkio_stats {
	__u64 q2q_time;
	__u64 inversions;
	__u32 reads;
	__u32 writes;
	__u32 iodepth;
	__u32 batch;
	struct blkio_disk_layout reads_layout;
	struct blkio_disk_layout writes_layout;
};

#endif /*__BLKRECORD_H__*/
