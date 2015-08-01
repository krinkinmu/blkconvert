#ifndef __BLKRECORD_H__
#define __BLKRECORD_H__

#include <asm/types.h>

struct blkio_stats {
	__u64 q2q_time;
	__u64 min_sector;
	__u64 max_sector;
	__u64 inversions;
	__u32 merged_sectors;
	__u32 sectors;
	__u32 reads;
	__u32 writes;
	__u32 iodepth;
	__u32 batch;
};

#endif /*__BLKRECORD_H__*/
