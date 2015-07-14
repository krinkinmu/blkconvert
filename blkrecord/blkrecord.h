#ifndef __BLKRECORD_H__
#define __BLKRECORD_H__

#include <asm/types.h>

struct blkio_stats {
	__u64 first_time;
	__u64 last_time;
	__u64 min_sector;
	__u64 max_sector;
	__u32 reads;
	__u32 writes;
	__u32 bytes;
	__u32 iodepth;
};

#endif /*__BLKRECORD_H__*/
