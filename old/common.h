#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>
#include <stddef.h>

struct blkio_stat {
	uint64_t start;
	uint64_t end;
	uint64_t total_ops;
	uint64_t total_bytes;
	uint64_t min_sector;
	uint64_t max_sector;
};

struct blkio_stats {
	struct blkio_stat read;
	struct blkio_stat write;
};

#define container_of(ptr, type, member) \
        ((type *)((char *)(ptr) - offsetof(type, member)))

#endif /*__COMMON_H__*/
