#ifndef __TRACE_NET_H__
#define __TRACE_NET_H__

#include "account.h"

#include <stdint.h>

#define BLKIO_MSG_START  1
#define BLKIO_MSG_STOP   2
#define BLKIO_MSG_STATS  3
#define BLKIO_MSG_STATUS 4

#define BLKIO_MAX_PATH   256

#define BLKIO_STATUS_OK     0
#define BLKIO_STATUS_ERROR  1

struct blkio_net_hdr {
	uint32_t type;
	uint32_t size;
} __attribute__((packed));

struct blkio_net_start {
	struct blkio_net_hdr hdr;
	char device[BLKIO_MAX_PATH];
	uint32_t buffer_size;
	uint32_t buffer_count;
	uint32_t events_count;
	uint32_t poll_timeout;
} __attribute__((packed));

struct blkio_net_stop {
	struct blkio_net_hdr hdr;
} __attribute__((packed));

struct blkio_net_stats {
	struct blkio_net_hdr hdr;
	struct blkio_stats stats;
} __attribute__((packed));

struct blkio_net_status {
	struct blkio_net_hdr hdr;
	uint32_t error;
	uint32_t drops;
} __attribute__((packed));

union blkio_net_storage {
	struct blkio_net_hdr hdr;
	struct blkio_net_start start;
	struct blkio_net_stop stop;
	struct blkio_net_stats stats;
	struct blkio_net_status status;
};

#endif /*__TRACE_NET_H__*/
