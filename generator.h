#ifndef __GENERATOR_H__
#define __GENERATOR_H__

#include "blkrecord.h"

static const unsigned long long sector_size = 512;

static inline unsigned long long BYTES(unsigned long long sectors)
{ return sectors * sector_size; }

static inline unsigned long long SECTORS(unsigned long long bytes)
{ return (bytes + sector_size - 1) / sector_size; }

#define BIO_WRITE  (1ul << 0)
#define BIO_READ   0ul
#define BIO_SYNC   (1ul << 4)
#define BIO_NOIDLE (1ul << 10)
#define BIO_FUA    (1ul << 12)

struct bio {
	unsigned long long offset;
	unsigned long bytes;
	unsigned long flags;
};

int bio_generate(struct bio *bios, const struct blkio_stats *stats);

#endif /*__GENERATOR_H__*/
