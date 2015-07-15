#ifndef __IOCB_CACHE_H__
#define __IOCB_CACHE_H__

void iocb_cache_create(void);
void iocb_cache_destroy(void);

struct iocb;

struct iocb *iocb_alloc(void);
void iocb_free(struct iocb *iocb);

#endif /*__IOCB_CACHE_H__*/
