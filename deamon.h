#ifndef __DEAMON_H__
#define __DEAMON_H__

typedef void (*deamon_fptr_t)(void);

int deamon(const char *name, deamon_fptr_t fptr);

#endif /*__DEAMON_H__*/
