#ifndef __DAEMON_H__
#define __DAEMON_H__

typedef void (*daemon_fptr_t)(void);

int mydaemon(const char *name, daemon_fptr_t fptr);

#endif /*__DAEMON_H__*/
