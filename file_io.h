#ifndef __FILE_IO_H__
#define __FILE_IO_H__

#include <stddef.h>

int myread(int fd, void *buf, size_t size);
int mywrite(int fd, const void *buf, size_t size);

#endif /*__FILE_IO_H__*/
