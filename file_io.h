#ifndef __FILE_IO_H__
#define __FILE_IO_H__

#include <stddef.h>

int myread(int fd, char *buf, size_t size);
int mywrite(int fd, const char *buf, size_t size);

#endif /*__FILE_IO_H__*/
