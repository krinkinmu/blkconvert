#ifndef __CIRCULAR_BUFFER_H__
#define __CIRCULAR_BUFFER_H__

#include <stddef.h>
#include <stdbool.h>

struct cbuffer {
	char *buf;
	size_t size;
	size_t read;
	size_t len;
};

int cbuffer_setup(struct cbuffer *buffer, size_t size);
void cbuffer_release(struct cbuffer *buffer);

size_t cbuffer_size(const struct cbuffer *buffer);
bool cbuffer_full(const struct cbuffer *buffer);
size_t cbuffer_read(struct cbuffer *buffer, void *dst, size_t size);
size_t cbuffer_advance(struct cbuffer *buffer, size_t size);
size_t cbuffer_write(struct cbuffer *buffer, const void *src, size_t size);

ssize_t cbuffer_fill(struct cbuffer *buffer, int fd);

#endif /* __CIRCULAR_BUFFER_H__ */
