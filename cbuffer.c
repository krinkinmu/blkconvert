#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include "cbuffer.h"
#include "common.h"

int cbuffer_setup(struct cbuffer *buffer, size_t size)
{
	buffer->buf = malloc(size);
	if (!buffer->buf)
		return 1;
	buffer->size = size;
	buffer->read = 0;
	buffer->len = 0;
	return 0;
}

void cbuffer_release(struct cbuffer *buffer)
{ free(buffer->buf); }

size_t cbuffer_size(const struct cbuffer *buffer)
{ return buffer->len; }

bool cbuffer_full(const struct cbuffer *buffer)
{ return buffer->len == buffer->size; }

size_t cbuffer_read(struct cbuffer *buffer, void *d, size_t size)
{
	const size_t to_read = MINU(size, buffer->len);
	const size_t to_end = buffer->size - buffer->read;
	char *dst = d;

	if (!to_read)
		return 0;

	if (to_end >= to_read) {
		memcpy(dst, buffer->buf + buffer->read, to_read);
	} else {
		memcpy(dst, buffer->buf + buffer->read, to_end);
		memcpy(dst + to_end, buffer->buf, to_read - to_end);
	}
	return to_read;
}

size_t cbuffer_advance(struct cbuffer *buffer, size_t size)
{
	const size_t to_advance = MINU(size, buffer->len);

	buffer->read += to_advance;
	if (buffer->read >= buffer->size)
		buffer->read -= buffer->size;
	buffer->len -= to_advance;
	return to_advance;
}

size_t cbuffer_write(struct cbuffer *buffer, const void *s, size_t size)
{
	const size_t to_write = MINU(buffer->size - buffer->len, size);
	size_t write = buffer->read + buffer->len;
	const char *src = s;

	if (write >= buffer->size)
		write -= buffer->size;

	const size_t to_end = buffer->size - write;

	if (!to_write)
		return 0;

	if (to_end >= to_write) {
		memcpy(buffer->buf + write, src, to_write);
	} else {
		memcpy(buffer->buf + write, src, to_end);
		memcpy(buffer->buf, src + to_end, to_write - to_end);
	}
	buffer->len += to_write;
	return to_write;
}

ssize_t cbuffer_fill(struct cbuffer *buffer, int fd)
{
	const size_t write = buffer->read + buffer->len;
	const size_t to_end = buffer->size - write;
	const size_t to_read = MINU(buffer->size - buffer->len, to_end);

	ssize_t ret = read(fd, buffer->buf + write, to_read);

	if (ret > 0)
		buffer->len += ret;
	return ret;
}
