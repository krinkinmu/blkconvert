#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include "file_io.h"

int myread(int fd, void *dst, size_t size)
{
	char *buf = dst;
	size_t rd = 0;

	while (rd != size) {
		const ssize_t ret = read(fd, buf + rd, size - rd);

		if (ret < 0) {
			if (errno != EINTR)
				perror("Error while reading file");
			return -1;
		}
		if (!ret)
			return -1;
		rd += ret;
	}
	return 0;
}

int mywrite(int fd, const void *src, size_t size)
{
	const char *buf = src;
	size_t wr = 0;

	while (wr != size) {
		const ssize_t ret = write(fd, buf + wr, size - wr);

		if (ret < 0) {
			if (errno != EINTR)
				perror("Error while writing file");
			return -1;
		}
		wr += ret;
	}
	return 0;
}
