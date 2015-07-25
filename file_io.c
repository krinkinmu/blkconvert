#include <unistd.h>
#include <stdio.h>

#include "file_io.h"

int myread(int fd, char *buf, size_t size)
{
	size_t rd = 0;

	while (rd != size) {
		const ssize_t ret = read(fd, buf + rd, size - rd);

		if (ret < 0) {
			perror("Error while reading file");
			return 1;
		}
		if (!ret) return 1;
		rd += ret;
	}
	return 0;
}

int mywrite(int fd, const char *buf, size_t size)
{
	size_t wr = 0;

	while (wr != size) {
		const ssize_t ret = write(fd, buf + wr, size - wr);

		if (ret < 0) {
			perror("Error while writing file");
			return 1;
		}
		wr += ret;
	}
	return 0;
}
