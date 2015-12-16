#include "network.h"
#include <string.h>
#include <unistd.h>

int server_socket(const char *service, int type)
{
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(NULL, service, &hints, &res))
		return -1;

	for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
		int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

		if (fd == -1)
			continue;

		if (!bind(fd, p->ai_addr, p->ai_addrlen)) {
			freeaddrinfo(res);
			return fd;
		}

		close(fd);
	}
	freeaddrinfo(res);

	return -1;
}

int client_socket(const char *node, const char *service, int type)
{
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;

	if (getaddrinfo(node, service, &hints, &res))
		return -1;

	for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
		int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

		if (fd == -1)
			continue;

		if (!connect(fd, p->ai_addr, p->ai_addrlen)) {
			freeaddrinfo(res);
			return fd;
		}

		close(fd);
	}
	freeaddrinfo(res);

	return -1;
}
