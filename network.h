#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int server_socket(const char *service, int type);
int client_socket(const char *node, const char *service, int type);

#endif /*__NETWORK_H__*/
