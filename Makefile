CC      ?= gcc
CFLAGS  ?= -g -std=c99 -O3 -Wall -Wextra -Werror -D_GNU_SOURCE
LDFLAGS ?= 

BLKPLAY_LDFLAGS          := $(LDFLAGS) -laio -lz
BLKRECORD_LDFLAGS        := $(LDFLAGS) -lz
BLKRECORD_CLIENT_LDFLAGS := $(LDFLAGS) -pthread
BLKRECORD_SERVER_LDFLAGS := $(LDFLAGS) -pthread

COMMON_SRC := algorithm.c object_cache.c file_io.c ctree.c list.c rbtree.c \
	debug.c utils.c network.c cbuffer.c deamon.c
COMMON_DEP := $(COMMON_SRC:.c=.d)
COMMON_OBJ := $(COMMON_SRC:.c=.o)

BLKRECORD_SRC := blkrecord.c blkqueue.c account.c
BLKRECORD_DEP := $(BLKRECORD_SRC:.c=.d)
BLKRECORD_OBJ := $(BLKRECORD_SRC:.c=.o)

BLKRECORD_CLIENT_SRC := blkrecord_client.c blkrecord_common.c account.c
BLKRECORD_CLIENT_DEP := $(BLKRECORD_CLIENT_SRC:.c=.d)
BLKRECORD_CLIENT_OBJ := $(BLKRECORD_CLIENT_SRC:.c=.o)

BLKRECORD_SERVER_SRC := blkrecord_server.c blkrecord_common.c account.c
BLKRECORD_SERVER_DEP := $(BLKRECORD_SERVER_SRC:.c=.d)
BLKRECORD_SERVER_OBJ := $(BLKRECORD_SERVER_SRC:.c=.o)

BLKPLAY_SRC := blkplay.c io_engine.c usio_engine.c aio_engine.c generator.c
BLKPLAY_DEP := $(BLKPLAY_SRC:.c=.d)
BLKPLAY_OBJ := $(BLKPLAY_SRC:.c=.o)

default: blkrecord-client blkrecord-server blkrecord blkplay

blkrecord-client: $(BLKRECORD_CLIENT_OBJ) $(COMMON_OBJ)
	$(CC) $^ $(BLKRECORD_CLIENT_LDFLAGS) -o $@

blkrecord-server: $(BLKRECORD_SERVER_OBJ) $(COMMON_OBJ)
	$(CC) $^ $(BLKRECORD_SERVER_LDFLAGS) -o $@

blkrecord: $(BLKRECORD_OBJ) $(COMMON_OBJ)
	$(CC) $^ $(BLKRECORD_LDFLAGS) -o $@

blkplay: $(BLKPLAY_OBJ) $(COMMON_OBJ)
	$(CC) $^ $(BLKPLAY_LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c $< -o $@

-include $(COMMON_DEP)
-include $(BLKRECORD_CLIENT_DEP)
-include $(BLKRECORD_SERVER_DEP)
-include $(BLKRECORD_DEP)
-include $(BLKPLAY_DEP)

.PHONY: clean
clean:
	rm -rf $(COMMON_DEP) $(COMMON_OBJ)
	rm -rf $(BLKRECORD_CLIENT_DEP) $(BLKRECORD_CLIENT_OBJ) blkrecord-client
	rm -rf $(BLKRECORD_SERVER_DEP) $(BLKRECORD_SERVER_OBJ) blkrecord-server
	rm -rf $(BLKRECORD_DEP) $(BLKRECORD_OBJ) blkrecord
	rm -rf $(BLKPLAY_DEP) $(BLKPLAY_OBJ) blkplay
