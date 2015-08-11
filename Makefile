CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Werror -D_GNU_SOURCE
LDFLAGS ?= 

BLKPLAY_LDFLAGS   := $(LDFLAGS) -laio
BLKRECORD_LDFLAGS := $(LDFLAGS)

COMMON_SRC := algorithm.c object_cache.c file_io.c ctree.c list.c
COMMON_DEP := $(COMMON_SRC:.c=.d)
COMMON_OBJ := $(COMMON_SRC:.c=.o)

BLKRECORD_SRC := blkrecord.c
BLKRECORD_DEP := $(BLKRECORD_SRC:.c=.d)
BLKRECORD_OBJ := $(BLKRECORD_SRC:.c=.o)

BLKPLAY_SRC := blkplay.c
BLKPLAY_DEP := $(BLKPLAY_SRC:.c=.d)
BLKPLAY_OBJ := $(BLKPLAY_SRC:.c=.o)

default: blkrecord blkplay

blkrecord: $(BLKRECORD_OBJ) $(COMMON_OBJ)
	$(CC) $^ $(BLKRECORD_LDFLAGS) -o $@

blkplay: $(BLKPLAY_OBJ) $(COMMON_OBJ)
	$(CC) $^ $(BLKPLAY_LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c $< -o $@

-include $(COMMON_DEP)
-include $(BLKRECORD_DEP)
-include $(BLKPLAY_DEP)

.PHONY: clean
clean:
	rm -rf $(COMMON_DEP) $(COMMON_OBJ)
	rm -rf $(BLKRECORD_DEP) $(BLKRECORD_OBJ) blkrecord
	rm -rf $(BLKPLAY_DEP) $(BLKPLAY_OBJ) blkplay
