CC      ?= gcc
CFLAGS  ?= -O3 -Wall -Wextra -Werror -D_GNU_SOURCE
LDFLAGS ?= 

BLKPLAY_LDFLAGS   := $(LDFLAGS) -laio -lz
BLKRECORD_LDFLAGS := $(LDFLAGS) -lz
BLKTIME_LDFLAGS   := $(LDFLAGS)
BLKOFFSET_LDFLAGS := $(LDFLAGS)

COMMON_SRC := algorithm.c object_cache.c file_io.c ctree.c list.c rbtree.c
COMMON_DEP := $(COMMON_SRC:.c=.d)
COMMON_OBJ := $(COMMON_SRC:.c=.o)

BLKRECORD_SRC := blkrecord.c
BLKRECORD_DEP := $(BLKRECORD_SRC:.c=.d)
BLKRECORD_OBJ := $(BLKRECORD_SRC:.c=.o)

BLKPLAY_SRC := blkplay.c
BLKPLAY_DEP := $(BLKPLAY_SRC:.c=.d)
BLKPLAY_OBJ := $(BLKPLAY_SRC:.c=.o)

BLKTIME_SRC := blktime.c
BLKTIME_DEP := $(BLKTIME_SRC:.c=.d)
BLKTIME_OBJ := $(BLKTIME_SRC:.c=.o)

BLKOFFSET_SRC := blkoffset.c
BLKOFFSET_DEP := $(BLKOFFSET_SRC:.c=.d)
BLKOFFSET_OBJ := $(BLKOFFSET_SRC:.c=.o)

default: blkrecord blkplay blktime blkoffset

blkoffset: $(BLKOFFSET_OBJ) $(COMMON_OBJ)
	$(CC) $^ $(BLKOFFSET_LDFLAGS) -o $@

blktime: $(BLKTIME_OBJ) $(COMMON_OBJ)
	$(CC) $^ $(BLKTIME_LDFLAGS) -o $@

blkrecord: $(BLKRECORD_OBJ) $(COMMON_OBJ)
	$(CC) $^ $(BLKRECORD_LDFLAGS) -o $@

blkplay: $(BLKPLAY_OBJ) $(COMMON_OBJ)
	$(CC) $^ $(BLKPLAY_LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c $< -o $@

-include $(COMMON_DEP)
-include $(BLKRECORD_DEP)
-include $(BLKPLAY_DEP)
-include $(BLKTIME_DEP)
-include $(BLKOFFSET_DEP)

.PHONY: clean
clean:
	rm -rf $(COMMON_DEP) $(COMMON_OBJ)
	rm -rf $(BLKOFFSET_DEP) $(BLKOFFSET_OBJ) blktime
	rm -rf $(BLKTIME_DEP) $(BLKTIME_OBJ) blktime
	rm -rf $(BLKRECORD_DEP) $(BLKRECORD_OBJ) blkrecord
	rm -rf $(BLKPLAY_DEP) $(BLKPLAY_OBJ) blkplay
