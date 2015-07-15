CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror
LDFLAGS ?= 

BLKPLAY_CFLAGS := $(CFLAGS) -I../common -D_GNU_SOURCE
BLKPLAY_LDFLAGS := $(LDFLAGS) -laio

SRC := blkplay.c iocbcache.c
DEP := $(SRC:.c=.d)
OBJ := $(SRC:.c=.o)
TGT := blkplay


default: $(TGT)

$(TGT): $(OBJ)
	$(CC) $(OBJ) $(BLKPLAY_LDFLAGS) -o $@

%.o: %.c
	$(CC) $(BLKPLAY_CFLAGS) -MMD -c $< -o $@

-include $(DEP)

.PHONY: clean
clean:
	rm -rf $(DEP) $(OBJ) $(TGT)
