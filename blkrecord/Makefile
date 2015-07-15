CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -I../common

SRC := blkrecord.c
DEP := $(SRC:.c=.d)
OBJ := $(SRC:.c=.o)
TGT := blkrecord


default: $(TGT)

$(TGT): $(OBJ)
	$(CC) $(OBJ) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c $< -o $@

-include $(DEP)

.PHONY: clean
clean:
	rm -rf $(DEP) $(OBJ) $(TGT)
