CC ?= gcc
BLKTRACE ?= ../blktrace
BTREPLAY ?= ../blktrace/btreplay
CFLAGS ?= -Wall -Werror -std=gnu99 -I$(BLKTRACE) -I$(BTREPLAY)
LDFLAGS ?=

CSRCS := rbtree.c blkioqueue.c blkconvert.c
CDEPS := $(CSRCS:.c=.d)
COBJS := $(CSRCS:.c=.o)
CTGT := convert

RSRCS := btrecord.c
RDEPS := $(RSRCS:.c=.d)
ROBJS := $(RSRCS:.c=.o)
RTGT := record

-include $(CDEPS)
-include $(RDEPS)

.PHONY: all
all: $(CTGT) $(RTGT)

$(RTGT): $(ROBJS)
	$(CC) $(LDFLAGS) $(ROBJS) -o $@

$(CTGT): $(COBJS)
	$(CC) $(LDFLAGS) $(COBJS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(CDEPS) $(COBJS) $(CTGT)
	rm -rf $(RDEPS) $(ROBJS) $(RTGT)
