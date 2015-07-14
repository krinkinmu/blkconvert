CC       ?= gcc
BLKTRACE ?= ../blktrace
BTT      := $(BLKTRACE)/btt
CFLAGS   ?= -Wall -I$(BLKTRACE) -I$(BTT) \
	-UCOUNT_IOS -UDEBUG -DNDEBUG \
	-D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
LDFLAGS  := -laio -lrt -lpthread

CSRCS := rbtree.c blkioqueue.c blkconvert.c
CDEPS := $(CSRCS:.c=.d)
COBJS := $(CSRCS:.c=.o)
CTGT  := compress

RSRCS := btrecord.c
RDEPS := $(RSRCS:.c=.d)
ROBJS := $(RSRCS:.c=.o)
RTGT  := convert

PSRCS := btreplay.c
PDEPS := $(PSRCS:.c=.d)
POBJS := $(PSRCS:.c=.o)
PTGT  := play

-include $(CDEPS)
-include $(RDEPS)
-include $(PDEPS)

.PHONY: all
all: $(CTGT) $(RTGT) $(PTGT)

$(PTGT): $(POBJS)
	$(CC) $(POBJS) $(LDFLAGS) -o $@

$(RTGT): $(ROBJS)
	$(CC) $(ROBJS) $(LDFLAGS) -o $@

$(CTGT): $(COBJS)
	$(CC) $(COBJS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -MMD -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(CDEPS) $(COBJS) $(CTGT)
	rm -rf $(RDEPS) $(ROBJS) $(RTGT)
	rm -rf $(PDEPS) $(POBJS) $(PTGT)
