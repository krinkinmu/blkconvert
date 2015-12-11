#!/bin/bash

DEVICE=/dev/nullb0
SCRIPT=rnd_read_sync.fio

# load null_blk in single queue mode
# sudo modprobe null_blk queue_mode=1 irqmode=2
sudo fio ${SCRIPT}
sync
