#!/bin/bash

RECORD=nullb0.blkrecord
DEVICE=/dev/nullb0

sudo ~/ws/blkconvert/blkplay -f ${RECORD} -d ${DEVICE} -t -e 4096
sync
