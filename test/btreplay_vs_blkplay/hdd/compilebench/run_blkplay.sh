#!/bin/bash

DEVNAME=sdb
RECORD=${DEVNAME}.blkrecord
DEVICE=/dev/${DEVNAME}

sudo ~/ws/blkconvert/blkplay -f ${RECORD} -d ${DEVICE} -t -e 4096
sync
