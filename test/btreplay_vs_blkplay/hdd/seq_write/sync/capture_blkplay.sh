#!/bin/bash

DEVNAME=sdb
DEVICE=/dev/${DEVNAME}
TRACES=blkplay_traces

mkdir -p ${TRACES}
sudo blktrace -d ${DEVICE} -o ${DEVNAME} -D ${TRACES}
