#!/bin/bash

DEVNAME=sdb
DEVICE=/dev/${DEVNAME}
TRACES=btreplay_traces

mkdir -p ${TRACES}
sudo blktrace -d ${DEVICE} -o ${DEVNAME} -D ${TRACES}
