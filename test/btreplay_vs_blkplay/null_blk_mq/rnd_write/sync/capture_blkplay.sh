#!/bin/bash

DEVICE=/dev/nullb0
TRACES=blkplay_traces

mkdir -p ${TRACES}
sudo blktrace -d ${DEVICE} -o nullb0 -D ${TRACES}
