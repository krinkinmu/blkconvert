#!/bin/bash

DEVICE=/dev/nullb0
TRACES=btreplay_traces

mkdir -p ${TRACES}
sudo blktrace -b 1024 -n 8 -d ${DEVICE} -o nullb0 -D ${TRACES}
