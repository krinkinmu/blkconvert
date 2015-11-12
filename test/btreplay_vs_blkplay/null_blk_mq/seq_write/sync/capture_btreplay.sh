#!/bin/bash

DEVICE=/dev/nullb0
TRACES=btreplay_traces

mkdir -p ${TRACES}
sudo blktrace -n 8 -d ${DEVICE} -o nullb0 -D ${TRACES}
