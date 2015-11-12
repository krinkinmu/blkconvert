#!/bin/bash

DEVICE=/dev/nullb0
TRACES=btreplay_traces

mkdir -p ${TRACES}
sudo blktrace -d ${DEVICE} -o nullb0 -D ${TRACES}
