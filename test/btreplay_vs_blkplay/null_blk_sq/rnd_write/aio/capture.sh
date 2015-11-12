#!/bin/bash

DEVICE=/dev/nullb0
TRACES=traces

mkdir -p ${TRACES}
sudo blktrace -d ${DEVICE} -o nullb0 -D ${TRACES}
