#!/bin/bash

INPUT=btrecord
DEVICE=nullb0
CPUS=4

sudo ~/ws/blktrace/btreplay/btreplay -c ${CPUS} -d ${INPUT} -F -W ${DEVICE}
sync
