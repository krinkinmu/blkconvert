#!/bin/bash

INPUT=btrecord
DEVNAME=sdb
CPUS=4

sudo ~/ws/blktrace/btreplay/btreplay -c ${CPUS} -d ${INPUT} -F -W ${DEVNAME}
sync
