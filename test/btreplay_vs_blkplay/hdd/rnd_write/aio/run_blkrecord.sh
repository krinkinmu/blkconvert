#!/bin/bash

DEVNAME=sdb
INPUT=traces
TRACE=${DEVNAME}.blktrace
OUTPUT=${DEVNAME}.blkrecord

blkparse -O -i ${DEVNAME} -D ${INPUT} -d ${TRACE}
~/ws/blkconvert/blkrecord -f ${TRACE} -o ${OUTPUT} -p
