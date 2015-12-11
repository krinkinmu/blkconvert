#!/bin/bash

INPUT=traces
TRACE=nullb0.blktrace
OUTPUT=nullb0.blkrecord
DEVICE=nullb0

blkparse -O -i ${DEVICE} -D ${INPUT} -d ${TRACE}
~/ws/blkconvert/blkrecord -f ${TRACE} -o ${OUTPUT} -p
