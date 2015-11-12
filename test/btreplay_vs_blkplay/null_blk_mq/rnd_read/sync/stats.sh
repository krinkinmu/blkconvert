#!/bin/bash

ORIGINAL_TRACES=traces
BTREPLAY_TRACES=btreplay_traces
BLKPLAY_TRACES=blkplay_traces
DEVICE=nullb0

blkparse -O -i ${DEVICE} -D ${BTREPLAY_TRACES} -d ${DEVICE}.btreplay
blkparse -O -i ${DEVICE} -D ${BLKPLAY_TRACES} -d ${DEVICE}.blkplay

btt -i ${DEVICE}.blktrace > original.btt
btt -i ${DEVICE}.btreplay > btreplay.btt
btt -i ${DEVICE}.blkplay > blkplay.btt

seekwatcher -t ${DEVICE} -D ${ORIGINAL_TRACES} -o original.png
seekwatcher -t ${DEVICE} -D ${BTREPLAY_TRACES} -o btreplay.png
seekwatcher -t ${DEVICE} -D ${BLKPLAY_TRACES} -o blkplay.png
