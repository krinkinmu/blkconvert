#!/bin/bash

ORIGINAL_TRACES=traces
BTREPLAY_TRACES=btreplay_traces
BLKPLAY_TRACES=blkplay_traces
DEVNAME=sdb

blkparse -O -i ${DEVNAME} -D ${BTREPLAY_TRACES} -d ${DEVNAME}.btreplay
blkparse -O -i ${DEVNAME} -D ${BLKPLAY_TRACES} -d ${DEVNAME}.blkplay

btt -i ${DEVNAME}.blktrace > original.btt
btt -i ${DEVNAME}.btreplay > btreplay.btt
btt -i ${DEVNAME}.blkplay > blkplay.btt

seekwatcher -t ${DEVNAME} -D ${ORIGINAL_TRACES} -o original.png
seekwatcher -t ${DEVNAME} -D ${BTREPLAY_TRACES} -o btreplay.png
seekwatcher -t ${DEVNAME} -D ${BLKPLAY_TRACES} -o blkplay.png
