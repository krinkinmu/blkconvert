#!/bin/bash

INPUT=traces
OUTPUT=btrecord
DEVNAME=sdb

mkdir -p ${OUTPUT}
btrecord -d ${INPUT} -D ${OUTPUT} -F ${DEVNAME}
