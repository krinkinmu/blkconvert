#!/bin/bash

INPUT=traces
OUTPUT=btrecord
DEVICE=nullb0

mkdir -p ${OUTPUT}
btrecord -d ${INPUT} -D ${OUTPUT} -F ${DEVICE}
