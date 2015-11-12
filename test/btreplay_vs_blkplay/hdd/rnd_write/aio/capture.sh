#!/bin/bash

DEVNAME=sdb
DEVICE=/dev/${DEVNAME}
TRACES=traces

mkdir -p ${TRACES}
sudo blktrace -d ${DEVICE} -o ${DEVNAME} -D ${TRACES}
