#!/bin/bash

DEVNAME=sdb
DEVICE=/dev/${DEVNAME}
SCRIPT=script.fio

sudo fio ${SCRIPT}
sync
