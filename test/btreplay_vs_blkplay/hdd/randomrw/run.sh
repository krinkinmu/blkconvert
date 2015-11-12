#!/bin/bash

DIR=$(pwd)/mount
DISK=/dev/sdb1
SCRIPT=script.f

sudo umount ${DISK}
sudo mount -t ext4 ${DISK} ${DIR}
sudo chown -R kmu:kmu ${DIR}
sudo ~/ws/filebench/filebench -f ${SCRIPT}
sync
sudo umount ${DISK}
