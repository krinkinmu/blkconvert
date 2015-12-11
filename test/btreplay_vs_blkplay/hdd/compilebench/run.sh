#!/bin/bash

DIR=$(pwd)/mount
DISK=/dev/sdb1

sudo umount ${DISK}
sudo mount -t ext4 ${DISK} ${DIR}
sudo chown -R kmu:kmu ${DIR}
cd ~/ws/compilebench/ 
python compilebench -D ${DIR} -i 10 --makej
cd -
sync
sudo umount ${DISK}
