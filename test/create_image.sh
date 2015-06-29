#!/bin/bash

BLOCKSIZE=1024
BLOCKCOUNT=1048576
FILENAME="disk.img"

if [ -n "$1" ]
then
	BLOCKCOUNT=$1
fi

if [ -n "$2" ]
then
	FILENAME="$2"
fi

dd if=/dev/zero of="$FILENAME" bs=$BLOCKSIZE count=$BLOCKCOUNT
