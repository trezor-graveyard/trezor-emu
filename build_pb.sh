#!/bin/bash
CURDIR=$(pwd)

cd $CURDIR/../trezor-common/protob

for i in messages storage types ; do
    protoc --python_out=$CURDIR/trezor/ -I/usr/include -I. $i.proto
done
