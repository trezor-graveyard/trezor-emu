#!/bin/bash

cd `dirname $0`

# This cycle emulates device reset on DebugLinkStop message
while [ true ]; do

    rm -f pipe.*
    python trezor/__init__.py -t pipe -p pipe.trezor -d -dt pipe -dp pipe.trezor_debug
    sleep 1

done
