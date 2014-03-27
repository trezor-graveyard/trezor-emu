#!/bin/bash

cd `dirname $0`

# This cycle emulates device reset on DebugLinkStop message
while [ true ]; do

    rm -f /tmp/pipe.*
    python trezor/__init__.py -t pipe -p /tmp/pipe.trezor -d -dt pipe -dp /tmp/pipe.trezor_debug
    sleep 1

done
