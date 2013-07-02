#!/bin/bash

cd `dirname $0`

rm -f pipe.*
trezor-emu -t pipe -p pipe.trezor -d -dt pipe -dp pipe.trezor_debug
