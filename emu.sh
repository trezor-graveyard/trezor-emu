#!/bin/bash

cd `dirname $0`

rm -f pipe.*
python trezor/__init__.py -t pipe -p pipe.trezor -d -dt pipe -dp pipe.trezor_debug
