#!/bin/bash

cd `dirname $0`

cp ../trezor/types_pb2.py ../../python-trezor/trezorlib/
cp ../trezor/messages_pb2.py ../../python-trezor/trezorlib/
