#!/bin/bash

cd `dirname $0`

cp trezor.proto ../../python-trezor/protobuf/
../../python-trezor/protobuf/build.sh
