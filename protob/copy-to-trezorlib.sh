#!/bin/bash

cd `dirname $0`

cp trezor.proto ../../trezor-python/protobuf/
../../trezor-python/protobuf/build.sh
