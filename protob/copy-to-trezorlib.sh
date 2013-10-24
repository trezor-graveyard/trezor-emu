#!/bin/bash

cd `dirname $0`

cp trezor.proto ../../python-trezor/protob/
../../python-trezor/protob/build.sh
