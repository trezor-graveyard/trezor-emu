#!/bin/bash

cd `dirname $0`

protoc --python_out=../trezor/ trezor.proto
protoc --python_out=../trezor/ wallet.proto
