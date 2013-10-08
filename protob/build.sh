#!/bin/bash

cd `dirname $0`

protoc --python_out=../trezor/ -I/usr/include -I. trezor.proto
protoc --python_out=../trezor/ -I/usr/include -I. storage.proto
