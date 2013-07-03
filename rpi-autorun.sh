#!/bin/bash

cd `dirname $0`

while [ 1 ]
do
    echo "Updating sources from Git..."
    git pull

    echo "Starting trezor-emu..."
    sh rpi-serial.sh
    sleep 2
done
