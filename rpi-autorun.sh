#!/bin/bash

cd `dirname $0`

while true
do
    ./display.py -t "Updating from git..."
    git pull

    ./display.py -t "Applying changes..."
    python setup.py develop

    echo "Starting trezor-emu..."
    ./rpi-serial.sh

    ./display.py -t "Restarting app..."
    sleep 2
done
