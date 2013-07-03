#!/bin/bash

cd `dirname $0`

while [ 1 ]
do
    ./disp.sh -t "Updating from git..."
    git pull

    ./disp.sh -t "Applying changes..."
    python setup.py develop

    echo "Starting trezor-emu..."
    ./rpi-serial.sh

    ./disp.sh -t "Restarting app..."
    sleep 2
done
