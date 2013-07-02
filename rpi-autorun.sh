#!/bin/bash
#
# Put following line to /etc/rc.local to start trezor-rpi on system boot:
#
# screen -AmdS trezor bash -i /home/pi/trezor/rpi-autorun.sh
#

cd `dirname $0`

while [ 1 ]
do
    git pull
    sh rpi-serial.sh
    sleep 2
done
