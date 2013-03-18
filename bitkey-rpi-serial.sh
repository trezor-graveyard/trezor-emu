#!/bin/bash

# add the following line to /etc/rc.local to invoke the script automatically on boot
# screen -AmdS bitkey bash -i /home/pi/bitkey-python/bitkey-rpi-serial.sh

# load kernel modules for spi communication
modprobe spi_bcm2708
modprobe spidev

# kill getty process interfering with serial port
pkill -f '.*getty.*ttyAMA0.*'

# chdir into script location
cd `dirname $0`

# run bitkey daemon
./src/bitkey.py -s # (serial transport on /dev/ttyAMA0 is the default)
