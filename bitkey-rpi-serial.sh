#!/bin/bash
# load kernel modules for spi communication
modprobe spi_bcm2708
modprobe spidev

# kill getty process interfering with serial port
pkill -f '.*getty.*ttyAMA0.*'

# chdir into script location
cd `dirname $0`

# run bitkey daemon
./src/bitkey.py -s # (serial transport on /dev/ttyAMA0 is the default)
