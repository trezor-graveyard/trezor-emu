#!/bin/bash
# load kernel modules for spi communication
modprobe spi_bcm2708
modprobe spidev

# chdir into script location
cd `dirname $0`

# run bitkey daemon
./src/bitkey.py -s -t socket -p 0.0.0.0:2000
