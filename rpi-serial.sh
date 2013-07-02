#!/bin/bash
# load kernel modules for spi communication
modprobe spi_bcm2708
modprobe spidev

# stop getty process interfering with serial port
pkill -STOP -f '.*getty.*ttyAMA0.*'

# chdir into script location
cd `dirname $0`

# run trezor daemon
trezor-emu -s # (serial transport on /dev/ttyAMA0 is the default)

# resume getty
pkill -CONT -f '.*getty.*ttyAMA0.*'
