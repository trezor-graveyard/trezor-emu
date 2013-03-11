#!/bin/bash

# Put following line to rc.local:
# screen -AmdS bitkey bash -i /home/pi/bitkey-python/bitkey-rpi.sh

cd `dirname $0`

./setup_hw.sh

./src/bitkey.py -s
