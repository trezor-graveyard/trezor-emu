#!/bin/bash

rm pipe.*
./src/bitkey.py -t pipe -p pipe -d -dt pipe -dp pipe.debug
#./bitkey.py -t socket -p 127.0.0.1:2000 -d -dt pipe -dp ../pipe.debug
