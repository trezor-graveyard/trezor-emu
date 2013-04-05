#!/bin/bash

rm -f bitkey*.pipe*

./src/bitkey.py -t pipe -p bitkey.pipe -d -dt pipe -dp bitkey_debug.pipe
