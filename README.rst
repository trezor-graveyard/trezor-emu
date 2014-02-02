trezor-emu
==========

Python implementation of TREZOR compatible hardware bitcoin wallet.

See http://bitcointrezor.com/ for more information.

How to install (Debian/Ubuntu/Raspbian)
---------------------------------------

* cd /home/pi (on Raspberry Pi)
* git clone https://github.com/trezor/trezor-emu.git
* sudo apt-get update
* sudo apt-get install python-dev python-setuptools screen
    (if you are not running on Raspberry Pi install python-pygame too)
* cd trezor-emu
* sudo python setup.py develop

* Running on standard desktop: ./emu.sh
* Running on Raspberry Pi: sudo ./rpi-serial.sh

* Autostart on Raspberry Pi (starts trezor-emu in 'screen'):
* sudo ln -s /home/pi/trezor-emu/rpi-init /etc/init.d/trezor
* sudo update-rc.d trezor defaults

TODO
--------

* x Implement deterministic keys / BIP32
* x Implement deterministic ECDSA / RFC 6979
* x Implement new mnemonic / BIP39
* x SetMaxFeeKb -> Settings
* x Allow to modify maxfeekb, coin type, ...
* x Implement SimpleSignTx
* Fix SignTx
* x Safe recovery of the seed
* x Finalize workflow for ResetDevice
* x Finalize LoadDevice
* x Allow importing xprv structure
* x Factory reset
* x Wipe device
* x Pin change
* x device_id
* x mpk_hash
* x Exponential pin backoff
* x PassphraseRequest
* x Encrypted seed
* x Plugin - signing script

