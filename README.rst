trezor-emu
==========

Python implementation of TREZOR compatible hardware bitcoin wallet.

See http://bitcointrezor.com/ for more information.

How to install
--------------

* git clone https://github.com/trezor/trezor-emu.git
* sudo apt-get install python-dev python-setuptools
* cd trezor-emu
* sudo python setup.py develop
* Running on standard desktop: ./emu.sh
* Running on Raspberry Pi: sudo ./rpi-serial.sh

TODO
--------

* Implement deterministic keys / BIP32
* Implement deterministic ECDSA / RFC 6979
* Implement SimpleSignTx
* Fix SignTx
* Finalize workflow for ResetDevice
* Finalize LoadDevice
* Implement new mnemonic / BIP39
* SetMaxFeeKb -> Settings
* Allow to modify maxfeekb, address_prefix, coin_name, coin_shortcut
