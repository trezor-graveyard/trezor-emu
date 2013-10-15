trezor-emu
==========

Python implementation of TREZOR compatible hardware bitcoin wallet.

See http://bitcointrezor.com/ for more information.

How to install
--------------

* git clone https://github.com/trezor/trezor-emu.git
* sudo apt-get update
* sudo apt-get install python-dev python-setuptools
* cd trezor-emu
* sudo python setup.py develop
* Running on standard desktop: ./emu.sh
* Running on Raspberry Pi: sudo ./rpi-serial.sh

TODO
--------

* x Implement deterministic keys / BIP32
* x Implement deterministic ECDSA / RFC 6979
* x Implement new mnemonic / BIP39
* x SetMaxFeeKb -> Settings
* x Allow to modify maxfeekb, coin type, ...
* Implement SimpleSignTx
* Fix SignTx
* Safe recovery of the seed
* Finalize workflow for ResetDevice
* Finalize LoadDevice
* Allow importing xprv structure
* Factory reset
* Wipe device
* Pin change
* device_id
* mpk_hash
* x Exponential pin backoff
* PassphraseRequest
* Encrypted seed
* MPK on storage
* Plugin - signing script
