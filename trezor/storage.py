import os

import types_pb2 as types
import messages_pb2 as proto
import storage_pb2 as proto_storage
from bip32 import BIP32
import tools
import signing
import coindef
from mnemonic import Mnemonic

class NotInitializedException(Exception):
    pass

class Storage(object):
    def __init__(self, filename, bootloader_mode=False):
        self.vendor = 'bitcointrezor.com'
        self.major_version = 0
        self.minor_version = 1
        self.bugfix_version = 0

        self.storage_version = 1  # Version of wallet file

        self.default_settings = proto_storage.Storage(
            version=self.storage_version,
            language='english',
        )

        self.device_id_filename = os.path.expanduser('~/.trezor')
        self._init_device_id()

        self.bootloader_mode = bootloader_mode
        self.filename = filename
        self.load()  # Storage protobuf object

        self.init_session()

    def init_session(self):
        self.session = proto_storage.Session()
        self.session.coin.CopyFrom(coindef.BTC)

    def get_features(self):
        m = proto.Features()
        m.vendor = self.vendor
        m.major_version = self.major_version
        m.minor_version = self.minor_version
        m.bugfix_version = self.bugfix_version
        m.bootloader_mode = self.bootloader_mode
        
        m.device_id = self.get_device_id()
        
        m.pin_protection = bool(self.struct.pin != '')
        m.passphrase_protection = bool(self.struct.passphrase_protection)
        m.language = self.struct.language
        m.label = self.struct.label
        
        # Add currently active coin
        coin = m.coins.add()
        coin.CopyFrom(self.session.coin)

        # Append all other coins
        types = coindef.types.keys()
        types.sort()
        for t in types:
            if coindef.types[t].coin_shortcut == self.session.coin.coin_shortcut:
                continue
            coin = m.coins.add()
            coin.CopyFrom(coindef.types[t])
            
        print m
        return m

    def _init_device_id(self):
        device_id_len = 12
        if os.path.exists(self.device_id_filename) and \
           os.path.getsize(self.device_id_filename) == device_id_len:
            return

        print "Generating new device serial number..."
        f = open(self.device_id_filename, 'w')
        f.write(os.urandom(device_id_len))
        f.close()

    def check_struct(self, struct):
        # Check if protobuf struct loaded from local storage
        # is compatible with current codebase.

        # Stub for wallet format updates
        if struct.version != 1:
            raise IOError("Incompatible wallet file, creating new one")

    def load(self):
        try:
            struct = proto_storage.Storage()
            struct.ParseFromString(open(self.filename, 'r').read())

            # Update to newer version or raises IOError if not possible
            self.check_struct(struct)
            self.struct = struct

        except:
            print "Wallet load failed, creating new one"
            self.struct = proto_storage.Storage()
            self.struct.CopyFrom(self.default_settings)
            self.save()

        # Coindef structure is read-only for the app, so rewriting should
        # not affect anything. Its just workaround for changed coin definition in coindef file
        # if self.session.struct.coin.coin_shortcut in coindef.types.keys():
        #    self.session.struct.coin.CopyFrom(coindef.types[self.struct.settings.coin.coin_shortcut])
        # else:
        #    # When coin is no longer supported...
        #    self.struct.settings.coin.CopyFrom(self.default_settings.coin)

    def get_device_id(self):
        f = open(self.device_id_filename, 'r')
        sernum = f.read()
        f.close()
        return sernum

    def get_pin(self):
        return self.struct.pin

    def set_pin(self, new_pin):
        self.struct.pin = new_pin
        self.save()

    def set_protection(self, passphrase_protection):
        self.struct.passphrase_protection = bool(passphrase_protection)
        self.save()

    def get_maxfee_kb(self):
        return self.session.coin.maxfee_kb

    def get_address_type(self):
        return self.session.coin.address_type

    def get_label(self):
        return self.struct.label

    def get_languages(self):
        return ['english']

    def set_label(self, label):
        self.struct.label = label
        self.save()

    def set_language(self, language):
        if language in self.get_languages():
            self.struct.language = language
        else:
            raise Exception("Unsupported language")
        self.save()

    def is_initialized(self):
        if self.struct.HasField('mnemonic'):
            return True
        if self.struct.HasField('node'):
            return True
        return False
    
    def get_node(self):
        '''Return decrypted HDNodeType (from stored mnemonic or encrypted HDNodeType)'''
        if not self.is_initialized():
            raise NotInitializedException("Device not initalized")

        if self.struct.HasField('mnemonic') and self.struct.HasField('node'):
            raise Exception("Cannot have both mnemonic and node at the same time")
        
        if self.struct.passphrase_protection:
            raise Exception("passphrase decryption not implemented yet")
        else:
            if self.struct.HasField('mnemonic'):
                seed = Mnemonic(self.struct.language).to_seed(self.struct.mnemonic)
                self.session.node.CopyFrom(BIP32.get_node_from_seed(seed))
            else:
                self.session.node.CopyFrom(self.struct.node)

        return self.session.node

    def increase_pin_attempt(self):
        self.struct.pin_failed_attempts += 1
        self.save()

    def clear_pin_attempt(self):
        self.struct.pin_failed_attempts = 0
        self.save()

    def get_pin_delay(self):
        if self.struct.pin_failed_attempts:
            return 1.8 ** self.struct.pin_failed_attempts
        return 0

    def save(self):
        open(self.filename, 'w').write(self.struct.SerializeToString())

    def load_from_mnemonic(self, mnemonic):
        print 'mnemonic', mnemonic
        if not Mnemonic(self.struct.language).check(mnemonic):
            raise Exception("Invalid mnemonic")

        self.struct.mnemonic = mnemonic
        self.struct.ClearField('node')
        self.save()

        self.init_session()

    def load_from_node(self, node):
        self.struct.node.CopyFrom(node)
        self.struct.ClearField('mnemonic')
        self.save()

        self.init_session()

    def reset_seed(self, mnemonic):
        self.struct.mnemonic = mnemonic
        self.struct.ClearField('node')
        self.save()