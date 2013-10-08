import os

import trezor_pb2 as proto
import storage_pb2 as proto_storage
from bip32 import BIP32
import tools
import signing
import coindef
import mnemonic

class NoXprvException(Exception):
    pass

class Storage(object):
    def __init__(self, filename):
        self.vendor = 'bitcointrezor.com'
        self.major_version = 0
        self.minor_version = 1

        self.default_settings = proto.SettingsType(
            language='english',
            coin=coindef.BTC,
        )

        self.device_id_filename = os.path.expanduser('~/.trezor')
        self._init_device_id()

        self.filename = filename
        self.load()  # Storage protobuf object

    def get_features(self):
        m = proto.Features()
        m.vendor = self.vendor
        m.major_version = self.major_version
        m.minor_version = self.minor_version
        m.settings.CopyFrom(self.struct.settings)
        m.device_id = self.get_device_id()
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

    def load(self):
        try:
            self.struct = proto_storage.Storage()
            self.struct.ParseFromString(open(self.filename, 'r').read())
        except IOError:
            # Wallet load failed, let's initialize new one
            self.struct = proto_storage.Storage()
            self.struct.settings.CopyFrom(self.default_settings)

        # Coindef structure is read-only for the app, so rewriting should
        # not affect anything. Its just workaround for changed coin definition in coindef file
        if self.struct.settings.coin.coin_shortcut in coindef.types.keys():
            self.struct.settings.coin.CopyFrom(coindef.types[self.struct.settings.coin.coin_shortcut])
        else:
            # When coin is no longer supported...
            self.struct.settings.coin.CopyFrom(self.default_settings.coin)

    def get_device_id(self):
        f = open(self.device_id_filename, 'r')
        sernum = f.read()
        f.close()
        return sernum

    def get_pin(self):
        return self.struct.pin

    def get_maxfee_kb(self):
        return self.struct.maxfee_kb

    def get_address_type(self):
        return self.struct.settings.coin.address_type

    def get_label(self):
        return self.struct.settings.label

    def get_languages(self):
        return ['english']

    def get_xprv(self):
        if not self.struct.xprv.private_key:
            raise NoXprvException("Device not initalized")
        return self.struct.xprv

    def save(self):
        open(self.filename, 'w').write(self.struct.SerializeToString())

    def load_from_mnemonic(self, words):
        seed = mnemonic.Mnemonic('english').decode(words)

        print 'seed', seed
        print 'mnemonic', mnemonic.Mnemonic('english').encode(seed)
        if words != mnemonic.Mnemonic('english').encode(seed):
            raise Exception("Seed words mismatch")

        xprv = BIP32.get_xprv_from_seed(seed)
        self.struct.xprv.CopyFrom(xprv)

    '''
    def reset_seed(self, random):
        seed = tools.generate_seed(random)
        seed_words = tools.get_mnemonic(seed)
        self.load_seed(seed_words)
        return seed_words
    '''
