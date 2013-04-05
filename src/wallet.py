import json
import os

import bitkey_pb2 as proto
import wallet_pb2 as proto_wallet 
from algo import AlgoFactory
import tools
import signing
 
class Wallet(object):
    def __init__(self, filename):
        self.vendor = 'bitcointrezor.com'
        self.major_version = 0
        self.minor_version = 1
                
        self.maxfee_kb = 1000000 # == 0.01 BTC/kB
        self.algo_available = [proto.ELECTRUM,]
        
        self.secexp = 0 # Cache of secret exponent in numeric form

        self.UUID_filename = os.path.expanduser('~/.bitkey')
        self.init_UUID()
    
        self.filename = filename
        self.load() # Wallet protobuf object
        
    def get_features(self):
        m = proto.Features()
        m.vendor = self.vendor
        m.major_version = self.major_version
        m.minor_version = self.minor_version
        m.has_otp = self.struct.has_otp
        m.has_spv = self.struct.has_spv == True
        m.pin = self.struct.pin != ''
        m.algo = self.struct.algo
        m.algo_available.extend(self.algo_available)
        m.maxfee_kb = self.maxfee_kb
        return m
            
    def load(self):
        try:
            self.struct = proto_wallet.Wallet()
            self.struct.ParseFromString(open(self.filename, 'r').read())
        except IOError:
            # Wallet load failed, let's initialize new one
            self.struct = proto_wallet.Wallet(algo=proto.BIP32, seed='')
            
    def _deserialize_secexp(self):
        # Deserialize secexp to number format
        self.secexp = int(self.struct.secexp, 16)
        
    def save(self):
        open(self.filename, 'w').write(self.struct.SerializeToString())
        
    def init_UUID(self):
        UUID_len = 9
        if os.path.exists(self.UUID_filename) and \
           os.path.getsize(self.UUID_filename) == UUID_len:
            return
        
        print "Generating new device UUID..."
        f = open(self.UUID_filename, 'w')
        f.write(os.urandom(UUID_len))
        f.close()            
        
    def get_UUID(self):
        f = open(self.UUID_filename, 'r')
        uuid = f.read()
        f.close()
        return uuid
           
    def get_master_public_key(self):    
        af = AlgoFactory(self.algo)
        master_public_key = af.init_master_public_key(self.secexp)
        return master_public_key
    
    def get_address(self, n):
        af = AlgoFactory(self.algo)
        return af.get_new_address(self._get_secexp(), n)
                        
    def load_seed(self, seed_words):
        af = AlgoFactory(self.algo)
        seed = tools.get_seed(seed_words)
        
        print 'seed', seed
        print 'mnemonic', tools.get_mnemonic(seed)
        if seed_words != tools.get_mnemonic(seed):
            raise Exception("Seed words mismatch")
        
        self.wallet.secexp = af.get_secexp_from_seed(seed)
        self._deserialize_secexp()        
                
    def reset_seed(self, random):
        seed = tools.generate_seed(random)
        seed_words = tools.get_mnemonic(seed)
        self.load_seed(seed_words)
        
    def sign_input(self, addr_n, tx_hash):
        af = AlgoFactory(self.algo)
        return signing.sign_input(af, self._get_secexp(), addr_n, tx_hash)
