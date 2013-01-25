import json
import os

import bitkey_pb2 as proto
from algo import AlgoFactory
import tools
import signing
 
class Wallet(object):
    def __init__(self):
        self.vendor = 'slush'
        self.major_version = 0
        self.minor_version = 1
        
        self.seed = '' # Seed in hex form
        self.otp = False
        self.spv = False
        self.pin = ''
        self.algo = [proto.ELECTRUM,]
        self.maxfee_kb = 100000 # == 0.001 BTC/kB
        
        self.secexp = 0 # Cache of secret exponent (from seed)

        self.UUID_filename = os.path.expanduser('~/.bitkey')
        self.init_UUID()
        
    @classmethod    
    def load(cls, filename):
        data = json.load(open(filename, 'r'))
        dev = cls()
        dev.seed = str(data['seed'])
        dev.otp = data['otp']
        dev.spv = data['spv']
        dev.pin = data['pin']
        dev.maxfee_kb = data['maxfee_kb']
        return dev
        
    def save(self, filename):
        data = {}
        data['seed'] = self.seed
        data['otp'] = self.otp
        data['spv'] = self.spv
        data['pin'] = self.pin
        data['maxfee_kb'] = self.maxfee_kb
        
        json.dump(data, open(filename, 'w'))
        
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
    
    def get_seed(self):
        if self.seed == '':
            raise Exception("Device not initialized")
        return self.seed
    
    def _get_secexp(self):
        if self.secexp == 0:
            self.secexp = tools.get_secexp(self.get_seed())
        return self.secexp
        
    def get_master_public_key(self, algo):    
        af = AlgoFactory(algo)
        master_public_key = af.init_master_public_key(self._get_secexp())
        return master_public_key
    
    def get_address(self, algo, n):
        af = AlgoFactory(algo)
        return af.get_new_address(self._get_secexp(), n)
        
    def get_mnemonic(self):
        return tools.get_mnemonic(self.get_seed())
                    
    def load_seed(self, seed_words):
        self.secexp = 0 # Flush secexp cache!
        self.seed = tools.get_seed(seed_words)
        print 'seed', self.seed
        print self.get_mnemonic()
        
    def reset_seed(self, random):
        self.secexp = 0 # Flush secexp cache!
        seed = tools.generate_seed(random)
        seed_words = tools.get_mnemonic(seed)
        self.load_seed(seed_words)
        
    '''
    def set_otp(self, is_otp):
        self.otp = is_otp
    
    def set_pin(self, pin):
        self.pin = pin
    
    def set_spv(self, spv):
        self.spv = spv
    '''
        
    def sign_input(self, algo, addr_n, tx_hash):
        if algo not in self.algo:
            raise Exception("Unsupported algo")
        
        af = AlgoFactory(algo)
        return signing.sign_input(af, self._get_secexp(), addr_n, tx_hash)