import ecdsa
import hashlib
from tools import Hash, SECP256k1, public_key_to_bc_address, generator_secp256k1, raw_tx

class AlgoElectrum(object):
    
    @classmethod
    def _stretch_key(cls, seed):
        oldseed = seed
        for _ in range(100000):
            seed = hashlib.sha256(seed + oldseed).digest()
        return ecdsa.util.string_to_number(seed)

    @classmethod
    def _get_sequence(cls, master_public_key, n):
        return ecdsa.util.string_to_number(Hash( "%d:0:" % n + master_public_key ))

    @classmethod
    def init_master_private_key(cls, seed):
        secexp = cls._stretch_key(seed)
        return ecdsa.SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
    
    @classmethod
    def init_master_public_key(cls, seed):
        master_private_key = cls.init_master_private_key(seed)
        return master_private_key.get_verifying_key().to_string()

    @classmethod
    def get_new_address(cls, seed, n):
        # Electrum has only one branch of keys
        n = n[0]
        
        """Publickey(type,n) = Master_public_key + H(n|S|type)*point  """
        master_public_key = cls.init_master_public_key(seed)
        z = cls._get_sequence(master_public_key, n)
        master_public_key = ecdsa.VerifyingKey.from_string(master_public_key, curve=SECP256k1 )
        pubkey_point = master_public_key.pubkey.point + z*SECP256k1.generator
        public_key2 = ecdsa.VerifyingKey.from_public_point( pubkey_point, curve = SECP256k1 )
        address = public_key_to_bc_address('04'.decode('hex') + public_key2.to_string() )
        return address
    
    @classmethod
    def get_private_key(cls, seed, n):
        # Electrum has only one branch of keys
        n = n[0]
        
        """  Privatekey(type,n) = Master_private_key + H(n|S|type)  """
        order = generator_secp256k1.order()
        secexp = cls._stretch_key(seed)
        secexp = ( secexp + cls._get_sequence(cls.init_master_public_key(seed), n) ) % order
        return ecdsa.util.number_to_string(secexp,order)