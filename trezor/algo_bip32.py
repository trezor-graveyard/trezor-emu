import ecdsa
import hashlib
from tools import Hash, SECP256k1, public_key_to_bc_address, generator_secp256k1

'''
    This is a mega-hack; implementation of Electrum seed in class 'BIP32'. I just need to test new structure,
    implementation of BIP32 will come very soon...
'''

class AlgoBIP32(object):
    @classmethod
    def _get_sequence(cls, master_public_key, n):
        return ecdsa.util.string_to_number(Hash("%d:%d:%s" % (n[0], n[1], master_public_key)))

    @classmethod
    def get_secexp_from_seed(cls, seed):
        # Perform seed stretching
        oldseed = seed
        for _ in range(100000):
            seed = hashlib.sha256(seed + oldseed).digest()
        return ecdsa.util.string_to_number(seed)

    @classmethod
    def init_master_private_key(cls, secexp):
        private_key = ecdsa.SigningKey.from_secret_exponent(secexp, curve=SECP256k1)
        return private_key

    @classmethod
    def init_master_public_key(cls, secexp):
        master_public_key = cls.init_master_private_key(secexp)
        return master_public_key.get_verifying_key().to_string()

    @classmethod
    def get_new_address(cls, secexp, n):
        # Electrum has two branches of keys - standard and change addresses
        # n[0] represent index in branch
        # n[1] == 0 is for standard addresses, n[1] == 1 for change addresses
        if len(n) != 2:
            raise Exception("n must have exactly two values")

        """Publickey(type,n) = Master_public_key + H(n|S|type)*point  """
        master_public_key = cls.init_master_public_key(secexp)
        z = cls._get_sequence(master_public_key, n)
        master_public_key = ecdsa.VerifyingKey.from_string(master_public_key, curve=SECP256k1)
        pubkey_point = master_public_key.pubkey.point + z * SECP256k1.generator
        public_key2 = ecdsa.VerifyingKey.from_public_point(pubkey_point, curve=SECP256k1)
        address = public_key_to_bc_address('04'.decode('hex') + public_key2.to_string())
        return address

    @classmethod
    def get_private_key(cls, secexp, n):
        # Electrum has only one branch of keys
        if len(n) != 2:
            raise Exception("n must have exactly two values")

        """  Privatekey(type,n) = Master_private_key + H(n|S|type)  """
        order = generator_secp256k1.order()
        secexp2 = (secexp + cls._get_sequence(cls.init_master_public_key(secexp), n)) % order
        return ecdsa.util.number_to_string(secexp2, order)
