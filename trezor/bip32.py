# import pycoin.wallet as pywallet
import ecdsa
import struct
from binascii import hexlify, unhexlify
import hashlib
import hmac
import trezor_pb2 as proto
from tools import public_key_to_bc_address
from ecdsa.curves import SECP256k1
from ecdsa.keys import SigningKey, VerifyingKey
from ecdsa.util import string_to_number, number_to_string

class BIP32(object):
    def __init__(self, xprv):
        self.xprv = xprv

    def _secexp(self):
        return string_to_number(self.xprv.private_key)

    @classmethod
    def get_xprv_from_seed(cls, seed):
        I64 = hmac.HMAC(key=b"Bitcoin seed", msg=seed, digestmod=hashlib.sha512).digest()

        xprv = proto.XprvType()
        xprv.version = unhexlify("0488ADE4")  # Main net
        xprv.depth = 0
        xprv.fingerprint = 0x00000000
        xprv.child_num = 0
        xprv.chain_code = I64[32:]
        xprv.private_key = I64[:32]
        return xprv

    @classmethod
    def from_seed(cls, seed):
        return cls(cls.get_xprv_from_seed(seed))

    def _get_master_private_key(self):
        return SigningKey.from_secret_exponent(self._secexp(), SECP256k1)

    def _get_master_public_key(self):
        return self._get_master_private_key().get_verifying_key()

    def get_master_public_key(self):
        return hexlify(self._get_master_public_key().to_string())

    def get_address(self, n):
        private_key = self.get_private_key(n)

        '''
        master_public_key = cls.init_master_public_key(secexp)

        z = cls._get_sequence(master_public_key, n)
        master_public_key = ecdsa.VerifyingKey.from_string(master_public_key, curve=SECP256k1)
        pubkey_point = master_public_key.pubkey.point + z * SECP256k1.generator
        public_key2 = ecdsa.VerifyingKey.from_public_point(pubkey_point, curve=SECP256k1)
        address = public_key_to_bc_address('04'.decode('hex') + public_key2.to_string())
        return address
        '''
        
    def get_private_key(self, n):
        if not isinstance(n, list):
            raise Exception('Parameter must be a list')

        xprv = proto.XprvType()
        xprv.CopyFrom(self.xprv)
        
        for i in n:
            xprv.CopyFrom(self._get_subkey(xprv, i))
        
        return xprv.private_key
        
    @classmethod
    def _get_subkey(cls, xprv, i):
        # Key derivation algorithm of BIP32
        if i < 0:
            i_as_bytes = struct.pack(">l", i)
        else:
            i &= 0x7fffffff
            i |= 0x80000000
            i_as_bytes = struct.pack(">L", i)

        data = b'\0' + xprv.private_key + i_as_bytes
        I64 = hmac.HMAC(key=xprv.chain_code, msg=data, digestmod=hashlib.sha512).digest()
        I_left_as_exponent = string_to_number(I64[:32])
        secexp = (I_left_as_exponent + string_to_number(xprv.private_key)) % SECP256k1.generator.order()
        
        xprv_out = proto.XprvType()
        xprv_out.version = xprv.version
        xprv_out.depth = xprv.depth + 1
        xprv_out.child_num = i
        xprv_out.chain_code = I64[32:]
        xprv_out.private_key = number_to_string(secexp, SECP256k1.generator.order())

        return xprv_out
