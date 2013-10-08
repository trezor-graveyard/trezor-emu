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
        xprv.version = 0x0488ADE4  # Main net
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
        mpk = proto.XpubType()
        mpk.version = self.xprv.version
        mpk.depth = self.xprv.depth
        mpk.fingerprint = self.xprv.fingerprint
        mpk.child_num = self.xprv.child_num
        mpk.chain_code = self.xprv.chain_code
        mpk.public_key = self._get_master_public_key().to_string()
        print len(mpk.public_key)
        return mpk

    def get_address(self, n, address_type):
        secexp = string_to_number(self.get_private_key(n))
        pubkey = SigningKey.from_secret_exponent(secexp, SECP256k1).get_verifying_key()
        address = public_key_to_bc_address('\x04' + pubkey.to_string(), address_type)
        return address
        
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
