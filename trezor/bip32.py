# import pycoin.wallet as pywallet
import ecdsa
import struct
from binascii import hexlify, unhexlify
import hashlib
import hmac
import trezor_pb2 as proto
from tools import public_key_to_bc_address, bip32_fingerprint
from ecdsa.curves import SECP256k1
from ecdsa.keys import SigningKey, VerifyingKey
from ecdsa.util import string_to_number, number_to_string

PRIME_DERIVATION_FLAG = 0x80000000

class BIP32(object):
    def __init__(self, node):
        if node.public_key == '':
            # Calculate pubkey if missing (public_key is optional field)
            node.public_key = self._get_pubkey(node.private_key)

        self.node = node

    @classmethod
    def get_node_from_seed(cls, seed):
        I64 = hmac.HMAC(key=b"Bitcoin seed", msg=seed, digestmod=hashlib.sha512).digest()

        node = proto.HDNodeType()
        node.version = 0x0488ADE4  # Main net
        node.depth = 0
        node.fingerprint = 0x00000000
        node.child_num = 0
        node.chain_code = I64[32:]
        node.private_key = I64[:32]
        return node

    @classmethod
    def from_seed(cls, seed):
        return cls(cls.get_node_from_seed(seed))

    @classmethod
    def prime(cls, n):
        return n | PRIME_DERIVATION_FLAG

    @classmethod
    def is_prime(cls, n):
        return (bool)(n & PRIME_DERIVATION_FLAG)

    @classmethod
    def _get_pubkey(cls, private_key):
        sk = SigningKey.from_string(private_key, curve=SECP256k1, hashfunc=hashlib.sha256)
        vk = sk.get_verifying_key().to_string()  # Uncompressed key
        vk = chr((ord(vk[63]) & 1) + 2) + vk[0:32]  # To compressed key
        return vk

    def get_address(self, n, address_type):
        pubkey = self.get_public_node(n).public_key
        address = public_key_to_bc_address(pubkey, address_type)
        return address

    def get_signer(self, n):
        return SigningKey.from_string(self.get_private_node(n).private_key, curve=SECP256k1, hashfunc=hashlib.sha256)

    def get_verifier(self, n):
        signer = self.get_signer(n)
        return signer.get_verifying_key()

    def get_public_node(self, n):
        node = self.get_private_node(n)
        node.private_key = ''
        return node

    def get_private_node(self, n):
        if not isinstance(n, list):
            raise Exception('Parameter must be a list')

        node = proto.HDNodeType()
        node.CopyFrom(self.node)
        
        for i in n:
            node.CopyFrom(self._get_subnode(node, i))
        
        return node

    @classmethod
    def _get_subnode(cls, node, i):
        # Child key derivation (CKD) algorithm of BIP32

        i_as_bytes = struct.pack(">L", i)

        if cls.is_prime(i):
            # Prime derivation
            data = '\0' + node.private_key + i_as_bytes

            I64 = hmac.HMAC(key=node.chain_code, msg=data, digestmod=hashlib.sha512).digest()
            I_left_as_exponent = string_to_number(I64[:32])

        else:
            # Public derivation
            data = node.public_key + i_as_bytes

            I64 = hmac.HMAC(key=node.chain_code, msg=data, digestmod=hashlib.sha512).digest()
            I_left_as_exponent = string_to_number(I64[:32])

        secexp = (I_left_as_exponent + string_to_number(node.private_key)) % SECP256k1.generator.order()

        node_out = proto.HDNodeType()
        node_out.version = node.version
        node_out.depth = node.depth + 1
        node_out.child_num = i
        node_out.chain_code = I64[32:]
        node_out.private_key = number_to_string(secexp, SECP256k1.generator.order())
        node_out.public_key = cls._get_pubkey(node_out.private_key)
        node_out.fingerprint = bip32_fingerprint(node.public_key)

        return node_out
