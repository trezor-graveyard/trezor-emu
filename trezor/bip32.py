'''
    TODO: Refactor this using package bip32utils
'''
# import pycoin.wallet as pywallet
import ecdsa
import struct
from binascii import hexlify, unhexlify
import hashlib
import hmac
import types_pb2 as types
from tools import public_key_to_bc_address, bip32_fingerprint
from ecdsa.curves import SECP256k1
from ecdsa.keys import SigningKey, VerifyingKey
from ecdsa.util import string_to_number, number_to_string
from ecdsa.ellipticcurve import Point, INFINITY

PRIME_DERIVATION_FLAG = 0x80000000

def point_to_pubkey(point):
    order = SECP256k1.order
    x_str = number_to_string(point.x(), order)
    y_str = number_to_string(point.y(), order)
    vk = x_str + y_str
    return chr((ord(vk[63]) & 1) + 2) + vk[0:32]  # To compressed key

def sec_to_public_pair(pubkey):
    """Convert a public key in sec binary format to a public pair."""
    x = string_to_number(pubkey[1:33])
    sec0 = pubkey[:1]
    if sec0 not in (b'\2', b'\3'):
        raise Exception("Compressed pubkey expected")

    def public_pair_for_x(generator, x, is_even):
        curve = generator.curve()
        p = curve.p()
        alpha = (pow(x, 3, p) + curve.a() * x + curve.b()) % p
        beta = ecdsa.numbertheory.square_root_mod_prime(alpha, p)
        if is_even == bool(beta & 1):
            return (x, p - beta)
        return (x, beta)

    return public_pair_for_x(ecdsa.ecdsa.generator_secp256k1, x, is_even=(sec0 == b'\2'))

def public_ckd(public_node, n):
    if not isinstance(n, list):
        raise Exception('Parameter must be a list')

    node = types.HDNodeType()
    node.CopyFrom(public_node)

    for i in n:
        node.CopyFrom(get_subnode(node, i))

    return node

def get_subnode(node, i):
    # Public Child key derivation (CKD) algorithm of BIP32
    i_as_bytes = struct.pack(">L", i)

    if BIP32.is_prime(i):
        raise Exception("Prime derivation not supported")

    # Public derivation
    data = node.public_key + i_as_bytes

    I64 = hmac.HMAC(key=node.chain_code, msg=data, digestmod=hashlib.sha512).digest()
    I_left_as_exponent = string_to_number(I64[:32])

    node_out = types.HDNodeType()
    node_out.depth = node.depth + 1
    node_out.child_num = i
    node_out.chain_code = I64[32:]
    node_out.fingerprint = bip32_fingerprint(node.public_key)

    # BIP32 magic converts old public key to new public point
    x, y = sec_to_public_pair(node.public_key)
    point = I_left_as_exponent * SECP256k1.generator + \
            Point(SECP256k1.curve, x, y, SECP256k1.order)

    if point == INFINITY:
        raise Exception("Point cannot be INFINITY")

    # Convert public point to compressed public key
    node_out.public_key = point_to_pubkey(point)

    return node_out

class BIP32(object):
    def __init__(self, node):
        if node.public_key == '':
            # Calculate pubkey if missing (public_key is optional field)
            node.public_key = self._get_pubkey(node.private_key)

        self.node = node

    @classmethod
    def get_node_from_seed(cls, seed):
        I64 = hmac.HMAC(key=b"Bitcoin seed", msg=seed, digestmod=hashlib.sha512).digest()

        node = types.HDNodeType()
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

    def get_address(self, coin, n):
        pubkey = self.get_public_node(n).public_key
        address = public_key_to_bc_address(pubkey, coin.address_type)
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

        node = types.HDNodeType()
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

        else:
            # Public derivation
            data = node.public_key + i_as_bytes
            I64 = hmac.HMAC(key=node.chain_code, msg=data, digestmod=hashlib.sha512).digest()

        I_left_as_exponent = string_to_number(I64[:32])
        secexp = (I_left_as_exponent + string_to_number(node.private_key)) % SECP256k1.order

        if I_left_as_exponent >= SECP256k1.order:
            raise Exception("Il cannot be bigger than order")
        if secexp == 0:
            raise Exception("secexp cannot be zero")

        node_out = types.HDNodeType()
        node_out.depth = node.depth + 1
        node_out.child_num = i
        node_out.chain_code = I64[32:]
        node_out.private_key = number_to_string(secexp, SECP256k1.order)
        node_out.public_key = cls._get_pubkey(node_out.private_key)
        node_out.fingerprint = bip32_fingerprint(node.public_key)

        return node_out
