import ecdsa
import struct
import hashlib
import binascii

Hash = lambda x: hashlib.sha256(hashlib.sha256(x).digest()).digest()
#Hash_obj = lambda x: hashlib.sha256(x.digest()).digest()

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)


def b58encode(v):
    """ encode v, which is a string of bytes, to base58."""

    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256 ** i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0':
            nPad += 1
        else:
            break

    return (__b58chars[0] * nPad) + result


def b58decode(v, length):
    """ decode v into a string of len bytes."""
    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += __b58chars.find(c) * (__b58base ** i)

    result = ''
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = chr(mod) + result
        long_value = div
    result = chr(long_value) + result

    nPad = 0
    for c in v:
        if c == __b58chars[0]:
            nPad += 1
        else:
            break

    result = chr(0) * nPad + result
    if length is not None and len(result) != length:
        return None

    return result


def EncodeBase58Check(vchIn):
    # Used only for debug prints of private keys
    return b58encode(vchIn + Hash(vchIn)[0:4])


'''
def SecretToASecret(secret):
    # Used only for debug prints of private keys
    vchIn = chr(addrtype + 128) + secret
    return EncodeBase58Check(vchIn)
'''

def hash_160(public_key):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
    return md.digest()

def hash_160_to_bc_address(h160, address_type):
    vh160 = chr(address_type) + h160
    h = Hash(vh160)
    addr = vh160 + h[0:4]
    return b58encode(addr)

def bc_address_to_hash_160(addr):
    return b58decode(addr, 25)[1:21]

def public_key_to_bc_address(public_key, address_type):
    if public_key[0] == '\x04':
        # compressed form
        public_key = chr((ord(public_key[64]) & 1) + 2) + public_key[1:33]

    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160, address_type)

STRENGTH_LOW = 0
STRENGTH_NORMAL = 1
STRENGTH_HIGH = 2

def generate_seed(strength, random):
    '''
    strength - length of produced seed. One of STRENGTH_LOW, STRENGTH_NORMAL, STRENGTH_HIGH
    random - binary stream of random data from external HRNG
    '''

    strength = int(strength)
    if strength < STRENGTH_LOW or strength > STRENGTH_HIGH:
        raise Exception("Invalid seed strength")

    # Generate random stream using internal HRNG
    seed = binascii.unhexlify("%064x" % ecdsa.util.randrange(pow(2, 256)))

    # Apply hash function on top of concatenated entropy
    seed = hashlib.sha256(seed + random).digest()

    return seed[:(128 + 64 * strength) / 8]

'''
def var_int(i):
    if i < 0xfd:
        return struct.pack('<B', i)
    elif i <= 0xffff:
        return '\xfd' + struct.pack('<H', i)
    elif i <= 0xffffffff:
        return '\xfe' + struct.pack('<Q', i)
    else:
        return '\xff' + struct.pack('<Q', i)
'''
