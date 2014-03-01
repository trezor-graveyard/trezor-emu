import os
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

def bc_address_type(addr):
    return ord(b58decode(addr, 25)[0])

def bc_address_to_hash_160(addr):
    return b58decode(addr, 25)[1:21]

def compress_pubkey(public_key):
    if public_key[0] == '\x04':
        return chr((ord(public_key[64]) & 1) + 2) + public_key[1:33]
    raise Exception("Pubkey is already compressed")

def public_key_to_bc_address(public_key, address_type, compress=True):
    if public_key[0] == '\x04' and compress:
        public_key = compress_pubkey(public_key)

    h160 = hash_160(public_key)
    return hash_160_to_bc_address(h160, address_type)

def bip32_fingerprint(pubkey):
    return ecdsa.util.string_to_number(hash_160(pubkey)[:4])

def get_local_entropy():
    return os.urandom(32)

def generate_entropy(strength, internal_entropy, external_entropy):
    '''
    strength - length of produced seed. One of 128, 192, 256
    random - binary stream of random data from external HRNG
    '''
    if strength not in (128, 192, 256):
        raise Exception("Invalid strength")

    if not internal_entropy:
        raise Exception("Internal entropy is not provided")

    if len(internal_entropy) < 32:
        raise Exception("Internal entropy too short")

    if not external_entropy:
        raise Exception("External entropy is not provided")

    if len(external_entropy) < 32:
        raise Exception("External entropy too short")

    entropy = hashlib.sha256(internal_entropy + external_entropy).digest()
    entropy_stripped = entropy[:strength / 8]

    if len(entropy_stripped) * 8 != strength:
        raise Exception("Entropy length mismatch")

    return entropy_stripped

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


def monkeypatch_google_protobuf_text_format():
    # monkeypatching: text formatting of protobuf messages
    import google.protobuf.text_format
    import google.protobuf.descriptor

    _oldPrintFieldValue = google.protobuf.text_format.PrintFieldValue

    def _customPrintFieldValue(field, value, out, indent=0, as_utf8=False, as_one_line=False):
        if field.type == google.protobuf.descriptor.FieldDescriptor.TYPE_BYTES:
            _oldPrintFieldValue(field, 'hex(%s)' % binascii.hexlify(value), out, indent, as_utf8, as_one_line)
        else:
            _oldPrintFieldValue(field, value, out, indent, as_utf8, as_one_line)

    google.protobuf.text_format.PrintFieldValue = _customPrintFieldValue
