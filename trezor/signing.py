import ecdsa
import binascii
from hashlib import sha256, sha512
from ecdsa import curves, numbertheory, ellipticcurve, util
import pyaes
import hmac

# from bip32 import BIP32
import messages_pb2 as proto
import types_pb2 as proto_types
import tools

def encrypt_message(pubkey, message, display_only):
    pk = tools.public_key_to_point(pubkey)
    if not ecdsa.ecdsa.point_is_valid(ecdsa.ecdsa.generator_secp256k1, pk.x(), pk.y()):
        raise Exception('invalid pubkey')

    deter = hmac.new(message, pubkey, sha512).digest()
    secexp, iv = deter[:32], deter[32:48]

    ephemeral_exponent = ecdsa.util.number_to_string(ecdsa.util.string_to_number(secexp), ecdsa.ecdsa.generator_secp256k1.order())
    ephemeral = tools.EcKey(ephemeral_exponent)

    ecdh_key = (pk * ephemeral.privkey.secret_multiplier).x()
    ecdh_key = ('%064x' % ecdh_key).decode('hex')
    if display_only:
        ecdh_key += '\x00'
    key = sha512(ecdh_key).digest()
    key_e, key_m = key[:32], key[32:]

    assert len(message) % 16 == 0
    aes = pyaes.AESModeOfOperationCBC(key=key_e, iv=iv)
    ciphertext = ''.join([aes.encrypt(message[i:i+16]) for i in range(0, len(message), 16)])

    ephemeral_pubkey = ephemeral.get_public_key(compressed=True).decode('hex')
    encrypted = 'BIE1' + ephemeral_pubkey + iv + ciphertext
    mac = hmac.new(key_m, encrypted, sha256).digest()

    return encrypted + mac

def decrypt_message(bip32, address_n, encrypted):

    if len(encrypted) < 85:
        raise Exception('invalid ciphertext length')

    magic = encrypted[:4]
    ephemeral_pubkey = encrypted[4:37]
    iv = encrypted[37:53]
    ciphertext = encrypted[53:-32]
    mac = encrypted[-32:]

    if magic != 'BIE1':
        raise Exception('invalid ciphertext: invalid magic bytes')

    try:
        ephemeral_pubkey = tools.public_key_to_point(ephemeral_pubkey)
    except AssertionError, e:
        raise Exception('invalid ciphertext: invalid ephemeral pubkey')

    if not ecdsa.ecdsa.point_is_valid(ecdsa.ecdsa.generator_secp256k1, ephemeral_pubkey.x(), ephemeral_pubkey.y()):
        raise Exception('invalid ciphertext: invalid ephemeral pubkey')

    priv_node = bip32.get_private_node(address_n)
    priv_key = tools.EcKey(priv_node.private_key)
    ecdh_key = (ephemeral_pubkey * priv_key.privkey.secret_multiplier).x()
    ecdh_key = ('%064x' % ecdh_key).decode('hex')

    display_only = False
    key = sha512(ecdh_key).digest()
    key_e, key_m = key[:32], key[32:]
    if mac != hmac.new(key_m, encrypted[:-32], sha256).digest():
        # try again with display_only setting
        display_only = True
        ecdh_key += '\x00'
        key = sha512(ecdh_key).digest()
        key_e, key_m = key[:32], key[32:]
        if mac != hmac.new(key_m, encrypted[:-32], sha256).digest():
            # fail
            raise Exception('invalid ciphertext: invalid mac')

    assert len(ciphertext) % 16 == 0
    aes = pyaes.AESModeOfOperationCBC(key=key_e, iv=iv)
    decrypted = ''.join([aes.decrypt(ciphertext[i:i+16]) for i in range(0, len(ciphertext), 16)])
    return (decrypted, display_only)

def message_magic(message):
    magic = "\x18Bitcoin Signed Message:\n" + chr(len(message)) + message
    return magic

def sign_message(bip32, coin, addr_n, message):
    signer = bip32.get_signer(addr_n)
    address = bip32.get_address(coin, addr_n)

    magic = message_magic(message)
    signature = signer.sign_deterministic(sha256(magic).digest(), hashfunc=sha256)

    for i in range(4):
        sig = chr(27 + i + 4) + signature
        try:
            verify_message(address, sig, message)
            return (address, sig)
        except:
            pass

    raise Exception("Cannot sign message")

def verify_message(address, signature, message):
    """ See http://www.secg.org/download/aid-780/sec1-v2.pdf for the math """
    curve = ecdsa.curves.SECP256k1.curve  # curve_secp256k1
    G = ecdsa.curves.SECP256k1.generator
    order = G.order()
    # extract r,s from signature
    if len(signature) != 65: raise BaseException("Wrong signature")
    r, s = util.sigdecode_string(signature[1:], order)
    nV = ord(signature[0])
    if nV < 27 or nV >= 35:
        raise BaseException("Bad encoding")
    if nV >= 31:
        compressed = True
        nV -= 4
    else:
        compressed = False

    recid = nV - 27
    # 1.1
    x = r + (recid / 2) * order
    # 1.3
    y = tools.point_y_from_x(x, recid % 2 > 0)
    # 1.4 the constructor checks that nR is at infinity
    R = ellipticcurve.Point(curve, x, y, order)
    # 1.5 compute e from message:
    h = sha256(sha256(message_magic(message)).digest()).digest()
    e = util.string_to_number(h)
    minus_e = -e % order
    # 1.6 compute Q = r^-1 (sR - eG)
    inv_r = numbertheory.inverse_mod(r, order)
    Q = inv_r * (s * R + minus_e * G)
    public_key = ecdsa.VerifyingKey.from_public_point(Q, curve=ecdsa.curves.SECP256k1)
    # check that Q is the public key
    public_key.verify_digest(signature[1:], h, sigdecode=ecdsa.util.sigdecode_string)

    if address:
        address_type = int(binascii.hexlify(tools.b58decode(address, None)[0]), 16)
        addr = tools.public_key_to_bc_address('\x04' + public_key.to_string(), address_type, compress=compressed)
        if address != addr:
            raise Exception("Invalid signature")

'''
def raw_tx_header(inputs_count):
    s = ''
    s += '\x01\x00\x00\x00'  # version
    s += tools.var_int(inputs_count)  # number of inputs
    return s


def raw_tx_input(inp, script_sig):
    s = ''
    s += inp.prev_hash[::-1]  # prev hash
    s += struct.pack('<L', inp.prev_index)  # prev index
    if script_sig != '':
        s += tools.var_int(len(script_sig))  # script length
        s += script_sig  # script sig
    s += "\xff\xff\xff\xff"  # sequence
    return s


def raw_tx_middle(outputs_count):
    s = ''
    s += tools.var_int(outputs_count)  # number of outputs
    return s


def raw_tx_output(out):
    s = ''
    s += struct.pack('<Q', out.amount)  # amount

    if out.script_type == proto.PAYTOADDRESS:
        script = '\x76\xa9'  # op_dup, op_hash_160
        script += '\x14'  # push 0x14 bytes
        script += tools.bc_address_to_hash_160(out.address)
        script += '\x88\xac'  # op_equalverify, op_checksig

    elif out.script_type == proto.PAYTOSCRIPTHASH:
        raise Exception("P2SH not implemented yet!")

    else:
        raise Exception("Unknown script type!")

    s += tools.var_int(len(script))  # script length
    s += script  # script
    return s


def raw_tx_footer(for_sign):
    s = ''
    s += '\x00\x00\x00\x00'  # lock time
    if for_sign:
        s += '\x01\x00\x00\x00'  # hash type
    return s

# https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
def raw_tx(inputs, outputs, for_sig):
    s = ''
    s += raw_tx_header(len(inputs))

    for i in range(len(inputs)):
        inp = inputs[i]

        if for_sig == i:
            script_sig = inp.script_sig
        else:
            script_sig = ''

        s += raw_tx_input(inp, script_sig)

    s += raw_tx_middle(len(outputs))

    for output in outputs:
        s += raw_tx_output(output)

    s += raw_tx_footer()
    return s
'''

def sign_input(bip32, addr_n, tx_hash):
    pk = bip32.get_private_key(addr_n)
    private_key = ecdsa.SigningKey.from_string(pk, curve=curves.SECP256k1)
    sig = private_key.sign_digest_deterministic(tx_hash, hashfunc=sha256, sigencode=ecdsa.util.sigencode_der_canonize)
    pubkey = private_key.get_verifying_key().to_string()
    return (pubkey, sig)

'''
def sign_inputs(algo, secexp, inputs, outputs):
    # This is reworked but backward compatible (non-streaming) method from Electrum
    signatures = []
    for i in range(len(inputs)):
        addr_n = inputs[i].address_n
        print addr_n

        tx = raw_tx(inputs, outputs, for_sig=i)
        tx_hash = tools.Hash(tx)
        signatures.append(sign_input(algo, secexp, addr_n, tx_hash))
    return signatures
'''
