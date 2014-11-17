import ecdsa
import binascii
from hashlib import sha256, sha512
from ecdsa import curves, numbertheory, ellipticcurve, util
import pyaes
import hmac
from pbkdf2 import PBKDF2

import messages_pb2 as proto
import types_pb2 as proto_types
import tools

def message_magic(message):
    magic = chr(24) + "Bitcoin Signed Message:\n" + tools.ser_length(len(message)) + message
    return magic

###### sign/verify ######

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

    address_type = int(binascii.hexlify(tools.b58decode(address, None)[0]), 16)
    addr = tools.public_key_to_bc_address('\x04' + public_key.to_string(), address_type, compress=compressed)
    if address != addr:
        raise Exception("Invalid signature")

###### ECIES : http://memwallet.info/btcmssgs.html ######

def encrypt_message(pubkey, message, display_only, bip32, coin, address_n):

    if len(address_n) > 0:
        priv_node = bip32.get_private_node(address_n)
        priv_key = tools.EcKey(priv_node.private_key)
        signing = True
    else:
        signing = False

    if signing:
        if display_only:
            payload = chr(0x80 + 1)
        else:
            payload = chr(1)
        address, signature = sign_message(bip32, coin, address_n, message)
        address_bin = tools.bc_address_decode(address)[:21]
        payload += tools.ser_length(len(message)) + message + address_bin + signature
    else:
        if display_only:
            payload = chr(0x80)
        else:
            payload = chr(0)
        payload += tools.ser_length(len(message)) + message

    nonce = tools.get_local_entropy()
    nonce_key = tools.EcKey(nonce)
    nonce_pub = binascii.unhexlify(nonce_key.get_public_key(True))
    dest_pub = tools.public_key_to_point(pubkey)
    shared_secret_point = dest_pub * nonce_key.privkey.secret_multiplier
    shared_secret = tools.point_to_public_key(shared_secret_point, True)
    keying_bytes = PBKDF2(shared_secret, "Bitcoin Secure Message" + nonce_pub, iterations=2048, macmodule=hmac, digestmodule=sha256).read(80)
    aes_key = keying_bytes[:32]
    hmac_key = keying_bytes[32:64]
    aes_iv = keying_bytes[64:]
    encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCFB(key=aes_key, iv=aes_iv, segment_size=16))
    payload = encrypter.feed(payload) + encrypter.feed()
    msg_hmac = hmac.HMAC(key=hmac_key, msg=payload, digestmod=sha256).digest()[:8]
    return (nonce_pub, payload, msg_hmac)

def decrypt_message(bip32, address_n, nonce_pub, payload, msg_hmac):

    priv_node = bip32.get_private_node(address_n)
    priv_key = tools.EcKey(priv_node.private_key)

    shared_secret_point = tools.public_key_to_point(nonce_pub) * priv_key.privkey.secret_multiplier
    shared_secret = tools.point_to_public_key(shared_secret_point, True)
    keying_bytes = PBKDF2(shared_secret, "Bitcoin Secure Message" + nonce_pub, iterations=2048, macmodule=hmac, digestmodule=sha256).read(80)
    aes_key = keying_bytes[:32]
    hmac_key = keying_bytes[32:64]
    aes_iv = keying_bytes[64:]
    msg_hmac_new = hmac.HMAC(key=hmac_key, msg=payload, digestmod=sha256).digest()[:8]
    if msg_hmac_new != msg_hmac:
        raise Exception('Message_HMAC does not match')
    decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCFB(key=aes_key, iv=aes_iv, segment_size=16))
    payload = decrypter.feed(payload) + decrypter.feed()
    if not ord(payload[0]) in [0x00, 0x01, 0x80, 0x81]:
        raise Exception('AES decryption failed')
    signing = (ord(payload[0]) & 0x01) > 0
    display_only = (ord(payload[0]) & 0x80) > 0
    if signing:
        message = tools.deser_length_string(payload[1:-(21+65)])
        address_bin = payload[-(21+65):-65]
        signature = payload[-65:]
        address = tools.hash_160_to_bc_address(address_bin[1:], ord(address_bin[0]))
        verify_message(address, signature, message)
    else:
        message = tools.deser_length_string(payload[1:])
        address = None
    return (message, address, display_only)
