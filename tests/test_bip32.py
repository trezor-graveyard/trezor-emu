import unittest

import struct
from hashlib import sha256
from binascii import hexlify, unhexlify
from trezor.bip32 import BIP32
from ecdsa.keys import SigningKey, VerifyingKey
from ecdsa.curves import SECP256k1
from ecdsa.rfc6979 import generate_k
from ecdsa.util import string_to_number
import pycoin.wallet as pywallet

# from trezor import tools

class TestBIP32(unittest.TestCase):
    def test_signing(self):
        seed = unhexlify('c882685a2859016f26ea3b95d3d06929')  # tools.generate_seed(tools.STRENGTH_LOW, '')
        data = 'nazdar bazar'
        hsh = sha256(data).digest()
        
        # Generate secexp
        xprv = BIP32.get_xprv_from_seed(seed)
        bip32 = BIP32(xprv)

        # Get signing key and sign some data
        signing = bip32._get_master_private_key()
        signature = signing.sign_digest_deterministic(hsh, sha256)

        # Transform secexp into master public key
        master_public_key = bip32.get_master_public_key()

        # Load verifying class from master public key
        verifying = VerifyingKey.from_string(unhexlify(master_public_key), SECP256k1)

        # Check that signature is valid using master public key
        self.assertTrue(verifying.verify(signature, data, sha256))

    def test_vector_bip32(self):
        seed = unhexlify('000102030405060708090a0b0c0d0e0f')
        xprv = BIP32.get_xprv_from_seed(seed)
        bip32 = BIP32(xprv)

        self.assertEqual(bip32._secexp(), int('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35', 16))

        print "test_vector_bip32: TODO"
        # master_public = bip32.get_master_public_key()
        # print master_public

    def test_vector_pycoin(self):
        wallet = pywallet.Wallet.from_master_secret(unhexlify('000102030405060708090a0b0c0d0e0f'))
        self.assertEqual(hexlify(wallet.secret_exponent_bytes), 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35')

        master_public = wallet.public_copy()
        self.assertEqual(master_public.wallet_key(), 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')
        self.assertEqual(master_public.bitcoin_address(), '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma')

        self.assertEqual(wallet.wallet_key(as_private=False), 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8')
        self.assertEqual(wallet.wallet_key(as_private=True), u'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')
        self.assertEqual(wallet.bitcoin_address(), '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma')

        wallet = wallet.subkey(is_prime=True, as_private=True)

        self.assertEqual(wallet.wallet_key(as_private=False), 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw')
        self.assertEqual(wallet.wallet_key(as_private=True), u'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7')
        self.assertEqual(wallet.bitcoin_address(), '19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh')
    
    def test_seed_to_xprv(self):
        # Transform seed to xprv object
        seed = unhexlify('000102030405060708090a0b0c0d0e0f')
        xprv = BIP32.get_xprv_from_seed(seed)

        # Load xprv object to pycoin wallet
        xprv1 = pywallet.Wallet(chain_code=xprv.chain_code,
                               secret_exponent_bytes=xprv.private_key,
                               parent_fingerprint=struct.pack('I', xprv.fingerprint),
                               depth=xprv.depth,
                               child_number=xprv.child_num,
                               is_private=True,
                               is_test=False)

        # Load the same seed to pycoin wallet directly
        xprv2 = pywallet.Wallet.from_master_secret(seed)

        # ...and compare them
        self.assertEqual(xprv1.wallet_key(as_private=True), xprv2.wallet_key(as_private=True))

    ''
    def test_pycoin_2(self):
        import pycoin.wallet as pywallet

        wallet = pywallet.Wallet.from_master_secret(unhexlify('000102030405060708090a0b0c0d0e0f'))

        x1 = wallet.subkey_for_path("0/1/1")
        x2 = wallet.subkey_for_path("0'/1'/1'")

        # print x1.wallet_key(as_private=True)

        print '----'
        print x1.wallet_key(as_private=True)
        print x2.wallet_key(as_private=True)
        print x1.wallet_key(as_private=False)
        print x2.wallet_key(as_private=False)
        print '----'

        print x1.wif(compressed=False)
        print x2.wif(compressed=False)

    def test_subkey_simple(self):
        seed = unhexlify('000102030405060708090a0b0c0d0e0f')
        bip32 = BIP32.from_seed(seed)
        secexp1 = string_to_number(BIP32._get_subkey(bip32.xprv, 0).private_key)

        wallet = pywallet.Wallet.from_master_secret(seed)
        secexp2 = wallet.subkey(0, is_prime=True, as_private=True).secret_exponent

        self.assertEqual(secexp1, secexp2)
    
    def test_subkey_path(self):
        seed = unhexlify('000102030405060708090a0b0c0d0e0f')
        path = [1, 1, 2]

        bip32 = BIP32.from_seed(seed)
        private_key = bip32.get_private_key(path)
        secexp1 = string_to_number(private_key)

        path_string = '/'.join([ "%d'" % p for p in path])
        wallet = pywallet.Wallet.from_master_secret(seed)
        secexp2 = wallet.subkey_for_path(path_string)

        self.assertEqual(secexp1, secexp2.secret_exponent)

if __name__ == '__main__':
    unittest.main()
