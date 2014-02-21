import unittest
import sys
sys.path.append('../')

import struct
from hashlib import sha256
from binascii import hexlify, unhexlify
from trezor.bip32 import BIP32
from ecdsa.util import string_to_number
from trezor.coindef import BTC
#import pycoin.wallet as pywallet

# from trezor import tools

class TestBIP32(unittest.TestCase):
    def test_signing(self):
        seed = unhexlify('c882685a2859016f26ea3b95d3d06929')  # tools.generate_seed(tools.STRENGTH_LOW, '')
        data = 'nazdar bazar'
        hsh = sha256(data).digest()
        
        # Generate secexp
        node = BIP32.get_node_from_seed(seed)
        bip32 = BIP32(node)

        # Get signing key and sign some data
        signer = bip32.get_signer([])
        signature = signer.sign_digest_deterministic(hsh, sha256)

        # Transform secexp into master public key
        verifying = bip32.get_verifier([])

        # Check that signature is valid using master public key
        self.assertTrue(verifying.verify(signature, data, sha256))

    def test_vector_bip32(self):
        import pycoin.wallet as pywallet

        seed = unhexlify('000102030405060708090a0b0c0d0e0f')
        # seed = unhexlify('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542')
        bip32 = BIP32.from_seed(seed)

        self.assertEqual(string_to_number(bip32.node.private_key), int('e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35', 16))

        self.assertEqual(bip32.get_address(BTC, []), '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma')
        self.assertEqual(bip32.get_address(BTC, [bip32.prime(0)]), '19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh')

        seed = unhexlify('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542')
        bip32 = BIP32.from_seed(seed)
        self.assertEqual(bip32.get_address(BTC, [0]), '19EuDJdgfRkwCmRzbzVBHZWQG9QNWhftbZ')
        self.assertEqual(bip32.get_address(BTC, [0, bip32.prime(2147483647)]), '1Lke9bXGhn5VPrBuXgN12uGUphrttUErmk')

        pw = pywallet.Wallet(chain_code=bip32.node.chain_code,
                       secret_exponent_bytes=bip32.node.private_key,
                       parent_fingerprint=struct.pack('I', bip32.node.fingerprint),
                       depth=bip32.node.depth,
                       child_number=bip32.node.child_num,
                       is_private=True,
                       is_test=False)

        privkey1 = hexlify(pw.subkey(0, is_prime=True, as_private=True).secret_exponent_bytes)
        privkey2 = hexlify(bip32._get_subnode(bip32.node, bip32.prime(0)).private_key)
        self.assertEqual(privkey1, privkey2)

    def test_vector_pycoin(self):
        import pycoin.wallet as pywallet
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
    
    def test_seed_to_node(self):
        import pycoin.wallet as pywallet

        # Transform seed to xprv object
        seed = unhexlify('000102030405060708090a0b0c0d0e0f')
        node = BIP32.get_node_from_seed(seed)

        # Load xprv object to pycoin wallet
        node1 = pywallet.Wallet(chain_code=node.chain_code,
                               secret_exponent_bytes=node.private_key,
                               parent_fingerprint=struct.pack('I', node.fingerprint),
                               depth=node.depth,
                               child_number=node.child_num,
                               is_private=True,
                               is_test=False)

        # Load the same seed to pycoin wallet directly
        node2 = pywallet.Wallet.from_master_secret(seed)

        # ...and compare them
        self.assertEqual(node1.wallet_key(as_private=True), node2.wallet_key(as_private=True))

    def test_subkey_simple(self):
        import pycoin.wallet as pywallet
        seed = unhexlify('000102030405060708090a0b0c0d0e0f')
        bip32 = BIP32.from_seed(seed)
        secexp1 = string_to_number(BIP32._get_subnode(bip32.node, 0).private_key)

        wallet = pywallet.Wallet.from_master_secret(seed)
        secexp2 = wallet.subkey(0, is_prime=False, as_private=True).secret_exponent

        self.assertEqual(secexp1, secexp2)
    
    def test_subkey_path(self):
        import pycoin.wallet as pywallet
        seed = unhexlify('000102030405060708090a0b0c0d0e0f')
        path = [1, 1, 2]

        bip32 = BIP32.from_seed(seed)
        private_key = bip32.get_private_node(path).private_key
        secexp1 = string_to_number(private_key)

        path_string = '/'.join([ "%d" % p for p in path])
        wallet = pywallet.Wallet.from_master_secret(seed)
        secexp2 = wallet.subkey_for_path(path_string)

        self.assertEqual(secexp1, secexp2.secret_exponent)

    def test_address(self):
        import pycoin.wallet as pywallet
        seed = unhexlify('000102030405060708090a0b0c0d0e0f')

        bip32 = BIP32.from_seed(seed)

        self.assertEqual(bip32.get_address(BTC, [bip32.prime(0), 1, bip32.prime(2)]), '1NjxqbA9aZWnh17q1UW3rB4EPu79wDXj7x')
        self.assertEqual(bip32.get_address(BTC, [bip32.prime(0), 1, bip32.prime(2), 2]), '1LjmJcdPnDHhNTUgrWyhLGnRDKxQjoxAgt')
        '''
        path_string = '-0/1/2'
        wallet = pywallet.Wallet.from_master_secret(seed)
        wallet2 = wallet.subkey_for_path(path_string)
        address2 = wallet2.bitcoin_address(True)
        print address2
        # self.assertEqual(address1, address2)
        '''

if __name__ == '__main__':
    unittest.main()
