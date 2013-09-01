import unittest
from trezor import mnemonic

mnem = 'beyond neighbor scratch swirl embarrass doll cause also stick softly physical nice'.split(' ')
seed = '13ee91e3c7e49dd620a5dd5a51d9d766'

# This code is obsolete, because we're moving to BIP39

class TestMnemonic(unittest.TestCase):
    def test_decode(self):
        self.assertEqual(mnemonic.decode(mnem), seed)

    def test_encode(self):
        self.assertEqual(mnemonic.encode(seed), mnem)

    def test_suggest(self):
        self.assertEqual(mnemonic.suggest('st', -1), None)
        self.assertEqual(mnemonic.suggest('st', 0), ('sta', 'stab'))
        self.assertEqual(mnemonic.suggest('st', 1), ('ste', 'steady'))
        self.assertEqual(mnemonic.suggest('st', 2), ('sti', 'stick'))
        self.assertEqual(mnemonic.suggest('st', 3), ('sto', 'stock'))
        self.assertEqual(mnemonic.suggest('st', 4), ('str', 'straight'))
        self.assertEqual(mnemonic.suggest('st', 5), ('stu', 'stubborn'))
        self.assertEqual(mnemonic.suggest('st', 6), ('sty', 'style'))
        self.assertEqual(mnemonic.suggest('st', 7), None)

if __name__ == '__main__':
    unittest.main()
