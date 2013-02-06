import unittest

import sys
sys.path.append('../src')

import mnemonic

mnem = 'beyond neighbor scratch swirl embarrass doll cause also stick softly physical nice'.split(' ')
seed = '13ee91e3c7e49dd620a5dd5a51d9d766'

class TestMnemonic(unittest.TestCase):
    def test_decode(self):
        self.assertEqual(mnemonic.decode(mnem), seed)

    def test_encode(self):
        self.assertEqual(mnemonic.encode(seed), mnem)

if __name__ == '__main__':
    unittest.main()
