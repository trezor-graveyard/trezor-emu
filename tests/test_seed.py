import unittest
from trezor import tools

class TestSeed(unittest.TestCase):
    def test_generate(self):
        seed = tools.generate_seed(tools.STRENGTH_LOW, '')
        self.assertEqual(len(seed), 128 / 8)

        seed = tools.generate_seed(tools.STRENGTH_NORMAL, '')
        self.assertEqual(len(seed), 192 / 8)

        seed = tools.generate_seed(tools.STRENGTH_HIGH, '')
        self.assertEqual(len(seed), 256 / 8)

        seed1 = tools.generate_seed(tools.STRENGTH_HIGH, 'nazdar')
        seed2 = tools.generate_seed(tools.STRENGTH_HIGH, 'nazdar')
        self.assertNotEqual(seed1, seed2)

if __name__ == '__main__':
    unittest.main()
