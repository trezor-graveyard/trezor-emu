import struct
import trezor_pb2 as proto
import urllib2
import json
import binascii
from hashlib import sha256
from StringIO import StringIO

def ser_length(l):
    if l < 253:
        return chr(l)
    elif l < 0x10000:
        return chr(253) + struct.pack("<H", l)
    elif l < 0x100000000L:
        return chr(254) + struct.pack("<I", l)
    else:
        return chr(255) + struct.pack("<Q", l)

def ser_uint256(u):
    rs = ""
    for _ in xrange(8):
        rs += struct.pack("<I", u & 0xFFFFFFFFL)
        u >>= 32
    return rs

class StreamTransaction(object):
    def __init__(self, inputs_len, outputs_len, version, lock_time):
        self.inputs_len = inputs_len
        self.outputs_len = outputs_len

        self.version = version
        self.lock_time = lock_time

        self.have_inputs = 0
        self.have_outputs = 0

    def _serialize_header(self):
        r = struct.pack("<i", self.version)
        r += ser_length(self.inputs_len)
        return r

    def serialize_input(self, inp):
        if self.have_inputs >= self.inputs_len:
            raise Exception("Already have all inputs")

        r = ''

        if self.have_inputs == 0:
            r += self._serialize_header()

        r += ser_uint256(int(binascii.hexlify(inp.prev_hash), 16))
        r += struct.pack("<I", inp.prev_index)
        r += ser_length(len(inp.script_sig))
        r += inp.script_sig
        r += struct.pack("<I", inp.sequence)

        self.have_inputs += 1
        return r

    def _serialize_middle(self):
        return ser_length(self.outputs_len)

    def serialize_output(self, output):
        if self.have_outputs >= self.outputs_len:
            raise Exception("Already have all outputs")

        r = ''
        if self.have_outputs == 0:
            # First output, let's serialize tx middle
            r += self._serialize_middle()

        r += struct.pack("<q", output.amount)
        r += ser_length(len(output.script_pubkey))
        r += output.script_pubkey

        self.have_outputs += 1

        if self.have_outputs == self.outputs_len:
            r += self._serialize_footer()
        return r

    def _serialize_footer(self):
        return struct.pack("<I", self.lock_time)

    @classmethod
    def serialize(cls, tx):
        # Demonstration of tx serialization in streamed fashion
        t = cls(len(tx.inputs), len(tx.outputs), tx.version, tx.lock_time)

        r = ''
        for i in tx.inputs:
            r += t.serialize_input(i)

        for o in tx.outputs:
            r += t.serialize_output(o)

        return r

class StreamTransactionHash(StreamTransaction):
    def __init__(self, inputs_len, outputs_len, version, lock_time):
        super(StreamTransactionHash, self).__init__(inputs_len, outputs_len, version, lock_time)

        self.hash = sha256('')

    def serialize_input(self, inp):
        r = super(StreamTransactionHash, self).serialize_input(inp)
        self.hash.update(r)
        return r

    def serialize_output(self, output):
        r = super(StreamTransactionHash, self).serialize_output(output)
        self.hash.update(r)
        return r

    def calc_txid(self):
        return sha256(self.hash.digest()).digest()[::-1]

    @classmethod
    def calculate(cls, tx):
        # Demonstration of hash calculation in streamed fashion
        th = cls(len(tx.inputs), len(tx.outputs), tx.version, tx.lock_time)

        for i in tx.inputs:
            th.serialize_input(i)

        for o in tx.outputs:
            th.serialize_output(o)

        return th.calc_txid()

if __name__ == '__main__':
    pass
'''
Test vectors:

Transaction with most inputs:
http://blockexplorer.com/t/55mvNHTqsH

Transaction with most outputs:
http://blockexplorer.com/t/25Q3XTsoe3

Address with most transactions:
http://blockexplorer.com/a/2isMCwqPQ2


txid 674b23e6c4c2f65e09eb406a58211e535f453cae6616628d9285ea11d195fafe

serialized
01000000021a98b9d7ff3357e88ec2d99fbcbd798193993ac69794e897d34e31d1005144be010000008b483045022100bf0f1731cb0a727073e9e3384a49a9fe51f47c175b48feea9a1058a584f10aeb02204af9e062024b5802395fc7830670abed482669f3bfb89bc2997214ab2540d39a014104b87b17fc6cd46beb56fae3126ab977474b1e024526347aae5967ea927c8d86c317ad388c30e5b4cc5bd5e7decbd78de63ed22a180d2505e5a225ce4135ecf776ffffffff3cf3a33516914d5d62442476cbaf321ed9c4d8b30681170a6b904769df7f656f010000008b483045022100dd94c5562339344b0a8c9fd0e211f1b2768e8f92ed850e2a8ca657e5457f8472022052ba93e87514baf5de1add94f3bf2db6ef343507386eef6582a5b935f82612a00141042a686611c8142e3b2c2ab592b88a3f668d47fbf7890d936902a30b17fbb9fc24d491bde8f77959c3020a60dfd602acf74c5ede7e4d2420bce41fbe041c9a42a3ffffffff02f0c51700000000001976a91463b7e6b62bfd212342acd143d8d465990740cee388ac44bf0100000000001976a91406c06f6d934aad5a21906e3e1ebbff6b0ecedd8488ac00000000

CTransaction(nVersion=1
    vin=
        [CTxIn(prevout=COutPoint(hash=be445100d1314ed397e89497c63a99938179bdbc9fd9c28ee85733ffd7b9981a n=1)
            scriptSig=483045022100bf0f1731cb0a727073e9e3384a49a9fe51f47c175b48feea9a1058a584f10aeb02204af9e062024b5802395fc7830670abed482669f3bfb89bc2997214ab2540d39a014104b87b17fc6cd46beb56fae3126ab977474b1e024526347aae5967ea927c8d86c317ad388c30e5b4cc5bd5e7decbd78de63ed22a180d2505e5a225ce4135ecf776
            nSequence=0),
         CTxIn(prevout=COutPoint(hash=6f657fdf6947906b0a178106b3d8c4d91e32afcb762444625d4d911635a3f33c n=1)
             scriptSig=483045022100dd94c5562339344b0a8c9fd0e211f1b2768e8f92ed850e2a8ca657e5457f8472022052ba93e87514baf5de1add94f3bf2db6ef343507386eef6582a5b935f82612a00141042a686611c8142e3b2c2ab592b88a3f668d47fbf7890d936902a30b17fbb9fc24d491bde8f77959c3020a60dfd602acf74c5ede7e4d2420bce41fbe041c9a42a3
             nSequence=0)]
    vout=[
        CTxOut(nValue=0.01558000 scriptPubKey=76a91463b7e6b62bfd212342acd143d8d465990740cee388ac),
        CTxOut(nValue=0.00114500 scriptPubKey=76a91406c06f6d934aad5a21906e3e1ebbff6b0ecedd8488ac)]
    nLockTime=0)

{
  "hash":"674b23e6c4c2f65e09eb406a58211e535f453cae6616628d9285ea11d195fafe",
  "ver":1,
  "lock_time":0,
  "in":[
    {
      "prev_out":{
        "hash":"be445100d1314ed397e89497c63a99938179bdbc9fd9c28ee85733ffd7b9981a",
        "n":1
      },
      "scriptSig":"3045022100bf0f1731cb0a727073e9e3384a49a9fe51f47c175b48feea9a1058a584f10aeb02204af9e062024b5802395fc7830670abed482669f3bfb89bc2997214ab2540d39a01 04b87b17fc6cd46beb56fae3126ab977474b1e024526347aae5967ea927c8d86c317ad388c30e5b4cc5bd5e7decbd78de63ed22a180d2505e5a225ce4135ecf776"
    },
    {
      "prev_out":{
        "hash":"6f657fdf6947906b0a178106b3d8c4d91e32afcb762444625d4d911635a3f33c",
        "n":1
      },
      "scriptSig":"3045022100dd94c5562339344b0a8c9fd0e211f1b2768e8f92ed850e2a8ca657e5457f8472022052ba93e87514baf5de1add94f3bf2db6ef343507386eef6582a5b935f82612a001 042a686611c8142e3b2c2ab592b88a3f668d47fbf7890d936902a30b17fbb9fc24d491bde8f77959c3020a60dfd602acf74c5ede7e4d2420bce41fbe041c9a42a3"
    }
  ],
  "out":[
    {
      "value":"0.01558000",
      "scriptPubKey":"OP_DUP OP_HASH160 63b7e6b62bfd212342acd143d8d465990740cee3 OP_EQUALVERIFY OP_CHECKSIG"
    },
    {
      "value":"0.00114500",
      "scriptPubKey":"OP_DUP OP_HASH160 06c06f6d934aad5a21906e3e1ebbff6b0ecedd84 OP_EQUALVERIFY OP_CHECKSIG"
    }
  ]
}
'''
