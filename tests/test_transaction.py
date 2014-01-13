import unittest
import json
import struct
import binascii
import urllib2
import sys
import hashlib
import ecdsa

sys.path.append('../')
from trezor import messages_pb2 as proto
from trezor import types_pb2 as types
from trezor.transaction import StreamTransaction, StreamTransactionHash, \
    StreamTransactionSign, StreamTransactionSerialize, \
    compile_TxOutput, compile_script_sig, serialize_script_sig

def pprint(data):
    # pretty printing of json structure
    print json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))

def raw_tx(txhash):
    # Download tx data from blockchain.info
    f = urllib2.urlopen('http://blockchain.info/rawtx/%s?scripts=true' % txhash)
    print 'got', txhash
    return json.load(f)

def get_tx(txhash):
    # Build protobuf transaction structure from blockchain.info
    d = raw_tx(txhash)
    t = types.TransactionType()

    for inp in d['inputs']:
        di = raw_tx(inp['prev_out']['tx_index'])
        i = t.inputs.add()
        i.prev_hash = binascii.unhexlify(di['hash'])
        i.prev_index = inp['prev_out']['n']
        i.script_sig = binascii.unhexlify(inp['script'])

    for output in d['out']:
        o = t.outputs.add()
        o.amount = output['value']
        o.script_pubkey = binascii.unhexlify(output['script'])

    return t

'''
Transaction with most inputs:
http://blockexplorer.com/t/55mvNHTqsH

Transaction with most outputs:
http://blockexplorer.com/t/25Q3XTsoe3

Address with most transactions:
http://blockexplorer.com/a/2isMCwqPQ2
'''

class TestTransaction(unittest.TestCase):
    def _load_vectors(self):
        f = open('test_transaction_vectors.json', 'r')
        return json.load(f)

    '''
    def test_serialize(self):
        for enabled, txid, serialized in self._load_vectors():
            if not enabled:
                # Do not use this vector
                continue

            # Download tx from blockchain and serialize it into protobuf
            tx_proto = get_tx(txid)

            # Serialize into bitcoin binary format
            data = StreamTransaction.serialize(tx_proto)

            # Compare serialized data
            self.assertEqual(binascii.hexlify(data), serialized)

            # Check if transaction id has been calculated correctly
            self.assertEqual(binascii.hexlify(StreamTransactionHash.calculate(tx_proto)), txid)
    '''

    def test_signing(self):
        '''
            ./electrum -w ~/.electrum-trezor mktx -f 0.0001 19WGvAHM5yJhftsf1c753QiyhVQWCFcoiY 0.039

            input 1:
            address 19qyPUSAXJ8cHw6TxZ6FYQFZdLMdJA7A2t
            pubkey 047a2d177c0f3626fc68c53610b0270fa6156181f46586c679ba6a88b34c6f4874686390b4d92e5769fbb89c8050b984f4ec0b257a0e5c4ff8bd3b035a51709503
            privkey 5JSSWLXRbfzwEcJfQ4Xcawvdru1eE6mid6Np4vRaf2N2VNnZy34
            secexp 521780deb5580c1c0e9851662c4963b5bd16b1805617ddc64ce9d69cf4a78397
            hash160 61040ad59b0b27402b8229df1fbd9442df409834
            tx hash to sign 69dd44af847f7e5f7aac451acf3bfddcfa270ee457ee1b9f837411f037f458e5

            input 2:
            address 1B4scQC2N8NZ5cYVbVwDrao1aSnwNAAvbb
            pubkey 0486ad608470d796236b003635718dfc07c0cac0cfc3bfc3079e4f491b0426f0676e6643a39198e8e7bdaffb94f4b49ea21baa107ec2e237368872836073668214
            privkey 5J2eS9jqhrBiQpjLYYmmANM9fzjuXBZkhcMTYF2j378YttocKFx
            secexp 1c1057564b1a27bc02110909545c7f5070be7df0186323c6d8a4efa11ae244d7
            hash160 6e6cc0cbbff6d830de4ec174d3e2539874a9dbec
            tx hash to sign f48a4839988f154e827d5d88172ba41e05629b2e0ebca6b6cb619214bc5acc13

            signed & serialized:
            0100000002cfdd9ee3b0ed9d9045f29a252d4c78ecac6c5814b67a29b5f6998fcff1036ac101000000
            8a473044022060881f66de54e6f6079a965036ef4e81d8d61bcbad2eb3897dfd0dc02178b2c9022043
            7478cd698ea9515b152af42f9746b70f2a597b171125face2e3b042ac23d0f0141047a2d177c0f3626
            fc68c53610b0270fa6156181f46586c679ba6a88b34c6f4874686390b4d92e5769fbb89c8050b984f4
            ec0b257a0e5c4ff8bd3b035a51709503ffffffffaf3e45194a9bb60c6108abe8d9d039e0618e8a1479
            11c68f0c67598d2f9ae31a010000008b483045022100a859cd1f8ef5fc611e4c9946296e9d181a522d
            1afc07ab82dc7d871e56a5c7960220741b11df59c017d9d8232d724acec10c82c1314b0b925295415d
            26bc810692cd01410486ad608470d796236b003635718dfc07c0cac0cfc3bfc3079e4f491b0426f067
            6e6643a39198e8e7bdaffb94f4b49ea21baa107ec2e237368872836073668214ffffffff0170f30500
            000000001976a9145d4a5b0a9f73fc4c320da7919f85c0f5a84681f388ac00000000

        '''
        tx1_hash = 'c16a03f1cf8f99f6b5297ab614586cacec784c2d259af245909dedb0e39eddcf'
        tx2_hash = '1ae39a2f8d59670c8fc61179148a8e61e039d0d9e8ab08610cb69b4a19453eaf'

        tx1 = get_tx(tx1_hash)
        tx2 = get_tx(tx2_hash)

        prevout1 = tx1.outputs[1]
        prevout2 = tx2.outputs[1]

        inp1 = types.TxInputType()
        inp1.prev_hash = binascii.unhexlify(tx1_hash)
        inp1.prev_index = 1

        inp2 = types.TxInputType()
        inp2.prev_hash = binascii.unhexlify(tx2_hash)
        inp2.prev_index = 1

        out1 = types.TxOutputType()
        out1.address = '19WGvAHM5yJhftsf1c753QiyhVQWCFcoiY'
        out1.amount = 390000
        out1.script_type = types.PAYTOADDRESS

        # Check tx fee
        to_spend = prevout1.amount + prevout2.amount
        spending = out1.amount  # + out2.amount
        fee = to_spend - spending
        if fee > 10000:
            raise Exception("High fee")

        d = ''
        version = 1
        lock_time = 0
        inp_count = 2
        out_count = 1

        outtx = StreamTransactionSerialize(inp_count, out_count, version, lock_time)
        out = ''

        '''
        Three streaming objects:
            a) StreamTransactionSerialize for serializing already signed fragments for P2P wire
            b) StreamTransactionHash for confirming that every pass handles the same parameters
                as user confirmed
            c) StreamTransactionSign for signing actual input
        '''
        # Signature 1
        tx = StreamTransactionSign(0, inp_count, out_count, version, lock_time)
        d += tx.serialize_input(inp1, address='19qyPUSAXJ8cHw6TxZ6FYQFZdLMdJA7A2t',
                                secexp=int('521780deb5580c1c0e9851662c4963b5bd16b1805617ddc64ce9d69cf4a78397', 16))
        d += tx.serialize_input(inp2)
        d += tx.serialize_output(compile_TxOutput(out1))
        hash1 = tx.calc_txid()
        (signature1, pubkey1) = tx.sign()
        out += outtx.serialize_input(inp1, signature1, pubkey1)
        print 'signature1', binascii.hexlify(signature1)
        print "TOSIGN", binascii.hexlify(d)
        print "HASH1", binascii.hexlify(hash1)

        # Signature 2
        tx = StreamTransactionSign(1, inp_count, out_count, version, lock_time)
        d = tx.serialize_input(inp1)
        d += tx.serialize_input(inp2, address='1B4scQC2N8NZ5cYVbVwDrao1aSnwNAAvbb',
                                secexp=int('1c1057564b1a27bc02110909545c7f5070be7df0186323c6d8a4efa11ae244d7', 16))
        d += tx.serialize_output(compile_TxOutput(out1))
        hash2 = tx.calc_txid()
        (signature2, pubkey2) = tx.sign()
        out += outtx.serialize_input(inp2, signature2, pubkey2)
        print 'signature2', binascii.hexlify(signature2)
        print "TOSIGN2", binascii.hexlify(d)
        #print 'scriptsig', binascii.hexlify(serialize_script_sig(signature1, pubkey1))

        out += outtx.serialize_output(compile_TxOutput(out1))
        print "TXHASH", binascii.hexlify(hashlib.sha256(hashlib.sha256(out).digest()).digest())
        print binascii.hexlify(out)
        
        self.assertEqual(binascii.hexlify(hash1), '69dd44af847f7e5f7aac451acf3bfddcfa270ee457ee1b9f837411f037f458e5')
        self.assertEqual(binascii.hexlify(hash2), 'f48a4839988f154e827d5d88172ba41e05629b2e0ebca6b6cb619214bc5acc13')
        self.assertEqual(binascii.hexlify(signature1), '3044022060881f66de54e6f6079a965036ef4e81d8d61bcbad2eb3897dfd0dc02178b2c90220437478cd698ea9515b152af42f9746b70f2a597b171125face2e3b042ac23d0f')
        self.assertEqual(binascii.hexlify(signature2), '3045022100a859cd1f8ef5fc611e4c9946296e9d181a522d1afc07ab82dc7d871e56a5c7960220741b11df59c017d9d8232d724acec10c82c1314b0b925295415d26bc810692cd')
        self.assertEqual(binascii.hexlify(pubkey1), '047a2d177c0f3626fc68c53610b0270fa6156181f46586c679ba6a88b34c6f4874686390b4d92e5769fbb89c8050b984f4ec0b257a0e5c4ff8bd3b035a51709503')
        self.assertEqual(binascii.hexlify(pubkey2), '0486ad608470d796236b003635718dfc07c0cac0cfc3bfc3079e4f491b0426f0676e6643a39198e8e7bdaffb94f4b49ea21baa107ec2e237368872836073668214')

        # print serialized
        self.assertEqual(binascii.hexlify(out), "0100000002cfdd9ee3b0ed9d9045f29a252d4c78ecac6c5814b67a29b5f6998fcff1036ac101000000"
           "8a473044022060881f66de54e6f6079a965036ef4e81d8d61bcbad2eb3897dfd0dc02178b2c9022043"
           "7478cd698ea9515b152af42f9746b70f2a597b171125face2e3b042ac23d0f0141047a2d177c0f3626"
           "fc68c53610b0270fa6156181f46586c679ba6a88b34c6f4874686390b4d92e5769fbb89c8050b984f4"
           "ec0b257a0e5c4ff8bd3b035a51709503ffffffffaf3e45194a9bb60c6108abe8d9d039e0618e8a1479"
           "11c68f0c67598d2f9ae31a010000008b483045022100a859cd1f8ef5fc611e4c9946296e9d181a522d"
           "1afc07ab82dc7d871e56a5c7960220741b11df59c017d9d8232d724acec10c82c1314b0b925295415d"
           "26bc810692cd01410486ad608470d796236b003635718dfc07c0cac0cfc3bfc3079e4f491b0426f067"
           "6e6643a39198e8e7bdaffb94f4b49ea21baa107ec2e237368872836073668214ffffffff0170f30500"
           "000000001976a9145d4a5b0a9f73fc4c320da7919f85c0f5a84681f388ac00000000")

        '''
            0100000002cfdd9ee3b0ed9d9045f29a252d4c78ecac6c5814b67a29b5f6998fcff1036ac101000000
            0100000002cfdd9ee3b0ed9d9045f29a252d4c78ecac6c5814b67a29b5f6998fcff1036ac101000000

            8a473044022060881f66de54e6f6079a965036ef4e81d8d61bcbad2eb3897dfd0dc02178b2c9022043
            00  3044022060881f66de54e6f6079a965036ef4e81d8d61bcbad2eb3897dfd0dc02178b2c9022043

            7478cd698ea9515b152af42f9746b70f2a597b171125face2e3b042ac23d0f0141047a2d177c0f3626
            7478cd698ea9515b152af42f9746b70f2a597b171125face2e3b042ac23d0f    047a2d177c0f3626
                                                                              ^- pubkey1 start

            fc68c53610b0270fa6156181f46586c679ba6a88b34c6f4874686390b4d92e5769fbb89c8050b984f4
            fc68c53610b0270fa6156181f46586c679ba6a88b34c6f4874686390b4d92e5769fbb89c8050b984f4

            ec0b257a0e5c4ff8bd3b035a51709503ffffffffaf3e45194a9bb60c6108abe8d9d039e0618e8a1479
            ec0b257a0e5c4ff8bd3b035a51709503ffffffffaf3e45194a9bb60c6108abe8d9d039e0618e8a1479
                              pubkey1 end -^

            11c68f0c67598d2f9ae31a010000008b483045022100a859cd1f8ef5fc611e4c9946296e9d181a522d
            11c68f0c67598d2f9ae31a0100000000

            1afc07ab82dc7d871e56a5c7960220741b11df59c017d9d8232d724acec10c82c1314b0b925295415d


            26bc810692cd01410486ad608470d796236b003635718dfc07c0cac0cfc3bfc3079e4f491b0426f067
                            0486ad608470d796236b003635718dfc07c0cac0cfc3bfc3079e4f491b0426f067
                            ^- pubkey2 start

            6e6643a39198e8e7bdaffb94f4b49ea21baa107ec2e237368872836073668214ffffffff0170f30500
            6e6643a39198e8e7bdaffb94f4b49ea21baa107ec2e237368872836073668214ffffffff0170f30500
                                                              pubkey2 end -^

            000000001976a9145d4a5b0a9f73fc4c320da7919f85c0f5a84681f388ac00000000
            000000001976a9145d4a5b0a9f73fc4c320da7919f85c0f5a84681f388ac00000000
        '''

if __name__ == '__main__':
    unittest.main()
