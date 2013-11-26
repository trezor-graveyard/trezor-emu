import unittest
import json
import binascii
import urllib2
import sys

sys.path.append('../')
from trezor import trezor_pb2 as proto
from trezor.transaction import StreamTransaction, StreamTransactionHash, \
    compile_TxOutput

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
    t = proto.TransactionType()

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
        tx1_hash = '1ae39a2f8d59670c8fc61179148a8e61e039d0d9e8ab08610cb69b4a19453eaf'
        tx2_hash = 'c16a03f1cf8f99f6b5297ab614586cacec784c2d259af245909dedb0e39eddcf'

        tx1 = get_tx(tx1_hash)
        tx2 = get_tx(tx2_hash)

        prevout1 = tx1.outputs[1]
        prevout2 = tx2.outputs[1]

        inp1 = proto.TxInput()
        inp1.prev_hash = binascii.unhexlify(tx1_hash)
        inp1.prev_index = 1

        inp2 = proto.TxInput()
        inp2.prev_hash = binascii.unhexlify(tx2_hash)
        inp2.prev_index = 1

        out1 = proto.TxOutput()
        out1.address = '19WGvAHM5yJhftsf1c753QiyhVQWCFcoiY'
        out1.amount = 100000
        out1.script_type = proto.PAYTOADDRESS

        out2 = proto.TxOutput()
        out2.address = '1GVnMb17jJirVp6TPMPBM9xb3gruasG82X'
        out2.amount = 290000
        out2.script_type = proto.PAYTOADDRESS

        # Check tx fee
        to_spend = prevout1.amount + prevout2.amount
        spending = out1.amount + out2.amount
        fee = to_spend - spending
        if fee > 10000:
            raise Exception("High fee")

        d = ''
        version = 1
        lock_time = 0
        inp_count = 2
        out_count = 2
        tx = StreamTransaction(inp_count, out_count, version, lock_time)
        d += tx.serialize_input(inp1)
        d += tx.serialize_input(inp2)
        d += tx.serialize_output(compile_TxOutput(out1))
        d += tx.serialize_output(compile_TxOutput(out2))

        print binascii.hexlify(d)




if __name__ == '__main__':
    unittest.main()
