import unittest
import json
import binascii
import urllib2
import sys

sys.path.append('../')
from trezor import trezor_pb2 as proto
from trezor.transaction import StreamTransaction, StreamTransactionHash

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

class TestTransaction(unittest.TestCase):
    def _load_vectors(self):
        f = open('test_transaction_vectors.json', 'r')
        return json.load(f)

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

if __name__ == '__main__':
    unittest.main()
