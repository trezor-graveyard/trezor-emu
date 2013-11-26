import struct
import binascii
from hashlib import sha256

import tools
import trezor_pb2 as proto

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

def compile_TxOutput(txout):
    ret = proto.TxOutputBin()
    ret.amount = txout.amount

    if len(list(txout.address_n)):
        raise Exception("address_n should be converted to address already")

    if txout.script_type == proto.PAYTOADDRESS:
        script = '\x76\xa9'  # op_dup, op_hash_160
        script += '\x14'  # push 0x14 bytes
        script += tools.bc_address_to_hash_160(txout.address)
        script += '\x88\xac'  # op_equalverify, op_checksig
        ret.script_pubkey = script

    elif txout.script_type == proto.PAYTOSCRIPTHASH:
        raise Exception("Not implemented")

    else:
        raise Exception("Unknown script type")

    return ret

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
        if self.have_inputs < self.inputs_len:
            raise Exception("Need all inputs first")

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
