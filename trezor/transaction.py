import struct
import binascii
import hashlib
import ecdsa
from hashlib import sha256

import tools
import types_pb2 as types

def ser_length(l):
    if l < 253:
        return chr(l)
    elif l < 0x10000:
        return chr(253) + struct.pack("<H", l)
    elif l < 0x100000000L:
        return chr(254) + struct.pack("<I", l)
    else:
        return chr(255) + struct.pack("<Q", l)

def op_push(i):
    if i<0x4c:
        return chr(i)
    elif i<0xff:
        return '\x4c' + chr(i)
    elif i<0xffff:
        return '\x4d' + struct.pack("<H", i)
    else:
        return '\x4e' + struct.pack("<I", i)

def ser_uint256(u):
    rs = ""
    for _ in xrange(8):
        rs += struct.pack("<I", u & 0xFFFFFFFFL)
        u >>= 32
    return rs

def compile_TxOutput(txout):
    ret = types.TxOutputBinType()
    ret.amount = txout.amount

    if len(list(txout.address_n)):
        raise Exception("address_n should be converted to address already")

    if txout.script_type == types.PAYTOADDRESS:
        script = '\x76\xa9'  # op_dup, op_hash_160
        script += '\x14'  # push 0x14 bytes
        script += tools.bc_address_to_hash_160(txout.address)
        script += '\x88\xac'  # op_equalverify, op_checksig
        ret.script_pubkey = script

    elif txout.script_type == types.PAYTOSCRIPTHASH:
        raise Exception("Not implemented")

    else:
        raise Exception("Unknown script type")

    return ret

def compile_script_sig(address):
    # Compile address to paytoaddress script
    address_type = tools.bc_address_type(address)

    if address_type == 0:  # BTC, paytoaddress
        script = '\x76\xa9'  # op_dup, op_hash_160
        script += '\x14'  # push 0x14 bytes
        script += tools.bc_address_to_hash_160(address)
        script += '\x88\xac'
        return script

    elif address_type == 5:  # BTC, P2SH
        raise Exception("P2SH not implemented yet")

    raise Exception("Unsupported address type")

def serialize_script_sig(signature, pubkey):
    # Put signature and pubkey together for serializing signed tx
    signature += '\x01'  # hashtype
    script = ''
    script += op_push(len(signature))
    script += signature
    script += op_push(len(pubkey))
    script += pubkey
    
    return script

class StreamTransaction(object):
    # Lowlevel streaming serialized of transaction structure
    def __init__(self, inputs_len, outputs_len, version, lock_time, add_hash_type=False):
        self.inputs_len = inputs_len
        self.outputs_len = outputs_len

        self.version = version
        self.lock_time = lock_time
        self.add_hash_type = add_hash_type

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
        d = struct.pack("<I", self.lock_time)
        if self.add_hash_type:
            d += struct.pack("<I", 1)
        return d

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
    # Serialized of streamed transaction, calculates txhash on the fly
    def __init__(self, inputs_len, outputs_len, version, lock_time, add_hash_type=False):
        super(StreamTransactionHash, self).__init__(inputs_len, outputs_len, version, lock_time, add_hash_type)

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
        return sha256(self.hash.digest()).digest()

    @classmethod
    def calculate(cls, tx):
        # Demonstration of hash calculation in streamed fashion
        th = cls(len(tx.inputs), len(tx.outputs), tx.version, tx.lock_time)

        for i in tx.inputs:
            th.serialize_input(i)

        for o in tx.outputs:
            th.serialize_output(o)

        return th.calc_txid()

class StreamTransactionSerialize(StreamTransaction):
    # Serialized of streamed transaction, calculates txhash on the fly
    def __init__(self, inputs_len, outputs_len, version, lock_time):
        super(StreamTransactionSerialize, self).__init__(inputs_len, outputs_len, version, lock_time, False)

    def serialize_input(self, inp, signature, pubkey):
        inp.script_sig = serialize_script_sig(signature, pubkey)
        r = super(StreamTransactionSerialize, self).serialize_input(inp)
        return r

class StreamTransactionSign(StreamTransactionHash):
    # Signer of serialized transaction, returns signature and pubkey
    # for every pass
    def __init__(self, input_index, inputs_len, outputs_len, version, lock_time):
        self.input_index = input_index  # Which index we're signing now
        self.secexp = None
        super(StreamTransactionSign, self).__init__(inputs_len, outputs_len, version, lock_time, True)

    def serialize_input(self, inp, address=None, secexp=None):
        if self.have_inputs == self.input_index:
            # Let's prepare current index to sign

            if address == None:
                raise Exception("Address of current input needed")
            if secexp == None:
                raise Exception("secexp for current privkey needed")
            if self.secexp != None:
                raise Exception("secexp for this round has been already set")

            self.secexp = secexp
            inp.script_sig = compile_script_sig(address)

        else:
            inp.script_sig = ''

        r = super(StreamTransactionSign, self).serialize_input(inp)
        return r

    # def serialize_output(self, output):
    #    r = super(StreamTransactionSign, self).serialize_output(output)
    #    return r

    def sign(self):
        sk = ecdsa.SigningKey.from_secret_exponent(self.secexp, curve=ecdsa.curves.SECP256k1)
        signature = sk.sign_digest_deterministic(self.calc_txid(),
                                                 hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)
        pubkey = '\x04' + sk.get_verifying_key().to_string()  # \x04 -> uncompressed key
        pubkey = tools.compress_pubkey(pubkey)
        return (signature, pubkey)
