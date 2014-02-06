import binascii
from ecdsa.util import string_to_number

from logo import logo
import coindef
import tools
from bip32 import BIP32
import messages_pb2 as proto
import types_pb2 as proto_types

from transaction import StreamTransactionHash, StreamTransactionSerialize, \
        StreamTransactionSign, compile_TxOutput, estimate_size, estimate_size_kb

'''
Workflow for two inputs and two outputs:

C SignTx
S TxRequest(type=input, index=0)
C TxInput
S TxRequest(type=input, index=1)
C TxInput
S TxRequest(type=output, index=0)
C TxOutput
S TxRequest(type=output, index=1)
C TxOutput
S TxRequest(type=input, index=0, signed_index=0, signature=<str>, serialized_tx=<str>
C TxInput
S TxRequest(type=input, index=1)
C TxInput
S TxRequest(type=output, index=0)
C TxOutput
S TxRequest(type=output, index=1)
C TxOutput
S TxRequest(type=output, index=0, signed_index=1, signature=<str>, serialized_tx=<str>
C TxOutput
S TxRequest(type=output, index=1, serialized_tx=<str>)
C TxOutput
S TxRequest(type=output, index=-1, serialized_tx=<str>)
'''

class SimpleSignStateMachine(object):
    def __init__(self, layout, storage, yesno, passphrase):
        self.layout = layout
        self.storage = storage
        self.yesno = yesno
        self.passphrase = passphrase

        self.set_main_state()

    def set_main_state(self):
        self.bip32 = None  # Reference to fresh BIP32 instance

    def simple_sign_tx(self, msg):
        self.bip32 = BIP32(self.storage.get_node())
        return self.confirm_output(msg, 0)

    def confirm_output(self, msg, index, out_change=None):
        '''Iterate over all outputs and ask user to confirm
        every address and balance'''

        if index >= len(msg.outputs):
            # All outputs are confirmed by user
            return self.confirm_fee(msg, out_change)

        coin = coindef.types[msg.coin_name]
        out = msg.outputs[index]

        if len(list(out.address_n)) and out.HasField('address'):
            return proto.Failure(code=proto_types.Failure_Other,
                                 message="Cannot have both address and address_n for the output")

        # Calculate proper address for given address_n
        if len(list(out.address_n)):
            out.address = self.bip32.get_address(coin, list(out.address_n))
            out.ClearField('address_n')
            out_change = index  # Remember which output is supposed to be a change

        self.layout.show_output(coin, out.address, out.amount)
        return self.yesno.request(proto_types.ButtonRequest_ConfirmOutput, self.confirm_output, *[msg, index + 1, out_change])
    
    def confirm_fee(self, msg, out_change):
        coin = coindef.types[msg.coin_name]
        print "CHANGE OUT:", out_change

        # Calculate tx hashes for all provided input transactions
        txes = {}
        for tx in msg.transactions:
            hsh = binascii.hexlify(StreamTransactionHash.calculate(tx)[::-1])
            txes[hsh] = tx

        # Check tx fees
        to_spend = 0
        for inp in msg.inputs:
            tx = txes[binascii.hexlify(inp.prev_hash)]
            to_spend += tx.outputs[inp.prev_index].amount

        spending = 0
        for out in msg.outputs:
            spending += out.amount

        est_size = estimate_size_kb(len(msg.inputs), len(msg.outputs))
        maxfee = coin.maxfee_kb * est_size
        fee = to_spend - spending

        print "Est tx size:", est_size
        print "Maxfee:", maxfee
        print "Tx fee:", fee
        print "Now please be patient..."

        if spending > to_spend:
            return proto.Failure(code=proto_types.Failure_Other, message="Not enough funds")

        if fee > maxfee:
            # FIXME soft limit
            #return proto.Failure(code=proto_types.Failure_Other, message="Fee is over threshold")
            self.layout.show_high_fee(fee, coin)
            return self.yesno.request(proto_types.ButtonRequest_FeeOverThreshold, self.do_sign, *[msg])

        return self.do_sign(msg)

    def do_sign(self, msg):
        # Basic checks passed, let's sign that shit!
        version = 1
        lock_time = 0
        serialized = ''

        coin = coindef.types[msg.coin_name]
        outtx = StreamTransactionSerialize(len(msg.inputs), len(msg.outputs), version, lock_time)

        # Sign inputs
        index = 0
        self.layout.show_progress(index, len(msg.inputs), clear=True, logo=logo)
        for inp in msg.inputs:
            self.layout.show_progress(index, len(msg.inputs), clear=False)

            tx = StreamTransactionSign(index, len(msg.inputs), len(msg.outputs), version, lock_time)

            for i in msg.inputs:
                print '.',
                if i == inp:
                    address = self.bip32.get_address(coin, list(i.address_n))
                    private_key = self.bip32.get_private_node(list(i.address_n)).private_key
                    print "ADDRESS", address
                    print "PRIVKEY", binascii.hexlify(private_key)
                    secexp = string_to_number(private_key)
                    tx.serialize_input(i, address, secexp)
                else:
                    tx.serialize_input(i)

            for o in msg.outputs:
                print '.',
                tx.serialize_output(compile_TxOutput(o))

            (signature, pubkey) = tx.sign()
            print "PUBKEY", binascii.hexlify(pubkey)
            serialized += outtx.serialize_input(inp, signature, pubkey)
            index += 1

        for out in msg.outputs:
            print '.',
            serialized += outtx.serialize_output(compile_TxOutput(out))

        self.layout.show_logo()
        self.set_main_state()
        return proto.TxRequest(request_type=proto_types.TXOUTPUT,
                               request_index=-1,
                               serialized_tx=serialized)

    def process_message(self, msg):
        if isinstance(msg, proto.SimpleSignTx):
            return self.passphrase.use(self.simple_sign_tx, msg)

class SignStateMachine(object):
    def __init__(self, layout, storage, yesno, passphrase):
        self.layout = layout
        self.storage = storage
        self.yesno = yesno
        self.passphrase = passphrase

        self.set_main_state()

    def set_main_state(self):
        self.inputs_count = 0  # Count of inputs in transaction
        self.outputs_count = 0  # Count ot outputs in transaction
        self.input_index = 0  # Index <0, inputs_count) of currently processed input
        self.output_index = 0  # Index <0, outputs_count) of currently processed output
        self.signing_index = 0  # Index <0, inputs_count) of currently processed signature
        self.signing_input = None  # Cache of currently signing input, for sending back serialized input

        self.input_hash = None  # sha256 object of currently processed input
        self.output_hash = None  # sha256 object of currently processed output
        self.tx_hash = None  # sha256 object of whole transaction

        # When flag is set, tx_output streams back it's part of tx template.
        # This is used in final phase of signing, where computer needs to know the rest
        # of transaction template, from last signature to the end
        self.ser_output = False

        self.bip32 = None  # Reference to fresh BIP32 instance


    def estimate_tx_size(self, msg):
        '''This is stub implementation, which will be replaced by exact
        calculation in the future.'''
        est_size = estimate_size(msg.inputs_count, msg.outputs_count)
        return proto.TxSize(tx_size=est_size)

    def sign_tx(self, msg):
        # This function starts workflow of signing Bitcoin transaction.
        # Function set up the environment and send back a input request message,
        # asking computer for first input.

        raise Exception("Not implemented")

        self.set_main_state()

        if msg.inputs_count < 1:
            return proto.Failure(message='Transaction must have at least one input')

        if msg.outputs_count < 1:
            return proto.Failure(message='Transaction must have at least one output')

        self.inputs_count = msg.inputs_count
        self.outputs_count = msg.outputs_count


        self.bip32 = BIP32(self.storage.get_xprv())

        return proto.TxRequest(request_type=proto_types.TXINPUT,
                               request_index=self.input_index)

    '''
    def tx_input(self, msg):
        # This message is called on tx input message.

        if msg.index != self.input_index:
            self.set_main_state()
            return proto.Failure(message="Input index doesn't correspond with internal state")

        print "RECEIVED INPUT", msg

        if msg.index == self.signing_index:
            # Store message to cache for serializing input in tx_output
            self.signing_input = msg

        
        #There we have received one input.
        if self.signing_index == 0:
            # If it is first one, we have to prepare
            # and hash the beginning of the transaction.

            if self.input_index == 0:
                # First input, let's hash the beginning of tx
                self.input_hash = hashlib.sha256(signing.raw_tx_header(self.inputs_count))
                self.tx_hash = self.input_hash

                #self.tx_hash.update()

                #self.input_hash.update(signing.raw_tx_input())
                #self.tx_hash.update(signing.raw_tx_input())
                # TODO

        # For every input, hash the input itself.
        print "INPUT HASH", self.input_hash.hexdigest()
        # TODO

        if self.input_index < self.inputs_count - 1:
            # If this is not the last input, request next input in the row.
            self.input_index += 1
            return proto.TxRequest(request_type=proto_types.TXINPUT,
                                   request_index=self.input_index)

        # We have processed all inputs. Let's request transaction outputs now.
        self.output_index = 0
        self.output_hash = hashlib.sha256()
        return proto.TxRequest(request_type=proto_types.TXOUTPUT,
                               request_index=self.output_index)

    def _check_address_n(self, msg):
        if len(msg.address_n):
            # Recalculate output address and compare with msg.address
            if msg.address != self.bip32.get_address(list(msg.address_n), self.storage.get_address_type()):
                self.set_main_state()
                return proto.Failure(message="address_n doesn't belong to given bitcoin address")

    def _check_output_index(self, msg):
        if msg.index != self.output_index:
            self.set_main_state()
            return proto.Failure(message="Output index doesn't correspond with internal state")

    def tx_output(self, msg):
        # This message is called on TxInput message, when serialize_output is False.
        # It does all the hashing for making input signatures.

        res = self._check_output_index(msg)
        if res is not None:
            return res

        res = self._check_address_n(msg)
        if res is not None:
            return res

        if self.output_index == 0:
            # If it is first one, we have to prepare
            # and hash the middle of the transaction (between inputs and outputs).
            # TODO

        # Let's hash tx output
        print "RECEIVED OUTPUT", msg

        if self.input_index == 0:
            # This is first time we're processing this output,
            # let's display output details on screen
            # self.layout.show_transactions()
            print "OUTPUT", msg.address, msg.amount

        if self.output_index < self.outputs_count - 1:
            # This was not the last tx output, so request next one.
            self.output_index += 1
            return proto.TxRequest(request_type=proto.TXOUTPUT,
                                   request_index=self.output_index)

        # Now we have processed all inputs and outputs. Let's finalize
        # hash of transaction.

        # Now we have hash of all outputs
        print "OUTPUT HASH", self.output_hash.hexdigest()

        # We also have tx hash now
        print "TX HASH", self.tx_hash.hexdigest()

        # We want to send header of tx template
        serialized_tx = ''
        if self.signing_index == 0:
            print "!!! SENDING TX HEADER"
            serialized_tx += signing.raw_tx_header(self.inputs_count)

        # Compute signature for current signing index
        print "FINISH INPUT SIGNATURE", self.signing_index

        # FIXME, TODO, CHECK
        start = time.time()
        # privkey = self.bip32.get_private_key(self.signing_input.address_n)
        (_, signature) = signing.sign_input(self.bip32,
                                    list(self.signing_input.address_n),
                                    hashlib.sha256(self.tx_hash.digest()).digest())
        # (_, signature) = self.bip32.sign_input(self.signing_input.address_n,
        #                                        hashlib.sha256(self.tx_hash.digest()).digest())
        print 'xxxx', time.time() - start

        serialized_tx += 'aaaa' + signing.raw_tx_input(self.signing_input, signature) + 'aaaa'  # FIXME, TODO, CHECK

        if self.signing_index < self.inputs_count - 1:
            # If we didn't process all signatures yet,
            # let's restart the signing process
            # and ask for first input again.

            # We're also sending signature for now_signed's input
            # back to the computer.
            now_signed = self.signing_index
            self.signing_index += 1
            self.input_index = 0
            self.input_hash = hashlib.sha256()
            return proto.TxRequest(request_type=proto.TXINPUT,
                                   request_index=self.input_index,
                                   signed_index=now_signed,
                                   signature=signature,
                                   serialized_tx=serialized_tx)

        # We signed all inputs, so it looks like we're done!
        # Let's ask again for all outputs to finalize serialized transaction.
        # process_message knows that we're in final stage by self.ser_output flag
        # and will route messages to serialize_output instead to tx_output.
        self.output_index = 0  # We need to reset counter
        self.ser_output = True
        return proto.TxRequest(request_type=proto.TXOUTPUT,
                               request_index=0,
                               signed_index=self.signing_index,
                               signature=signature,
                               serialized_tx=serialized_tx)

    def serialize_output(self, msg):
        # This message is called on TxInput message, when ser_output is True.
        # It just finalize serialized_tx structure in computer by dumping template
        # used for creating signatures.

        res = self._check_output_index(msg)
        if res is not None:
            return res

        res = self._check_address_n(msg)
        if res is not None:
            return res

        serialized_tx = ''

        if self.output_index == 0:
            # If it is first one, we have to send middle part of tx.
            serialized_tx += signing.raw_tx_middle(self.outputs_count)

        # Let's serialize tx output
        serialized_tx += signing.raw_tx_output(msg)

        if self.output_index < self.outputs_count - 1:
            # This was not the last tx output, so request next one.
            self.output_index += 1
            print "REQUESTING", self.output_index
            return proto.TxRequest(request_type=proto.TXOUTPUT,
                                   request_index=self.output_index,
                                   serialized_tx=serialized_tx)

        # Ok, this looks like last output, so we need send tx footer
        serialized_tx += signing.raw_tx_footer(for_sign=False)

        print "FINISHING"
        # We're done with serializing outputs!
        return proto.TxRequest(request_type=proto.TXOUTPUT,
                               request_index=-1,
                               serialized_tx=serialized_tx)
    '''

    def process_message(self, msg):
        if isinstance(msg, proto.EstimateTxSize):
            return self.passphrase.use(self.estimate_tx_size, msg)

        if isinstance(msg, proto.SignTx):
            # Start signing process
            return self.passphrase.use(self.sign_tx, msg)

        '''
        if isinstance(msg, proto.TxInput):
            return self.tx_input(msg)

        if isinstance(msg, proto.TxOutput):
            if self.ser_output:
                # We just want to serialize part of output
                # and send it back to computer
                return self.serialize_output(msg)
            else:
                return self.tx_output(msg)
        '''
        # return Failure message to indicate problems to upstream SM
        return proto.Failure(code=1, message="Signing failed")
