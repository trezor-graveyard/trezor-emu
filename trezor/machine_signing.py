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
Workflow of streamed signing

I - input
O - output

foreach I:
    Request I

    Calculate amount of I:
        Request prevhash I, META
        foreach prevhash I:
            Request prevhash I
        foreach prevhash O:
            Request prevhash O
            Store amount of I
        Calculate hash of streamed tx, compare to prevhash I

    Request META
    Add META to StreamTransactionSign
    foreach I:
        Request I
        If I == I-to-be-signed:
            Fill scriptsig
        Add I to StreamTransactionSign
    foreach O:
        Request O
        If I=0:
            Display output
            Ask for confirmation
        Add O to StreamTransactionSign

    If I=0:
        Check tx fee
        Calculate txhash
    else:
        Compare current hash with txhash
        If different:
            Failure

    Sign StreamTransactionSign
    Return signed chunk
'''

class SimpleSignStateMachine(object):
    def __init__(self, layout, storage, yesno, pin, passphrase):
        self.layout = layout
        self.storage = storage
        self.yesno = yesno
        self.pin = pin
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
            if out_change == None:
                out.address = self.bip32.get_address(coin, list(out.address_n))
                out.ClearField('address_n')
                out_change = index  # Remember which output is supposed to be a change
            else:
                return proto.Failure(code=proto_types.Failure_Other,
                                     message="Only one change output allowed")

        if out_change == index: # we have a change output
            return self.confirm_output(msg, index + 1, out_change)
        else:
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
            try:
                tx = txes[binascii.hexlify(inp.prev_hash)]
            except:
                return proto.Failure(code=proto_types.Failure_Other, message="Prev hash %s not found in [%s]" % (binascii.hexlify(inp.prev_hash), ','.join(txes.keys())))
            to_spend += tx.bin_outputs[inp.prev_index].amount

        spending = 0
        for out in msg.outputs:
            spending += out.amount

        if out_change != None:
            change_amount = msg.outputs[out_change].amount
        else:
            change_amount = 0

        est_size = estimate_size_kb(len(msg.inputs), len(msg.outputs))
        maxfee = coin.maxfee_kb * est_size
        fee = to_spend - spending

        print "To spend:", to_spend
        print "Spending:", spending
        print "Est tx size:", est_size
        print "Maxfee:", maxfee
        print "Tx fee:", fee
        print "Change output amount:", change_amount
        print "Now please be patient..."

        if spending > to_spend:
            return proto.Failure(code=proto_types.Failure_NotEnoughFunds, message="Not enough funds")

        if fee > maxfee:
            # FIXME soft limit
            #return proto.Failure(code=proto_types.Failure_Other, message="Fee is over threshold")
            self.layout.show_high_fee(fee, coin)
            return self.yesno.request(proto_types.ButtonRequest_FeeOverThreshold, self.do_confirm_sign, *[msg, to_spend])

        return self.do_confirm_sign(msg, to_spend)

    def do_confirm_sign(self, msg, to_spend):
        coin = coindef.types[msg.coin_name]
        self.layout.show_send_tx(to_spend, coin) # - change_amount)
        return self.yesno.request(proto_types.ButtonRequest_SignTx, self.do_sign, *[msg])
    
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
            serialized += outtx.serialize_input(inp, signature, pubkey)
            print "SIGNATURE", binascii.hexlify(signature)
            print "PUBKEY", binascii.hexlify(pubkey)

            index += 1

        for out in msg.outputs:
            print '.',
            serialized += outtx.serialize_output(compile_TxOutput(out))

        self.layout.show_logo()
        self.set_main_state()
        return proto.TxRequest(request_type=proto_types.TXFINISHED,
                               serialized=proto_types.TxRequestSerializedType(serialized_tx=serialized))

    def process_message(self, msg):
        if isinstance(msg, proto.SimpleSignTx):
            return self.pin.request('', False,
                                    self.passphrase.use, self.simple_sign_tx, msg)

class Workflow(object):
    def workflow(self, msg):
        raise Exception("Override me")
    
    def start(self, msg):
        self.generator = self.workflow(msg)
        return self.generator.next()

    def process(self, msg):
        return self.generator.send(msg)

class TrezorIface(object):
    def __init__(self, layout, storage, yesno, pin, passphrase):
        self.layout = layout
        self.storage = storage
        self.yesno = yesno
        self.pin = pin
        self.passphrase = passphrase

class StreamingSigningWorkflow(Workflow):
    def __init__(self, iface):
        self.iface = iface

    def workflow(self, msg):
        if msg.inputs_count < 1:
            raise Exception(proto.Failure(message='Transaction must have at least one input'))

        if msg.outputs_count < 1:
            raise Exception(proto.Failure(message='Transaction must have at least one output'))

        bip32 = BIP32(self.iface.storage.get_node())
        coin = coindef.types[msg.coin_name]
 
        version = 1
        lock_time = 0
        serialized = ''
        ser = ''

        outtx = StreamTransactionSerialize(msg.inputs_count, msg.outputs_count,
                                           version, lock_time)

        # foreach I:
        for i in range(msg.inputs_count):
            # Request I
            ret = yield(proto.TxRequest(request_type=proto_types.TXINPUT,
                                        details=proto_types.TxRequestDetailsType(
                                            request_index=i, tx_hash='')))
            inp = ret.tx.inputs[0]

            # ----------- Calculate amount of I:
            amount = None

            # Request prevhash I, META
            ret = yield(proto.TxRequest(request_type=proto_types.TXMETA,
                    details=proto_types.TxRequestDetailsType(
                        tx_hash=inp.prev_hash)))
            
            amount_hash = StreamTransactionHash(ret.tx.inputs_count, ret.tx.outputs_count,
                                                version, lock_time)
            # foreach prevhash I:
            for i2 in range(ret.tx.inputs_count):
                # Request prevhash I
                ret2 = yield(proto.TxRequest(request_type=proto_types.TXINPUT,
                        details=proto_types.TxRequestDetailsType(
                            request_index=i2, tx_hash=inp.prev_hash)))
                amount_hash.serialize_input(ret2.tx.inputs[0])

            # foreach prevhash O:
            for o2 in range(ret.tx.outputs_count):
                # Request prevhash O
                ret2 = yield(proto.TxRequest(request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(
                            request_index=o2, tx_hash=inp.prev_hash)))
                amount_hash.serialize_output(ret2.tx.bin_outputs[0])

                if inp.prev_index == o2:
                    # Store amount of I
                    amount = ret2.tx.bin_outputs[0].amount

            # Calculate hash of streamed tx, compare to prevhash I
            if inp.prev_hash != amount_hash.calc_txid()[::-1]:
                raise Exception(proto.Failure(message="Provided input data doesn't match to prev_hash"))

            # ------------- End of streaming amounts
            
            # Request META
            ret = yield(proto.TxRequest(request_type=proto_types.TXMETA,
                                        details=proto_types.TxRequestDetailsType(tx_hash='')))

            # Add META to StreamTransactionSign
            sign = StreamTransactionSign(i, ret.tx.inputs_count, ret.tx.outputs_count,
                                         version, lock_time)

            # foreach I:
            for i2 in range(ret.tx.inputs_count):
                # Request I
                ret2 = yield(proto.TxRequest(request_type=proto_types.TXINPUT,
                        details=proto_types.TxRequestDetailsType(request_index=i2)))

                # If I == I-to-be-signed:
                if i2 == i:
                    # Fill scriptsig
                    address = bip32.get_address(coin, list(ret2.tx.inputs[0].address_n))
                    private_key = bip32.get_private_node(list(ret2.tx.inputs[0].address_n)).private_key
                    print "ADDRESS", address
                    print "PRIVKEY", binascii.hexlify(private_key)

                    secexp = string_to_number(private_key)
                    ser += sign.serialize_input(ret2.tx.inputs[0], address, secexp)
                else:
                    # Add I to StreamTransactionSign
                    ser = sign.serialize_input(ret2.tx.inputs[0])

            # foreach O:
            out_change = None
            for o2 in range(ret.tx.outputs_count):
                # Request O
                ret2 = yield(proto.TxRequest(request_type=proto_types.TXOUTPUT,
                        details=proto_types.TxRequestDetailsType(request_index=o2)))

                out = ret2.tx.outputs[0]
                if len(list(out.address_n)) and out.HasField('address'):
                    raise Exception(proto.Failure(code=proto_types.Failure_Other,
                                 message="Cannot have both address and address_n for the output"))

                # Calculate proper address for given address_n
                if len(list(out.address_n)):
                    if out_change == None:
                        out.address = bip32.get_address(coin, list(out.address_n))
                        out.ClearField('address_n')
                        out_change = o2  # Remember which output is supposed to be a change

                # If I=0:
                if i == 0:
                    # Display output, TODO
                    print "SENDING", out.amount, "TO", out.address

                    # Ask for confirmation, TODO

                # Add O to StreamTransactionSign
                ser += sign.serialize_output(compile_TxOutput(out))

        #    If I=0:
        #        Calculate to_spend, check tx fees - TODO
        #        Ask for confirmation of tx fees - TODO
        #        Calculate txhash
        #    else:
        #        Compare current hash with txhash
        #        If different:
        #            Failure

            # Sign StreamTransactionSign
            (signature, pubkey) = sign.sign()
            serialized += outtx.serialize_input(inp, signature, pubkey)

            print "SIGNATURE", binascii.hexlify(signature)
            print "PUBKEY", binascii.hexlify(pubkey)


        # Serialize outputs
        for o2 in range(ret.tx.outputs_count):
            # Request O
            ret2 = yield(proto.TxRequest(request_type=proto_types.TXOUTPUT,
                    details=proto_types.TxRequestDetailsType(request_index=o2)))

            out = ret2.tx.outputs[0]
            if len(list(out.address_n)) and out.HasField('address'):
                raise Exception(proto.Failure(code=proto_types.Failure_Other,
                             message="Cannot have both address and address_n for the output"))

            # Calculate proper address for given address_n
            if len(list(out.address_n)):
                out.address = bip32.get_address(coin, list(out.address_n))
                out.ClearField('address_n')

            serialized += outtx.serialize_output(compile_TxOutput(out))

        yield proto.TxRequest(request_type=proto_types.TXFINISHED,
                              serialized=proto_types.TxRequestSerializedType(serialized_tx=serialized))

class SignStateMachine(object):
    def __init__(self, layout, storage, yesno, pin, passphrase):
        self.iface = TrezorIface(layout, storage, yesno, pin, passphrase)
        self.workflow = None

    def estimate_tx_size(self, msg):
        '''This is stub implementation, which will be replaced by exact
        calculation in the future.'''
        est_size = estimate_size(msg.inputs_count, msg.outputs_count)
        return proto.TxSize(tx_size=est_size)

    def process_message(self, msg):
        if isinstance(msg, proto.EstimateTxSize):
            return self.estimate_tx_size(msg)

        if isinstance(msg, proto.SignTx):
            # Start signing process
            self.workflow = StreamingSigningWorkflow(self.iface)
            return self.iface.passphrase.use(self.workflow.start, msg)

        if isinstance(msg, proto.TxAck):
            return self.iface.passphrase.use(self.workflow.process, msg)

        # return Failure message to indicate problems to upstream SM
        return proto.Failure(code=1, message="Signing failed")


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
                                   signature_index=now_signed,
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
                               signature_index=self.signing_index,
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
        return proto.TxRequest(finished=True, serialized_tx=serialized_tx)
    '''
