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
        signature = None

        outtx = StreamTransactionSerialize(msg.inputs_count, msg.outputs_count,
                                           version, lock_time)

        # foreach I:
        for i in range(msg.inputs_count):
            # Request I
            req = proto.TxRequest(request_type=proto_types.TXINPUT,
                                  details=proto_types.TxRequestDetailsType(request_index=i),
                                  serialized=proto_types.TxRequestSerializedType(
                                                        serialized_tx=serialized))
            
            if signature:
                # Fill values from previous round
                req.serialized.signature = signature
                req.serialized.signature_index = i - 1

            serialized = ''

            ret = yield req
            inp = ret.tx.inputs[0]

            # ----------- Calculate amount of I:
            amount = None

            # Request prevhash I, META
            ret = yield(proto.TxRequest(request_type=proto_types.TXMETA,
                    details=proto_types.TxRequestDetailsType(
                        tx_hash=inp.prev_hash)))
            
            amount_hash = StreamTransactionHash(ret.tx.inputs_cnt, ret.tx.outputs_cnt,
                                                version, lock_time)
            # foreach prevhash I:
            for i2 in range(ret.tx.inputs_cnt):
                # Request prevhash I
                ret2 = yield(proto.TxRequest(request_type=proto_types.TXINPUT,
                        details=proto_types.TxRequestDetailsType(
                            request_index=i2, tx_hash=inp.prev_hash)))
                amount_hash.serialize_input(ret2.tx.inputs[0])

            # foreach prevhash O:
            for o2 in range(ret.tx.outputs_cnt):
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
            
            # Add META to StreamTransactionSign
            sign = StreamTransactionSign(i, msg.inputs_count, msg.outputs_count,
                                         version, lock_time)

            # foreach I:
            for i2 in range(msg.inputs_count):
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
                    sign.serialize_input(ret2.tx.inputs[0], address, secexp)
                else:
                    # Add I to StreamTransactionSign
                    sign.serialize_input(ret2.tx.inputs[0])

            # foreach O:
            out_change = None
            for o2 in range(msg.outputs_count):
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
                sign.serialize_output(compile_TxOutput(out))

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
        for o2 in range(msg.outputs_count):
            # Request O
            req = proto.TxRequest(request_type=proto_types.TXOUTPUT,
                    details=proto_types.TxRequestDetailsType(request_index=o2),
                    serialized=proto_types.TxRequestSerializedType(serialized_tx=serialized))

            if signature:
                # Fill signature of last input
                req.serialized.signature = signature
                req.serialized.signature_index = i - 1
                signature = None

            serialized = ''

            ret2 = yield req
                
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
