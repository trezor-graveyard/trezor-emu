import time
import random
import traceback

import bitkey_pb2 as proto
import machine_signing
from wallet import NoSeedException


class PinState(object):
    def __init__(self, layout, wallet):
        self.layout = layout
        self.wallet = wallet

        self.set_main_state()

    def set_main_state(self):
        self.cancel()

    def is_waiting(self):
        return self.func is not None

    def request(self, message, pass_or_check, func, *args):
        self.pass_or_check = pass_or_check
        self.func = func
        self.args = args

        self.layout.show_pin_request()
        if message is not None:
            return proto.PinRequest(message=message)
        else:
            return proto.PinRequest()

    def check(self, pin):
        if self.pass_or_check:
            # Pass PIN to method
            msg = self.func(pin, *self.args)
            self.cancel()
            return msg
        else:
            # Check PIN against device's internal PIN
            if pin == self.wallet.struct.pin:
                msg = self.func(*self.args)
                self.cancel()
                return msg
            else:
                time.sleep(3)
                self.cancel()
                self.set_main_state()
                return proto.Failure(code=6, message="Invalid PIN")

    def cancel(self):
        self.pass_or_check = False
        self.func = None
        self.args = []


class OtpState(object):
    def __init__(self, layout):
        self.layout = layout

        self.set_main_state()

    def set_main_state(self):
        self.cancel()

    def is_waiting(self):
        return self.otp is not None

    def request(self, message, func, *args):
        def generate():
            # Removed l and 0
            #return ''.join(random.choice('abcdefghijkmnopqrstuvwxyz123456789') for _ in range(4))
            #return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(4))
            return ''.join(random.choice('0123456789') for _ in range(6))

        self.otp = generate()
        self.func = func
        self.args = args
        if message is not None:
            m = proto.OtpRequest(message=message)
        else:
            m = proto.OtpRequest()

        self.layout.show_otp_request(self.otp)
        return m

    def check(self, otp):
        # OTP is displayed with spaces, but they aren't significant
        otp = otp.replace(' ', '')

        if otp == self.otp:
            msg = self.func(*self.args)
            self.cancel()
            return msg
        else:
            time.sleep(3)
            self.cancel()
            self.set_main_state()
            return proto.Failure(code=3, message="Invalid OTP")

    def cancel(self):
        self.otp = None
        self.func = None
        self.args = []


class YesNoState(object):
    def __init__(self, layout):
        self.layout = layout

        self.set_main_state()

    def set_main_state(self):
        self.cancel()

    def is_waiting(self):
        # We're waiting for confirmation from computer
        return self.func is not None and self.pending

    def allow(self):
        # Computer confirms that we can accept button press now
        self.pending = False

    def cancel(self):
        self.pending = False
        self.decision = None
        self.func = None
        self.args = []

    def request(self, message, question, yes_text, no_text, func, *args):
        self.layout.show_question(message, question, yes_text, no_text)

        self.func = func
        self.args = args
        self.pending = True  # Waiting for confirmation from computer

        # Tell computer that device is waiting for HW buttons
        return proto.ButtonRequest()

    def store(self, button):
        if not self.func:
            return

        self.decision = button

    def resolve(self):
        if not self.func:
            # We're not waiting for hw buttons
            return

        if self.pending:
            # We still didn't received ButtonAck from computer
            return

        if self.decision is None:
            # We still don't know user's decision (call yesno_store() firstly)
            return

        if self.decision is True:
            ret = self.func(*self.args)
        else:
            self.set_main_state()
            ret = proto.Failure(code=4, message='Action cancelled by user')

        self.func = None
        self.args = []
        return ret


class StateMachine(object):
    def __init__(self, wallet, layout):
        self.wallet = wallet
        self.layout = layout

        self.yesno = YesNoState(layout)
        self.otp = OtpState(layout)
        self.pin = PinState(layout, wallet)
        self.signing = machine_signing.SigningStateMachine(layout, wallet)

        self.set_main_state()

    def protect_reset(self, yesno_message, question, yes_text, no_text, otp_message, random):
        # FIXME

        if self.wallet.struct.has_otp:
            # Require hw buttons and OTP
            return self.yesno.request(yesno_message, question, yes_text, no_text,
                                      self.otp.request, *[otp_message, self._reset_wallet] + [random, ])

        # If confirmed, call final function directly
        return self.yesno.request(yesno_message, question, yes_text, no_text, self._reset_wallet, *[random, ])

    def protect_call(self, yesno_message, question, no_text, yes_text,
                     otp_message, pin_message, func, *args):
        # FIXME: Um, maybe it needs some simplification?

        if self.wallet.struct.has_otp:
            if self.wallet.struct.pin:
                # Require hw buttons, OTP and PIN
                return self.yesno.request(yesno_message, question, yes_text, no_text, self.otp.request,
                                          *[otp_message, self.pin.request, pin_message, False, func] + list(args))
            else:
                # Require hw buttons and OTP
                return self.yesno.request(yesno_message, question, yes_text, no_text, self.otp.request,
                                          *[otp_message, func] + list(args))
        elif self.wallet.struct.pin:
            # Require hw buttons and PIN
            return self.yesno.request(yesno_message, question, yes_text, no_text, self.pin.request,
                                      *[pin_message, False, func] + list(args))

        # If confirmed, call final function directly
        return self.yesno.request(yesno_message, question, yes_text, no_text, func, *args)

    def clear_custom_message(self):
        if self.custom_message:
            self.custom_message = False
            self.layout.show_logo()

    def press_button(self, button):
        if button and self.custom_message:
            self.clear_custom_message()

        self.yesno.store(button)
        ret = self.yesno.resolve()
        if isinstance(ret, proto.Failure):
            self.set_main_state()
        return ret

    def debug_get_state(self, msg):
        resp = proto.DebugLinkState()
        if msg.otp and self.otp.is_waiting():
            resp.otp.otp = self.otp.otp
        if msg.pin and self.pin.is_waiting():
            resp.pin.pin = self.wallet.struct.pin
        return resp

    def set_main_state(self):
        # Switch device to default state
        self.yesno.set_main_state()
        self.otp.set_main_state()
        self.signing.set_main_state()
        self.pin.set_main_state()

        # Display is showing custom message which just wait for "Continue" button,
        # but doesn't require any interaction with computer
        self.custom_message = False

        try:
            #self.wallet.get_secexp()
            self.layout.show_logo()
        except NoSeedException:
            self.layout.show_message(
                ["Device hasn't been",
                 "initialized yet.",
                 "Please initialize it",
                 "from desktop client."])

    def debug_load_wallet(self, algo, seed_words, otp, pin, spv):
        self.wallet.load_seed(seed_words)
        self.wallet.struct.algo = algo
        self.wallet.struct.has_otp = otp
        self.wallet.struct.pin = pin
        self.wallet.struct.has_spv = spv
        self.wallet.save()
        return proto.Success(message='Wallet loaded')

    def _reset_wallet(self, random):
        # TODO
        print "Starting setup wizard..."
        # self.wallet.save()
        return proto.Success()

    '''
        is_otp = self.yesno("Use OTP?")
        is_spv = self.yesno("Use SPV?")
        is_pin = self.yesno("Use PIN?")

        if is_pin:
            return self.pin_request("Please enter new PIN", True, self._reset_wallet2, random, is_otp, is_spv)

        return self._reset_wallet2('', random, is_otp, is_spv)

    def _reset_wallet2(self, random, pin, is_otp, is_spv):
        self.device.set_pin(pin)
        self.device.set_otp(is_otp)
        self.device.set_spv(is_spv)

        seed = tools.generate_seed(random)
        seed_words = tools.get_mnemonic(seed)
        self.device.load_seed(seed_words)

        print "PIN:", pin
        print "Seed:", seed
        print "Mnemonic:", seed_words
        print "Write down your seed and keep it secret!"

        return proto.Success()
'''

    def _get_entropy(self, size):
        random.seed()
        m = proto.Entropy()
        m.entropy = ''.join([chr(random.randrange(0, 255, 1)) for _ in xrange(0, size)])
        self.set_main_state()
        return m

    def _process_message(self, msg):
        if isinstance(msg, proto.Initialize):
            self.set_main_state()
            m = self.wallet.get_features()
            m.session_id = msg.session_id
            return m

        if self.otp.is_waiting():
            '''OTP response is expected'''
            if isinstance(msg, proto.OtpAck):
                return self.otp.check(msg.otp)

            if isinstance(msg, proto.OtpCancel):
                self.otp.cancel()
                return proto.Success(message="OTP cancelled")

            self.set_main_state()
            return proto.Failure(code=2, message='OTP expected')

        if self.pin.is_waiting():
            '''PIN response is expected'''
            if isinstance(msg, proto.PinAck):
                return self.pin.check(msg.pin)

            if isinstance(msg, proto.PinCancel):
                self.pin_cancel()
                return proto.Success(message="PIN request cancelled")

            self.set_main_state()
            return proto.Failure(code=5, message='PIN expected')

        if self.yesno.is_waiting():
            '''Button confirmation is expected'''
            if isinstance(msg, proto.ButtonAck):
                self.yesno.allow()
                return self.yesno.resolve()  # Process if button has been already pressed

            if isinstance(msg, proto.ButtonCancel):
                self.set_main_state()
                return proto.Success(message="Button confirmation cancelled")

            self.set_main_state()
            return proto.Failure(code=2, message='Button confirmation expected')

        if isinstance(msg, proto.Ping):
            return proto.Success(message=msg.message)

        if isinstance(msg, proto.GetUUID):
            return proto.UUID(UUID=self.wallet.get_UUID())

        if isinstance(msg, proto.GetEntropy):
            return self.protect_call(["Send %d bytes" % msg.size, "of entropy", "to computer?"], '',
                                     '{ Cancel', 'Confirm }', None, None, self._get_entropy, msg.size)

        if isinstance(msg, proto.GetMasterPublicKey):
            return proto.MasterPublicKey(key=self.wallet.get_master_public_key())

        if isinstance(msg, proto.GetAddress):
            address = self.wallet.get_address(list(msg.address_n))
            self.layout.show_receiving_address(address)
            self.custom_message = True  # Yes button will redraw screen
            return proto.Address(address=address)

        if isinstance(msg, proto.SetMaxFeeKb):
            return self.protect_call(["Current maximal fee",
                                     "is %s per kB." % self.wallet.maxfee_kb,
                                     "Set transaction fee",
                                     "to %s per kB?" % msg.maxfee_kb],
                                     '', '{ Cancel', 'Confirm }',
                                     None, None,
                                     self._set_maxfee_kb, msg.maxfee_kb)

        if isinstance(msg, proto.ResetDevice):
            return self.protect_reset("Reset device?", '', '{ Cancel', 'Confirm }', None, msg.random)

        if isinstance(msg, (proto.SignTx, proto.TxInput, proto.TxOutput)):
            return self.signing.process_message(msg)

        self.set_main_state()
        return proto.Failure(code=1, message="Unexpected message")

    def _process_debug_message(self, msg):
        if isinstance(msg, proto.DebugLinkGetState):
            # Report device state
            return self.debug_get_state(msg)

        if isinstance(msg, proto.LoadDevice):
            return self.debug_load_wallet(msg.algo, msg.seed, msg.otp, msg.pin, msg.spv)

        self.set_main_state()
        return proto.Failure(code=1, message="Unexpected message")

    def process_message(self, msg):
        # Any exception thrown during message processing
        # will result in Failure message instead of application crash
        try:
            ret = self._process_message(msg)
            if isinstance(ret, proto.Failure):
                self.set_main_state()
            return ret
        except Exception as exc:
            traceback.print_exc()
            self.set_main_state()
            return proto.Failure(message=str(exc))

    def process_debug_message(self, msg):
        # Process messages handled by debugging connection
        try:
            return self._process_debug_message(msg)
        except Exception as exc:
            traceback.print_exc()
            self.set_main_state()
            return proto.Failure(message=str(exc))
