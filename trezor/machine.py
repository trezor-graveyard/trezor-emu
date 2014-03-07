import time
import random
import hashlib
import traceback
import binascii

import signing
import tools
import messages_pb2 as proto
import types_pb2 as proto_types
import machine_signing
from mnemonic import Mnemonic
from storage import NotInitializedException
from bip32 import BIP32
import coindef

class PinState(object):
    def __init__(self, layout, storage):
        self.layout = layout
        self.storage = storage
        self.matrix = None

        self.set_main_state()

    def set_main_state(self):
        self.cancel()

    def is_waiting(self):
        return self.func is not None

    def _generate_matrix(self):
        # Generate random order of numbers 1-9
        matrix = range(1, 10)
        random.shuffle(matrix)
        return matrix

    def _decode_from_matrix(self, pin_encoded):
        # Receive pin encoded using a matrix
        # Return original PIN sequence
        pin = ''.join([ str(self.matrix[int(x) - 1]) for x in pin_encoded ])
        print "Real PIN", pin
        return pin    
        
    def request(self, msg, pass_or_check, func, *args):

        self.pass_or_check = pass_or_check
        self.func = func
        self.args = args
        self.matrix = self._generate_matrix()

        if not pass_or_check:        
            # We just want to check PIN / authorize user,
            # so we can use PIN cached in session

            if self.storage.is_authorized():
                return self._check(self.storage.session.pin)

        if not msg:
            msg = 'Please enter your PIN:'
        
        self.layout.show_matrix(self.matrix, msg)
        return proto.PinMatrixRequest(message=msg)

    def change(self, is_remove):
        if is_remove:
            self.storage.set_pin('')
            return proto.Success(message="Pin has been succesfully removed")

        return self.request_new(self._change_done)

    def _change_done(self, new_pin):
        self.storage.set_pin(new_pin)
        return proto.Success(message="Pin has been succesfully set")

    def request_new(self, func, *args):
        '''Ask user for new PIN'''
        return self.request('Please enter new PIN:', True, self._request_second, func, args)
        
    def _request_second(self, pin, func, args):
        '''Ask second time for new PIN to confirm user's entry'''
        return self.request('Enter new PIN again:', True, self._request_compare, *[pin, func, args])
        
    def _request_compare(self, pin2, pin1, func, args):
        '''Compare both pins and return if they're the same'''
        if pin2 != pin1:
            raise Exception("Pin is different")
        return func(pin1, *args)
        
    def check(self, pin_encoded):
        try:
            pin = self._decode_from_matrix(pin_encoded)
        except ValueError:
            return proto.Failure(code=proto_types.Failure_SyntaxError, message="Syntax error")
        
        return self._check(pin)

    def _check(self, pin):
        if self.pass_or_check:
            # Pass PIN to method
            func = self.func
            args = self.args[:]
            self.cancel()
            msg = func(pin, *args)
            return msg
        else:
            # Check PIN against device's internal PIN
            if pin == self.storage.get_pin():
                func = self.func
                args = self.args
                self.cancel()
                self.storage.clear_pin_attempt()
                self.storage.session.set_pin(pin)
                msg = func(*args)

                return msg
            else:
                self.storage.increase_pin_attempt()
                print "Invalid PIN, waiting %s seconds" % self.storage.get_pin_delay()
                delay = self.storage.get_pin_delay()
                self.layout.show_pin_backoff_progress(delay)
                self.cancel()
                self.set_main_state()
                return proto.Failure(code=proto_types.Failure_PinInvalid, message="Invalid PIN")

    def cancel(self):
        self.pass_or_check = False
        self.func = None
        self.args = []
        self.matrix = None

class PassphraseState(object):
    def __init__(self, layout, storage):
        self.layout = layout
        self.storage = storage

        self.set_main_state()

    def set_main_state(self):
        self.cancel()

    def is_waiting(self):
        return self.func is not None
    
    def use(self, func, *args):
        '''Check if storage is locked. In that case asks user to provide
        passphrase.'''
        if self.storage.is_locked():
            return self.request('Please enter passphrase', False, func, *args)
        
        return func(*args)
        
    def request(self, msg, pass_or_check, func, *args):
        self.pass_or_check = pass_or_check
        self.func = func
        self.args = args
        self.layout.request_passphrase(msg)
        return proto.PassphraseRequest()
        
    def check(self, passphrase):       
        if self.pass_or_check:
            # Pass passphrase to method
            func = self.func
            args = self.args[:]
            self.cancel()
            msg = func(passphrase, *args)
            return msg
        else:
            # Use passphrase to unlock local storage
            self.storage.unlock(passphrase)
            func = self.func
            args = self.args
            self.cancel()
            msg = func(*args)
            return msg

    def cancel(self):
        self.pass_or_check = False
        self.func = None
        self.args = []

class ResetDeviceState(object):
    def __init__(self, layout, storage, yesno, pin, main_state_func):
        self.layout = layout
        self.storage = storage
        self.yesno = yesno
        self.pin = pin
        self._set_main_state = main_state_func
        self.set_main_state()
        
    def set_main_state(self):
        self.internal_entropy = None
        self.external_entropy = None
        self.strength = None
        self.passphrase_protection = False
        self.pin_protection = False
        self.language = 'english'
        self.label = ''
        self.current_word = None
    
    def is_waiting(self):
        if self.internal_entropy:
            return True
        return False

    def get_debug(self):
        if self.current_word != None:
            return (self.current_word , self.internal_entropy)
        else:
            return ('' , self.internal_entropy)

    def step1(self, display_random, strength, passphrase_protection, pin_protection, language, label):
        '''This starts resetting workflow by generating internal random
        and asking user to confirm device reset.'''
        
        if self.storage.is_initialized():
            return proto.Failure(message="Device is initialized already.")

        self.set_main_state()
        
        print "Starting device reset..."
        internal_entropy = tools.get_local_entropy()
        print "Trezor-generated entropy:", binascii.hexlify(internal_entropy)
        
        if language not in self.storage.get_languages():
            raise Exception("Unsupported language")

        self.internal_entropy = internal_entropy
        self.external_entropy = None
        self.strength = strength
        self.passphrase_protection = passphrase_protection
        self.pin_protection = pin_protection
        self.label = label
        self.language = language
        self.new_pin = None

        if display_random:
            msg = ["_cLocal entropy is", ]
            ent = binascii.hexlify(internal_entropy)
            while ent:
                msg += ["_c%s" % ent[:16], ]
                ent = ent[16:]

            self.layout.show_question(msg, 'Setup device?', 'Next }', '{ Cancel')
            return self.yesno.request(proto_types.ButtonRequest_ResetDevice, self.step2)

        return self.step2()

    def step2(self):
        if self.pin_protection:
            return self.pin.request_new(self.step3)
        else:
            return self.step3('')

    def step3(self, pin):
        if self.pin_protection and not pin:
            raise Exception("Pin need to be provided")

        if self.pin_protection == False:
            pin = ''
        
        self.new_pin = pin
        return proto.EntropyRequest()
    
    def step4(self, external_entropy):
        '''Now the action is confirmed by user and both
        internal and external entropy is generated.
        '''
        self.external_entropy = external_entropy
        print "Computer-generated entropy:", binascii.hexlify(self.external_entropy)
        
        entropy = tools.generate_entropy(self.strength, self.internal_entropy, self.external_entropy)
        mnemonic = Mnemonic(self.language).to_mnemonic(entropy)
        
        pin = self.new_pin
        self.new_pin = None

        if not Mnemonic(self.language).check(mnemonic):
            raise Exception("Unexpected error, mnemonic doesn't pass internal check")
        
        print "Mnemonic:", mnemonic
        return self.step5(pin, mnemonic, 0, first_pass=True)

    def step5(self, pin, mnemonic, mnemonic_index, first_pass):
        '''Display words of mnemonic and ask user to write them down'''
        words = mnemonic.split(' ')
        self.current_word = words[mnemonic_index]

        if first_pass:
            text = ["_cPlease write down",
                    "_c%d/%d" % ((mnemonic_index + 1), len(words)),
                    "_cwords of mnemonic:",
                    "",
                    "_c'%s'" % self.current_word]
        else:
            text = ["_cPlease check that",
                    "_c%d. word" % (mnemonic_index + 1),
                    "_cof your mnemonic is:",
                    "",
                    "_c'%s'" % self.current_word]
            
        mnemonic_index += 1
        if mnemonic_index == len(words):
            if first_pass == True:
                # Print second pass of printing
                self.layout.show_question(text, '', 'Done }', '{ Cancel')
                return self.yesno.request(proto_types.ButtonRequest_ConfirmWord, self.step5, *[pin, mnemonic, 0, False])

            else:
                self.layout.show_question(text, '', 'Done }', '{ Cancel')
                return self.yesno.request(proto_types.ButtonRequest_ConfirmWord, self.step6, *[pin, mnemonic])

        self.layout.show_question(text, '', 'Next }', '{ Cancel')
        return self.yesno.request(proto_types.ButtonRequest_ConfirmWord, self.step5, *[pin, mnemonic, mnemonic_index, first_pass])
        
    def step6(self, pin, mnemonic):
        self.storage.load_device(mnemonic, None, self.language, self.label, pin, self.passphrase_protection)
        self._set_main_state() 
        return proto.Success(message='Device loaded')
        
class RecoveryDeviceState(object):
    def __init__(self, layout, storage, pin, main_state_func):
        self.layout = layout
        self.storage = storage
        self.pin = pin
        self._set_main_state = main_state_func
        
        self.multiplier = 0.5  # 1  # How many fake words use in recovery process
        self.set_main_state()

    def set_main_state(self):
        self.passphrase_protection = False
        self.new_pin = ''
        self.language = None
        self.label = None
        self.enforce_wordlist = False
        self.fake_word = None
        self.pending_request = False
        
        self.sequence = []
        self.mnemonic = []
        self.index = None
        
    def is_waiting(self):
        return self.pending_request

    def step1(self, word_count, passphrase_protection, pin_protection, language,
              label, enforce_wordlist):
        # Reset all internal variable, just for sure
        
        if self.storage.is_initialized():
            return proto.Failure(message="Device is initialized already.")

        self.set_main_state()
        
        if language not in self.storage.get_languages():
            return proto.Failure(message="Unsupported language")

        self.passphrase_protection = passphrase_protection
        self.language = language
        self.label = label
        self.enforce_wordlist = enforce_wordlist
        self.mnemonic = [None] * word_count

        self.generate_sequence(word_count)

        if pin_protection:
            return self.pin.request_new(self.step2)
        else:
            return self.request_word()

        return self.request_word()
    
    def step2(self, new_pin):
        # This is called only if PIN protection is set
        self.new_pin = new_pin
        return self.request_word()

    def generate_sequence(self, word_count):
        self.sequence = range(word_count) + [None] * int(self.multiplier * word_count)
        random.shuffle(self.sequence)
        self.index = 0  # Ask for first word of sequence
        
        print "Generated sequence:", self.sequence
        
    def get_debug(self):
        # Provide current fake word and expected index for debuglink
        pos = self.sequence[self.index]
        if pos == None:
            return (self.fake_word, 0)
        else:
            return ('', pos + 1)

    def request_word(self):
        pos = self.sequence[self.index]
        
        if pos == None:
            # Ask for fake word
            self.fake_word = random.choice(Mnemonic(self.language).wordlist)
            self.layout.show_message(["",
                                      "_cPlease retype word",
                                      "",
                                      "_c'%s'" % self.fake_word])
                
        else:
            # Ask for word from mnemonic
            self.fake_word = ''
            self.layout.show_message(["",
                                      "_cPlease retype",
                                      "_c%d. word" % (pos + 1),
                                      "_cof your mnemonic"])
        
        # Sleep for a moment, this may mislead frequency analysis
        # of retyping words on backdoored computer
        time.sleep(1)
        
        # Flag for state machine and debuglink to report fakeword/pos
        self.pending_request = True
        return proto.WordRequest()

    def process_word(self, word):
        self.pending_request = False
        pos = self.sequence[self.index]

        if self.enforce_wordlist and word not in Mnemonic(self.language).wordlist:
            return proto.Failure(message="This word is not in wordlist")
        
        if pos == None:
            # Word is supposed to be fake
            if word != self.fake_word:
                return proto.Failure(message="Unexpected word")
        else:
            self.mnemonic[pos] = word

        print "Partial mnemonic:", self.mnemonic

        self.index += 1
        if self.index < len(self.sequence):
            return self.request_word()

        # We're done!
        return self.finalize()

    def finalize(self):
        mnemonic = ' '.join(self.mnemonic)
        print "Final mnemonic is", mnemonic

        if not Mnemonic(self.language).check(mnemonic):
            return proto.Failure(message="Invalid mnemonic, are words in correct order?")

        self.storage.load_device(mnemonic, None, self.language,
                                 self.label, self.new_pin, self.passphrase_protection)
        self._set_main_state()
        return proto.Success()

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

    def request(self, code, func, *args):
        self.func = func
        self.args = args
        self.pending = True  # Waiting for confirmation from computer

        # Tell computer that device is waiting for HW buttons
        return proto.ButtonRequest(code=code)
        
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

        func = self.func
        args = self.args
        decision = self.decision
        
        self.cancel()

        if decision is True:
            ret = func(*args)
        else:
            self.set_main_state()
            ret = proto.Failure(code=proto_types.Failure_ActionCancelled, message='Action cancelled by user')

        return ret

class StateMachine(object):
    def __init__(self, storage, layout):
        self.storage = storage
        self.layout = layout

        self.yesno = YesNoState(layout)
        self.pin = PinState(layout, storage)
        self.passphrase = PassphraseState(layout, storage)
        self.sign = machine_signing.SignStateMachine(layout, storage, self.yesno, self.pin, self.passphrase)
        self.simplesign = machine_signing.SimpleSignStateMachine(layout, storage, self.yesno, self.pin, self.passphrase)
        self.reset_device = ResetDeviceState(layout, storage, self.yesno, self.pin, self.set_main_state)
        self.recovery_device = RecoveryDeviceState(layout, storage, self.pin, self.set_main_state)
        self.set_main_state()
    
    def protect_wipe(self):
        self.layout.show_question(["_cReset device to",
                                   "_cfactory defaults?",
                                   "_cAll private data",
                                   "_cwill be removed!"],
                                  'Wipe device?', 'Confirm }', '{ Cancel')

        return self.yesno.request(proto_types.ButtonRequest_WipeDevice, self._wipe_device)


    def protect_call(self, yesno_message, question, no_text, yes_text, func, *args):
        '''
            yesno_message - display text on the main part of the display
            question - short question in status bar (above buttons)
            no_text - text of the left button
            yes_text - text of the right button
            func - which function to call when user passes the protection
            *args - arguments for func
        '''  

        self.layout.show_question(yesno_message, question, yes_text, no_text)

        if self.storage.get_pin():
            # Require hw buttons and PIN
            return self.yesno.request(proto_types.ButtonRequest_ProtectCall, self.pin.request, *['', False, func] + list(args))

        # If confirmed, call final function directly
        return self.yesno.request(proto_types.ButtonRequest_ProtectCall, func, *args)

    def clear_custom_message(self):
        if self.custom_message:
            self.custom_message = False
            self.layout.show_logo(None, self.storage.get_label())

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
        resp.pin = self.storage.get_pin()
        resp.passphrase_protection = self.storage.get_passphrase_protection()
        resp.layout = ''.join([ chr(x) for x in self.layout.buffer.data ])

        if self.pin.is_waiting():
            resp.matrix = ''.join([ str(x) for x in self.pin.matrix ])
        if self.storage.struct.HasField('mnemonic'):
            resp.mnemonic = self.storage.struct.mnemonic
        if self.storage.struct.HasField('node'):
            resp.node.CopyFrom(self.storage.struct.node)

        if self.reset_device.is_waiting():
            (resp.reset_word, resp.reset_entropy) = self.reset_device.get_debug()

        if self.recovery_device.is_waiting():
            (resp.recovery_fake_word, resp.recovery_word_pos) = self.recovery_device.get_debug()

        return resp

    def set_main_state(self):
        # Switch device to default state
        self.yesno.set_main_state()
        self.sign.set_main_state()
        self.simplesign.set_main_state()
        self.pin.set_main_state()
        self.passphrase.set_main_state()
        self.reset_device.set_main_state()
        self.recovery_device.set_main_state()

        # Display is showing custom message which just wait for "Continue" button,
        # but doesn't require any interaction with computer
        self.custom_message = False
    
        if self.storage.is_initialized():
            self.layout.show_logo(None, self.storage.get_label())   
        else:
            self.layout.show_message(
                ["_cDevice hasn't been",
                 "_cinitialized yet.",
                 "_cPlease run setup",
                 "_cfrom desktop client."])
    
    def apply_settings(self, settings):
        message = []
        if settings.HasField('language') and settings.language in self.storage.get_languages():
            message.append('Language: %s' % settings.language)
        else:
            settings.ClearField('language')

        if settings.HasField('label'):
            message.append('Label: %s' % settings.label)
        else:
            settings.ClearField('label')
            
        question = 'Apply these settings?'
        func = self._apply_settings
        args = (settings,)

        return self.protect_call(message, question, '{ Cancel', 'Confirm }', func, *args)
        
    def _apply_settings(self, settings):
        if settings.HasField('language'):
            self.storage.set_language(settings.language)
            
        if settings.HasField('label'):
            self.storage.set_label(settings.label)

        self.set_main_state()
        return proto.Success(message='Settings updated')

    def _wipe_device(self):
        self.storage.wipe_device()
        self.set_main_state()
        return proto.Success()

    def _load_device(self, mnemonic, node, pin, passphrase_protection, language, label, skip_checksum):
        # Use mnemonic OR HDNodeType to initialize the device
        # If both are provided, mnemonic has higher priority

        if self.storage.is_initialized():
            return proto.Failure(message="Device is initialized already.")

        self.storage.load_device(mnemonic, node, language, label, pin, passphrase_protection, skip_checksum=skip_checksum)
        self.set_main_state()
        return proto.Success(message='Device loaded')

    def _get_entropy(self, size):
        random.seed()
        m = proto.Entropy()
        d = ''
        while len(d) < size:
            d += tools.get_local_entropy()

        m.entropy = d[:size]
        self.set_main_state()
        return m

    def _change_pin(self, is_remove):
        msg = "Change existing PIN?"

        if is_remove:
            msg = "Remove existing PIN?"

        elif not self.storage.get_pin():
            msg = "Set new PIN?"

        return self.protect_call([msg], '',
                    '{ Cancel', 'Confirm }', self.pin.change, is_remove)

    def _get_address(self, coin, address_n):
        address = BIP32(self.storage.get_node()).get_address(coin, address_n)
        self.layout.show_receiving_address(address)
        self.custom_message = True  # Yes button will redraw screen
        return proto.Address(address=address)

    def _get_public_key(self, address_n):
        node = BIP32(self.storage.get_node()).get_public_node(address_n)
        return proto.PublicKey(node=node)

    def _ping(self, message, button_protection, pin_protection, passphrase_protection):
        if button_protection:
            self.layout.show_question(['', "_cAnswer to ping?"], '', 'Confirm }', '{ Cancel')
            return self.yesno.request(proto_types.ButtonRequest_Other, self._ping, message, False, pin_protection, passphrase_protection)

        if pin_protection and self.storage.get_pin():
            return self.pin.request('Answer to ping?', False, self._ping,
                    message, button_protection, False, passphrase_protection)
                        
        if passphrase_protection:
            return self.passphrase.use(self._ping, message, button_protection, pin_protection, False)
            
        self.set_main_state()
        return proto.Success(message=message)

    def _sign_message(self, coin, address_n, message):
        try:
            (address, sig) = signing.sign_message(BIP32(self.storage.get_node()), coin, address_n, message)
            return proto.MessageSignature(address=address, signature=sig)
        except:
            return proto.Failure(code=proto_types.Failure_InvalidSignature, message="Cannot sign message")
        
    def _process_message(self, msg):
        if isinstance(msg, proto.Initialize):
            self.set_main_state()
            return self.storage.get_features()

        if self.pin.is_waiting():
            '''PIN response is expected'''
            if isinstance(msg, proto.PinMatrixAck):
                return self.pin.check(msg.pin)

            if isinstance(msg, proto.Cancel):
                self.pin.cancel()
                return proto.Failure(code=proto_types.Failure_PinCancelled, message="PIN request cancelled")

            self.set_main_state()
            return proto.Failure(code=proto_types.Failure_PinExpected, message='PIN expected')

        if self.passphrase.is_waiting():
            '''Passphrase is expected'''
            if isinstance(msg, proto.PassphraseAck):
                return self.passphrase.check(msg.passphrase)
        
        if self.yesno.is_waiting():
            '''Button confirmation is expected'''
            if isinstance(msg, proto.ButtonAck):
                self.yesno.allow()
                return self.yesno.resolve()  # Process if button has been already pressed

            if isinstance(msg, proto.Cancel):
                self.set_main_state()
                return proto.Success(message="Button confirmation cancelled")

            self.set_main_state()
            return proto.Failure(code=proto_types.Failure_ButtonExpected, message='Button confirmation expected')

        if self.reset_device.is_waiting():
            if isinstance(msg, proto.EntropyAck):
                return self.reset_device.step4(msg.entropy)

            self.set_main_state()
            return proto.Failure(code=proto_types.Failure_UnexpectedMessage, message='EntropyAck expected')

        if self.recovery_device.is_waiting():
            if isinstance(msg, proto.Cancel):
                self.set_main_state()
                return self.Failure(message='Recovery cancelled')
            if isinstance(msg, proto.WordAck):
                return self.recovery_device.process_word(msg.word)

        if isinstance(msg, proto.Ping):
            return self._ping(msg.message, msg.button_protection, msg.pin_protection, msg.passphrase_protection)

        if isinstance(msg, proto.FirmwareUpload):
            if msg.payload[:4] != 'TRZR':
                return proto.Failure(code=proto_types.Failure_SyntaxError, message='Firmware header expected')
            return proto.Success(message='%d bytes of firmware succesfully uploaded' % len(msg.payload))

        if isinstance(msg, proto.GetEntropy):
            self.layout.show_question(['', "_cSend sample entropy", "_cof %d bytes" % msg.size, "_cto computer?"],
                                      '', 'Confirm }', '{ Cancel')
            return self.yesno.request(proto_types.ButtonRequest_Other, self._get_entropy, *[msg.size])

        if isinstance(msg, proto.GetPublicKey):
            return self.passphrase.use(self._get_public_key, list(msg.address_n))

        if isinstance(msg, proto.GetAddress):
            return self.passphrase.use(self._get_address, coindef.types[msg.coin_name], list(msg.address_n))
        
        if isinstance(msg, proto.ChangePin):
            return self._change_pin(msg.remove)

        if isinstance(msg, proto.ApplySettings):
            return self.apply_settings(msg)

        if isinstance(msg, proto.WipeDevice):
            return self.protect_wipe()
        
        if isinstance(msg, proto.LoadDevice):
            return self._load_device(msg.mnemonic, msg.node, msg.pin, msg.passphrase_protection,
                        msg.language, msg.label, msg.skip_checksum)

        if isinstance(msg, proto.ResetDevice):
            return self.reset_device.step1(msg.display_random, msg.strength, msg.passphrase_protection, msg.pin_protection, msg.language, msg.label)
        
        if isinstance(msg, proto.RecoveryDevice):
            return self.recovery_device.step1(msg.word_count, msg.passphrase_protection, msg.pin_protection,
                                      msg.language, msg.label, msg.enforce_wordlist)

        if isinstance(msg, proto.SignMessage):
            return self.protect_call([msg.message[:21],
                                      msg.message[21:42],
                                      msg.message[42:63],
                                      msg.message[63:84],
                                      msg.message[84:105]],
                                     'Sign this message?', '{ Cancel', 'Confirm }',
                                     self.passphrase.use, self._sign_message,
                                     coindef.types[msg.coin_name], list(msg.address_n), msg.message)

        if isinstance(msg, proto.VerifyMessage):
            try:
                signing.verify_message(msg.address, msg.signature, msg.message)
                self.layout.show_verified_message(msg.address, msg.message)
                self.custom_message = True  # Yes button will redraw screen
                return proto.Success()
            except:
                return proto.Failure(code=proto_types.Failure_InvalidSignature, message="Invalid signature")

        if isinstance(msg, proto.SimpleSignTx):
            return self.simplesign.process_message(msg)

        if isinstance(msg, (proto.EstimateTxSize, proto.SignTx, proto.TxInput, proto.TxOutput)):
            return self.sign.process_message(msg)

        self.set_main_state()
        return proto.Failure(code=proto_types.Failure_UnexpectedMessage, message="Unexpected message")

    def _process_debug_message(self, msg):
        if isinstance(msg, proto.DebugLinkGetState):
            # Report device state
            return self.debug_get_state(msg)

        if isinstance(msg, proto.DebugLinkStop):
            import sys
            sys.exit()

        self.set_main_state()
        return proto.Failure(code=proto_types.Failure_UnexpectedMessage, message="Unexpected message")

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
