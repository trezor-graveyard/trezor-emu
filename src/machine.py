import time
import random

import tools
import bitkey_pb2 as proto
from logo import logo

class StateMachine(object):
    def __init__(self, wallet, layout, is_debuglink):
        self.wallet = wallet
        self.layout = layout
        self.is_debuglink = is_debuglink

        self.set_main_state()
                    
    def pin_request(self, message, pass_or_check, func, *args):
        self.pin_pass_or_check = pass_or_check
        self.pin_func = func
        self.pin_args = args
        
        #self.debug_transport.write(proto.PinAck(pin=self.device.pin))
            
        self.layout.show_pin_request()
        if message != None:
            return proto.PinRequest(message=message)
        else:
            return proto.PinRequest()
    
    def pin_check(self, pin):
        if self.pin_pass_or_check:
            # Pass PIN to method
            msg = self.pin_func(pin, *self.pin_args)
            self.pin_cancel()
            return msg
        else:
            # Check PIN against device's internal PIN
            if pin == self.wallet.pin:
                msg = self.pin_func(*self.pin_args)
                self.pin_cancel()
                return msg
            else:
                time.sleep(3)
                self.pin_cancel()
                self.set_main_state()
                return proto.Failure(code=6, message="Invalid PIN")
    
    def pin_cancel(self):
        self.pin_pass_or_check = False
        self.pin_func = None
        self.pin_args = []

    def otp_request(self, message, func, *args):
        def generate():
            # Removed l and 0
            return ''.join(random.choice('abcdefghijkmnopqrstuvwxyz123456789') for _ in range(4))
            #return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(4))
        
        self.otp = generate()
        self.otp_func = func
        self.otp_args = args
        if message != None:
            m = proto.OtpRequest(message=message)
        else:
            m = proto.OtpRequest()

        self.layout.show_otp_request(self.otp)
        return m
        
    def otp_check(self, otp):
        if otp == self.otp:
            msg = self.otp_func(*self.otp_args)
            self.otp_cancel()
            return msg
        else:
            time.sleep(3)
            self.otp_cancel()
            self.set_main_state()
            return proto.Failure(code=3, message="Invalid OTP")
    
    def otp_cancel(self):
        self.otp = None
        self.otp_func = None
        self.otp_args = []
    
    def yesno_cancel(self):
        self.yesno_pending = False
        self.yesno_decision = None
        self.yesno_func = None
        self.yesno_args = []
        
    def yesno_request(self, message, question, yes_text, no_text, func, *args):
        self.layout.show_question(message, question, yes_text, no_text)
        
        self.yesno_func = func
        self.yesno_args = args
        self.yesno_pending = True # Waiting for confirmation from computer
        
        # Tell computer that device is waiting for HW buttons
        return proto.ButtonRequest()
        
    def yesno_store(self, button):
        if not self.yesno_func:
            return

        self.yesno_decision = button
        
    def yesno_resolve(self):
        if not self.yesno_func:
            # We're not waiting for hw buttons
            return
        
        if self.yesno_pending:
            # We still didn't received ButtonAck from computer
            return
        
        if self.yesno_decision == None:
            # We still don't know user's decision (call yesno_store() firstly)
            return
        
        button = self.yesno_decision
        if button == True:
            ret = self.yesno_func(*self.yesno_args)
        else:
            self.set_main_state()
            ret = proto.Failure(code=4, message='Action cancelled by user')
            
        self.yesno_func = None
        self.yesno_args = []
        return ret
        
    def protect_call(self, yesno_message, question, yes_text, no_text,
                     otp_message, pin_message, func, *args):
        # Um, maybe it needs some simplification?
        
        if self.wallet.otp:
            if self.wallet.pin:
                # Require hw buttons, OTP and PIN
                return self.yesno_request(yesno_message, question, yes_text, no_text,
                            self.otp_request, *[otp_message, self.pin_request, pin_message, False, func]+list(args))
            else:
                # Require hw buttons and OTP
                return self.yesno_request(yesno_message, question, yes_text, no_text,
                            self.otp_request, *[otp_message, func]+list(args))
        elif self.wallet.pin:
            # Require hw buttons and PIN
            return self.yesno_request(yesno_message, question, yes_text, no_text,
                self.pin_request, *[pin_message, False, func]+list(args))
                
        # If confirmed, call final function directly
        return self.yesno_request(yesno_message, question, yes_text, no_text, func, *args)
    
    def press_button(self, button):
        if button and self.custom_message:
            self.clear_custom_message()
            
        self.yesno_store(button)
        return self.yesno_resolve()
    
    def get_state(self, msg):
        resp = proto.DebugLinkState()
        if msg.otp and self.otp != None:
            resp.otp.otp = self.otp
        if msg.pin and self.pin_func != None:
            resp.pin.pin = self.wallet.pin
        return resp

    def clear_custom_message(self):
        if self.custom_message:
            self.custom_message = False
            self.layout.show_logo(logo)
            
    def set_main_state(self):
        # Switch device to default state
        self.yesno_cancel()
        self.otp_cancel()
        self.pin_cancel()

        # Display is showing custom message which just wait for "Continue" button,
        # but doesn't require any interaction with computer
        self.custom_message = False
        
        try:
            self.wallet.get_seed()
            self.layout.show_logo(logo)
        except:
            raise
            self.layout.show_message(
                ["Device hasn't been",
                 "initialized yet.",
                 "Please initialize it",
                 "from desktop client."])

    def _load_wallet(self, seed_words, otp, pin, spv):
        self.wallet.load_seed(seed_words)
        self.wallet.otp = otp
        self.wallet.pin = pin
        self.wallet.spv = spv
        return proto.Success(message='Wallet loaded')
    
    def _reset_wallet(self, random):
        print "Starting setup wizard..."
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
        m.entropy = ''.join([ chr(random.randrange(0, 255, 1)) for _ in xrange(0, size) ])
        self.set_main_state()
        return m 
          
    def _sign_tx(self, tx):
        #self.device.sign_tx(algo=tx.algo, inputs=tx.inputs, output=tx.output)
        return proto.Success()
        
    def process_message(self, msg):
        if isinstance(msg, proto.Initialize):
            self.set_main_state()
            
            m = proto.Features()
            m.session_id = msg.session_id
            m.vendor = self.wallet.vendor
            m.major_version = self.wallet.major_version
            m.minor_version = self.wallet.minor_version
            m.otp = self.wallet.otp == True
            m.pin = self.wallet.pin != ''
            m.spv = self.wallet.spv == True
            m.algo.extend(self.wallet.algo)
            m.maxfee_kb = self.wallet.maxfee_kb
            m.debug_link = self.is_debuglink
            return m
        
        if self.otp != None:
            '''OTP response is expected'''
            if isinstance(msg, proto.OtpAck):
                return self.otp_check(msg.otp)
        
            if isinstance(msg, proto.OtpCancel):
                self.otp_cancel()
                return proto.Success(message="OTP cancelled")
            
            self.set_main_state()
            return proto.Failure(code=2, message='OTP expected')
            
        if self.pin_func != None:            
            '''PIN response is expected'''
            if isinstance(msg, proto.PinAck):
                return self.pin_check(msg.pin)
            
            if isinstance(msg, proto.PinCancel):
                self.pin_cancel()
                return proto.Success(message="PIN request cancelled")
            
            self.set_main_state()
            return proto.Failure(code=5, message='PIN expected')
        
        if self.yesno_pending:
            if isinstance(msg, proto.ButtonAck):
                self.yesno_pending = False # Now we can accept the button press
                return self.yesno_resolve() # Process if button has been already pressed
            
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
            return self.protect_call(["Send %d bytes" % msg.size, "of entropy", "to computer?"],
                                      '', '{ Cancel', 'Confirm }',
                                     None, None,
                                     self._get_entropy, msg.size)

        if isinstance(msg, proto.GetMasterPublicKey):
            return proto.MasterPublicKey(key=self.wallet.get_master_public_key(msg.algo))
    
        if isinstance(msg, proto.GetAddress):
            address = self.wallet.get_address(msg.algo, list(msg.address_n))
            self.layout.show_receiving_address(address)
            self.custom_message = True # Yes button will redraw screen
            return proto.Address(address=address)
    
        if isinstance(msg, proto.SetMaxFeeKb):
            return self.protect_call(["Current maximal fee",
                                     "is %s per kB." % self.wallet.maxfee_kb,
                                     "Set transaction fee",
                                     "to %s per kB?" % msg.maxfee_kb],
                                     '', '{ Cancel', 'Confirm }',
                                     None, None,
                                     self._set_maxfee_kb, msg.maxfee_kb)    
            
        if isinstance(msg, proto.LoadDevice):
            return self.protect_call(["Load device with", "custom seed?"],
                                     '', '{ Cancel', 'Confirm }',
                                     None, None,
                                     self._load_wallet, msg.seed, msg.otp, msg.pin, msg.spv)
            
        if isinstance(msg, proto.ResetDevice):
            return self.protect_call("Reset device?",
                                     '', '{ Cancel', 'Confirm }',
                                     None, None,
                                     self._reset_wallet, msg.random)
            
        if isinstance(msg, proto.SignTx):
            print "<TODO: Print transaction details>"
            return self.protect_call("Sign transaction?",
                                     '', '{ Cancel', 'Confirm }',
                                     None, None,
                                     self._sign_tx, msg)
        
        self.set_main_state()
        return proto.Failure(code=1, message="Unexpected message")
