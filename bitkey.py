#!/usr/bin/python
import random
import time
import json

import tools
from bitkey_proto import bitkey_pb2 as proto
from transport_pipe import PipeTransport
from transport_serial import SerialTransport
from algo import AlgoFactory

'''
    Failure codes:
        1 - Unknown method
        2 - Waiting to OTP
        3 - Invalid OTP 
        4 - Cancelled by user ("no" button)
        5 - Waiting to PIN
        6 - Invalid PIN
'''
class Device(object):
    def __init__(self):
        self.seed = ''
        self.version = 'sim/0.1'
        self.otp = False
        self.spv = False
        self.pin = ''
        self.algo = [proto.ELECTRUM,]
        
    @classmethod    
    def load(cls, filename):
        data = json.load(open(filename, 'r'))
        dev = Device()
        dev.seed = str(data['seed'])
        dev.otp = data['otp']
        dev.spv = data['spv']
        dev.pin = data['pin']
        return dev
        
    def save(self, filename):
        data = {}
        data['seed'] = self.seed
        data['otp'] = self.otp
        data['spv'] = self.spv
        data['pin'] = self.pin
        json.dump(data, open(filename, 'w'))
        
    def get_master_public_key(self, algo):
        af = AlgoFactory(algo)
        master_public_key = af.init_master_public_key(self.seed)
        af.get_new_address(master_public_key, 0)
        return master_public_key
    
    def get_mnemonic(self):
        return tools.get_mnemonic(self.seed)
                    
    def load_seed(self, seed_words):
        self.seed = tools.get_seed(seed_words)
        print 'seed', self.seed
        print self.get_mnemonic()
        
    def set_otp(self, is_otp):
        self.otp = is_otp
    
    def set_pin(self, pin):
        self.pin = pin
    
    def set_spv(self, spv):
        self.spv = spv
        
    def sign_tx(self, algo):
        # TODO
        pass
    
class MessageBroker(object):
    def __init__(self, device):
        self.device = device
        # Setup internal variables for OTP handshake
        self.otp_cancel()
        self.pin_cancel()
        
    def yesno(self, question):
        return raw_input("%s (y/n) " % question) == 'y'
        
    def pin_request(self, message, pass_or_check, func, *args):
        self.pin_pass_or_check = pass_or_check
        self.pin_func = func
        self.pin_args = args
        
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
            if pin == self.device.pin:
                msg = self.pin_func(*self.pin_args)
                self.pin_cancel()
                return msg
            else:
                time.sleep(3)
                self.pin_cancel()
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
        
        print "OTP:", self.otp
        return m
        
    def otp_check(self, otp):
        if otp == self.otp:
            msg = self.otp_func(*self.otp_args)
            self.otp_cancel()
            return msg
        else:
            time.sleep(3)
            self.otp_cancel()
            return proto.Failure(code=3, message="Invalid OTP")
    
    def otp_cancel(self):
        self.otp = None
        self.otp_func = None
        self.otp_args = []
            
    def _get_entropy(self, size):
        random.seed()
        m = proto.Entropy()
        m.entropy = ''.join([ chr(random.randrange(0, 255, 1)) for _ in xrange(0, size) ])
        return m

    def _load_device(self, seed_words, otp, pin, spv):
        self.device.load_seed(seed_words)
        self.device.set_otp(otp)
        self.device.set_pin(pin)
        self.device.set_spv(spv)
        return proto.Success()

    def _reset_device(self):
        print "Starting setup wizard..."

        is_otp = raw_input("Use OTP? (y/n) ") == 'y'
        is_spv = raw_input("Use SPV? (y/n) ") == 'y'
        is_pin = raw_input("Use PIN? (y/n) ") == 'y'
        
        if is_pin:
            return self.pin_request("Please enter new PIN", True, self._reset_device2, is_otp, is_spv)
        
        return self._reset_device2('', is_otp, is_spv)
            
    def _reset_device2(self, pin, is_otp, is_spv):        
        self.device.set_pin(pin)
        self.device.set_otp(is_otp)
        self.device.set_spv(is_spv)
        
        seed = tools.generate_seed()
        seed_words = tools.get_mnemonic(seed)
        self.device.load_seed(seed_words)
        
        print "PIN:", pin
        print "Seed:", seed
        print "Mnemonic:", seed_words
        print "Write down your seed and keep it secret!"

        return proto.Success()
    
    def _sign_tx(self, *args):
        self.device.sign_tx()
        return proto.SignedTx(tx='signed transaction')
    
    def process_message(self, msg):
        if self.otp != None:
            '''OTP response is expected'''
            
            if isinstance(msg, proto.OtpAck):
                return self.otp_check(msg.otp)
        
            if isinstance(msg, proto.OtpCancel):
                self.otp_cancel()
                return proto.Success(message="OTP cancelled")
            
            return proto.Failure(code=2, message='Waiting for OTP')
            
        if self.pin_func != None:
            '''PIN response is expected'''
            if isinstance(msg, proto.PinAck):
                return self.pin_check(msg.pin)
            
            if isinstance(msg, proto.PinCancel):
                self.pin_cancel()
                return proto.Success(message="PIN request cancelled")
            
            return proto.Failure(code=5, message='Waiting for PIN')
        
        if isinstance(msg, proto.Initialize):
            m = proto.Features()
            m.version = self.device.version
            m.otp = self.device.otp == True
            m.pin = self.device.pin != ''
            m.spv = self.device.spv == True
            m.algo.extend(self.device.algo)
            return m
        
        if isinstance(msg, proto.Ping):
            return proto.Success()
    
        if isinstance(msg, proto.GetUUID):
            return proto.UUID(UUID='device-UUID')
                
        if isinstance(msg, proto.GetEntropy):
            if not self.yesno("Send %d bytes of entropy to computer?" % msg.size):
                return proto.Failure(code=4, message='Action cancelled by user')
            if self.device.otp:
                return self.otp_request(None, self._get_entropy, msg.size)
            return self._get_entropy(msg.size)
    
        if isinstance(msg, proto.GetMasterPublicKey):
            return proto.MasterPublicKey(key=self.device.get_master_public_key(msg.algo))

        if isinstance(msg, proto.LoadDevice):
            if not self.yesno("Load device with custom seed?"):
                return proto.Failure(code=4, message='Action cancelled by user')
            if self.device.otp:
                return self.otp_request(None, self._load_device, msg.seed, msg.otp, msg.pin, msg.spv)
            return self._load_device(msg.seed, msg.otp, msg.pin, msg.spv)
            
        if isinstance(msg, proto.ResetDevice):
            if not self.yesno("Reset device?"):
                return proto.Failure(code=4, message='Action cancelled by user')
            if self.device.otp:
                return self.otp_request(None, self._reset_device)

            return self._reset_device()
            
        if isinstance(msg, proto.SignTx):
            print "<TODO: Print transaction details>"
            if not self.yesno("Sign transaction?"):
                return proto.Failure(code=4, message='Action cancelled by user')
            if self.device.otp:
                return self.otp_request(None, self._sign_tx, msg.algo)
            return self._sign_tx(msg.algo)
        
        return proto.Failure(code=1, message='Unknown method')
        
def loop(broker):
    while True:
        msg = client.read()
        print "Received:", msg.__class__
        resp = broker.process_message(msg)
        print "Sent:", resp.__class__
        client.write(resp)

if __name__ == '__main__':
    #client = PipeTransport('device.socket', is_device=True)
    client = SerialTransport('COM8')

    try:
        print "Loading device..."
        device = Device.load('device.dat')
        print "Using seed:", device.get_mnemonic()
    except IOError:
        print "Load failed, starting with new device configuration..."
        device = Device()
    
    if device.seed == '':
        print "This device hasn't been initialized yet. Please initialize it in desktop client."
        
    #device.get_master_public_key(proto.ELECTRUM)
    #print tools.SecretToASecret(AlgoFactory(proto.ELECTRUM).get_private_key(device.seed, 0))
    
    broker = MessageBroker(device)        
    try:
        loop(broker)
    except KeyboardInterrupt:
        client.close()
        
    device.save('device.dat')