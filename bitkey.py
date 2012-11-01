#!/usr/bin/python
import random
import time
import pickle

import tools
from bitkey_proto import bitkey_pb2 as proto
from transport_pipe import PipeTransport

'''
    Failure codes:
        1 - Unknown method
        2 - Waiting to OTP
        3 - Invalid OTP 
        4 - Cancelled by user ("no" button)
'''
class Device(object):
    def __init__(self):
        self.seed = ''
        self.version = 'sim/0.1'
        self.otp = False
        self.spv = False
        self.pin = ''
            
    def get_master_public_key(self):
        master_public_key = tools.init_master_public_key(self.seed)
        tools.get_new_address(master_public_key, 0)
        tools.get_new_address(master_public_key, 1)
        return master_public_key
    
    def get_mnemonic(self):
        return tools.get_mnemonic(self.seed)
            
    def reset(self):
        print "Starting setup wizard..."
        
        self.otp = raw_input("Use OTP? (y/n) ") == 'y'
        self.pin = raw_input("Enter PIN (blank=disable): ")
        self.spv = raw_input("Use SPV? (y/n) ") == 'y'

        self.seed = tools.generate_seed()
        seed_words = self.get_mnemonic()
        
        print "Seed:", self.seed
        print "Mnemonic:", seed_words
        print "Write down your seed and keep it secret!"
        
    def load_seed(self, seed_words):
        self.seed = tools.get_seed(seed_words)
        print 'seed', self.seed
        print self.get_mnemonic()
        
    def set_otp(self, is_otp):
        self.otp = is_otp
    
    def set_pin(self, pin):
        self.pin = pin
    
    def sign_tx(self):
        # TODO
        pass
    
class MessageBroker(object):
    def __init__(self, device):
        self.device = device
        # Setup internal variables for OTP handshake
        self.otp_cancel()
        
    def yesno(self, question):
        return raw_input("%s (y/n) " % question) == 'y'
        
    def otp_request(self, func, *args):
        def generate():
            return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(4))
        
        self.otp = generate()
        self.otp_func = func
        self.otp_args = args
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

    def _load_device(self, seed_words, otp, pin):
        self.device.load_seed(seed_words)
        self.device.set_otp(otp)
        self.device.set_pin(pin)
        return proto.Success()

    def _reset_device(self):
        self.device.reset()
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
            
        if isinstance(msg, proto.Initialize):
            m = proto.Features()
            m.version = self.device.version
            m.otp = self.device.otp == True
            m.pin = self.device.pin != ''
            m.spv = self.device.spv == True
            return m
        
        if isinstance(msg, proto.Ping):
            return proto.Success()
    
        if isinstance(msg, proto.GetUUID):
            return proto.UUID(UUID='device-UUID')
                
        if isinstance(msg, proto.GetEntropy):
            if not self.yesno("Send %d bytes of entropy to computer?" % msg.size):
                return proto.Failure(code=4)
            if self.device.otp:
                return self.otp_request(self._get_entropy, msg.size)
            return self._get_entropy(msg.size)
    
        if isinstance(msg, proto.GetMasterPublicKey):
            return proto.MasterPublicKey(key=self.device.get_master_public_key())

        if isinstance(msg, proto.LoadDevice):
            if not self.yesno("Load device with custom seed?"):
                return proto.Failure(code=4)
            if self.device.otp:
                return self.otp_request(self._load_device, msg.seed, msg.otp, msg.pin)
            return self._load_device(msg.seed, msg.otp, msg.pin)
            
        if isinstance(msg, proto.ResetDevice):
            if not self.yesno("Reset device?"):
                return proto.Failure(code=4)
            if self.device.otp:
                return self.otp_request(self._reset_device)
            return self._reset_device()

        if isinstance(msg, proto.SignTx):
            print "<TODO: Print transaction details>"
            if not self.yesno("Sign transaction?"):
                return proto.Failure(code=4)
            if self.device.otp:
                return self.otp_request(self._sign_tx)
            return self._sign_tx()
        
        return proto.Failure(code=1, message='Unknown method')
        
def loop(broker):
    while True:
        msg = client.read()
        print "Received:", msg.__class__
        resp = broker.process_message(msg)
        print "Sent:", resp.__class__
        client.write(resp)

if __name__ == '__main__':
    client = PipeTransport('device.socket', is_device=True)

    try:
        print "Loading device..."
        device = pickle.load(open('device.dat', 'r'))
        print "Using seed:", device.get_mnemonic()
    except IOError:
        print "Load failed, starting with new device configuration..."
        device = Device()
    
    if device.seed == '':
        # Clean device
        device.reset()
        
    broker = MessageBroker(device)        
    try:
        loop(broker)
    except KeyboardInterrupt:
        client.close()
        
    pickle.dump(device, open('device.dat', 'w+'))