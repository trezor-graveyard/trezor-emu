#!/usr/bin/python
import random
import time
import json
import sys
from select import select  # For raw_input timeout

import tools
import bitkey_pb2 as proto
from transport_pipe import PipeTransport
from transport_fake import FakeTransport
from algo import AlgoFactory

'''
    Feature list:
        * PIN-protected seed
        * master private key derived from PIN?
        * Store PIN as a hash
        * SPV
        * P2SH

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
        self.vendor = 'slush'
        self.major_version = 0
        self.minor_version = 1

        self.seed = ''
        self.otp = False
        self.spv = False
        self.pin = ''
        self.algo = [proto.ELECTRUM, ]
        self.maxfee_kb = 100000  # == 0.001 BTC/kB
        self.debug_link = False  # Enabled debugging connection

    @classmethod
    def load(cls, filename):
        data = json.load(open(filename, 'r'))
        dev = Device()
        dev.seed = str(data['seed'])
        dev.otp = data['otp']
        dev.spv = data['spv']
        dev.pin = data['pin']
        dev.maxfee_kb = data['maxfee_kb']
        return dev

    def save(self, filename):
        data = {}
        data['seed'] = self.seed
        data['otp'] = self.otp
        data['spv'] = self.spv
        data['pin'] = self.pin
        data['maxfee_kb'] = self.maxfee_kb

        # Debug link state is NOT persisted

        json.dump(data, open(filename, 'w'))

    def get_master_public_key(self, algo):
        af = AlgoFactory(algo)
        master_public_key = af.init_master_public_key(self.seed)
        #af.get_new_address(master_public_key, [0])
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

    def sign_tx(self, algo, inputs, outputs):
        # TODO
        pass


class YesNo(object):
    def __init__(self, debug_transport):
        self.debug_transport = debug_transport

    def yesno(self, question):
        '''Reads for y/n from standard input
        AND from debug link if enabled'''

        timeout = 0.5
        sys.stdout.write("%s (y/n) " % question)
        sys.stdout.flush()

        while True:
            if self.debug_transport.ready_to_read():
                decision = self.debug_transport.read()
                if not isinstance(decision, proto.DebugLinkDecision):
                    raise Exception("Expected DebugLinkDecision object, got %s" % decision)

                print 'y' if decision.yes_no else 'n'
                return decision.yes_no

            rlist, _, _ = select([sys.stdin], [], [], timeout)

            if not rlist:
                continue  # timeout

            return sys.stdin.readline().strip() == 'y'


class MessageBroker(object):
    def __init__(self, device, debug_transport, yesno_func):
        self.device = device
        # Setup internal variables for OTP handshake
        self.otp_cancel()
        self.pin_cancel()

        self.debug_transport = debug_transport
        self.yesno = yesno_func

    def pin_request(self, message, pass_or_check, func, *args):
        self.pin_pass_or_check = pass_or_check
        self.pin_func = func
        self.pin_args = args

        self.debug_transport.write(proto.PinAck(pin=self.device.pin))

        if message is not None:
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
        if message is not None:
            m = proto.OtpRequest(message=message)
        else:
            m = proto.OtpRequest()

        self.debug_transport.write(proto.OtpAck(otp=self.otp))

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

    def protect_call(self, yesno_message, otp_message, pin_message, func, *args):
        if not self.yesno(yesno_message):
            return proto.Failure(code=4, message='Action cancelled by user')

        if self.device.otp:
            if self.device.pin:
                return self.otp_request(otp_message, self.pin_request, *[pin_message, False, func] + list(args))
            else:
                return self.otp_request(otp_message, func, *args)

        if self.device.pin:
            return self.pin_request(pin_message, False, func, *args)

        return func(*args)

    def _get_entropy(self, size):
        random.seed()
        m = proto.Entropy()
        m.entropy = ''.join([chr(random.randrange(0, 255, 1)) for _ in xrange(0, size)])
        return m

    def _set_maxfee_kb(self, maxfee_kb):
        self.device.maxfee_kb = maxfee_kb
        return proto.Success()

    def _load_device(self, seed_words, otp, pin, spv):
        self.device.load_seed(seed_words)
        self.device.set_otp(otp)
        self.device.set_pin(pin)
        self.device.set_spv(spv)
        return proto.Success()

    def _reset_device(self, random):
        print "Starting setup wizard..."

        is_otp = self.yesno("Use OTP?")
        is_spv = self.yesno("Use SPV?")
        is_pin = self.yesno("Use PIN?")

        if is_pin:
            return self.pin_request("Please enter new PIN", True, self._reset_device2, random, is_otp, is_spv)

        return self._reset_device2('', random, is_otp, is_spv)

    def _reset_device2(self, random, pin, is_otp, is_spv):
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

    def _sign_tx(self, tx):
        #self.device.sign_tx(algo=tx.algo, inputs=tx.inputs, output=tx.output)
        return proto.SignedTx(tx='signed transaction')

    def process_message(self, msg):
        if isinstance(msg, proto.Initialize):
            self.otp_cancel()
            self.pin_cancel()

            m = proto.Features()
            m.session_id = msg.session_id
            m.vendor = self.device.vendor
            m.major_version = self.device.major_version
            m.minor_version = self.device.minor_version
            m.otp = self.device.otp is True
            m.pin = self.device.pin != ''
            m.spv = self.device.spv is True
            m.algo.extend(self.device.algo)
            m.maxfee_kb = self.device.maxfee_kb
            m.debug_link = self.device.debug_link
            return m

        if self.otp is not None:
            '''OTP response is expected'''

            if isinstance(msg, proto.OtpAck):
                return self.otp_check(msg.otp)

            if isinstance(msg, proto.OtpCancel):
                self.otp_cancel()
                return proto.Success(message="OTP cancelled")

            return proto.Failure(code=2, message='Waiting for OTP')

        if self.pin_func is not None:
            '''PIN response is expected'''
            if isinstance(msg, proto.PinAck):
                return self.pin_check(msg.pin)

            if isinstance(msg, proto.PinCancel):
                self.pin_cancel()
                return proto.Success(message="PIN request cancelled")

            return proto.Failure(code=5, message='Waiting for PIN')

        if isinstance(msg, proto.Ping):
            return proto.Success(message=msg.message)

        if isinstance(msg, proto.GetUUID):
            return proto.UUID(UUID='device-UUID')

        if isinstance(msg, proto.GetEntropy):
            return self.protect_call("Send %d bytes of entropy to computer?" % msg.size,
                                     None, None,
                                     self._get_entropy, msg.size)

        if isinstance(msg, proto.GetMasterPublicKey):
            return proto.MasterPublicKey(key=self.device.get_master_public_key(msg.algo))

        if isinstance(msg, proto.SetMaxFeeKb):
            return self.protect_call("Current maximal fee is %s per kB. Set transaction fee to %s per kilobyte?" %
                                     (self.device.maxfee_kb, msg.maxfee_kb),
                                     None, None,
                                     self._set_maxfee_kb, msg.maxfee_kb)

        if isinstance(msg, proto.LoadDevice):
            return self.protect_call("Load device with custom seed?",
                                     None, None,
                                     self._load_device, msg.seed, msg.otp, msg.pin, msg.spv)

        if isinstance(msg, proto.ResetDevice):
            return self.protect_call("Reset device?",
                                     None, None,
                                     self._reset_device, msg.random)

        if isinstance(msg, proto.SignTx):
            print "<TODO: Print transaction details>"
            return self.protect_call("Sign transaction?",
                                     None, None,
                                     self._sign_tx, msg)

        return proto.Failure(code=1, message='Unknown method')


def loop(transport, broker):
    while True:
        msg = transport.read()
        print "Received:", msg.__class__
        resp = broker.process_message(msg)
        print "Sent:", resp.__class__
        transport.write(resp)


if __name__ == '__main__':
    ENABLE_DEBUG_LINK = True

    if ENABLE_DEBUG_LINK:
        debug_transport = PipeTransport('../device.socket.debug', is_device=True)
    else:
        debug_transport = FakeTransport('/dev/null')

    #transport = SerialTransport('COM8')
    transport = PipeTransport('../device.socket', is_device=True)

    try:
        print "Loading device..."
        device = Device.load('../device.dat')
        device.debug_link = ENABLE_DEBUG_LINK
    except IOError:
        print "Load failed, starting with new device configuration..."
        device = Device()
        device.debug_link = ENABLE_DEBUG_LINK

    print "Using seed:", device.get_mnemonic()
    print "Using debug link:", device.debug_link

    if device.seed == '':
        print "This device hasn't been initialized yet. Please initialize it in desktop client."

    #device.get_master_public_key(proto.ELECTRUM)
    #print tools.SecretToASecret(AlgoFactory(proto.ELECTRUM).get_private_key(device.seed, 0))

    # 521631520fe6c44ebd98b0e70c1c720d570d0ecd7927efd27151fc45dd1c84de

    data = '080118a0c21e222c0a22314c4e35664b727a557677696e6e42716e6d426a324a486557664235654e776f3451100418c0843d2000' \
           '222c0a22314b7159797a4c353352386f41314c6459767976376d364a5572794666474a447061100018e0a71220002a4508001080' \
           'ea301a20622632090b7ca1a456c659e651f5778da4f3f1d3d4508811b8602b1209fb1ae820012a1976a914cea0ed8f6c892b20ec' \
           '85202d00fac7e3155c7a8288ac2a45080410c0843d1a20729689408b9bc45c66f026fa4e4a2a5d535c56b5e9b8d23220b220b9f1' \
           '978e9420002a1976a914d4670405b4b734ca2be50c044e815152503cbc8888ac3a800274596e35425aef92cbba32bc19e252166c' \
           '95f765080cdea37b9202a98b7ea54f62bf3ee6899b75f01eee8c69e006cabf6006e957757e6f1ee49680ca62febff81c377b0841' \
           'a63240f439b0c7bfbb507cb11701bdb47d3838426cc5802ee93ea5fd870f1c2b7e39969bad203da1a0b3df701901393264bdf7bc' \
           '155f95fcc8ab5793ad7e1612c5ecf0dfb85b8e654260477bf1d2cd183f4a8743e93a2255d03f1836d9a36ea8746f34bd301ac6bd' \
           '0e99c6a703a176f32a55370675b249deba83db776b5e20ab5f8d879518fdc91a6aa412f203fca59588dea131c7e09649cbaaca59' \
           '5aab8906674e97034f7f2431bd1cdf0aee725f592e56a768783a1dcdfa7b45'
    # signature add550d6ba9ab7e01d37e17658f98b6e901208d241f24b08197b5e20dfa7f29f095ae01acbfa5c4281704a64053dcb80e9b0
    # 89ecbe09f5871d67725803e36edd 3045022100dced96eeb43836bc95676879eac303eabf39802e513f4379a517475c259da12502201fd
    # 36c90ecd91a32b2ca8fed2e1755a7f2a89c2d520eb0da10147802bc7ca217
    #print tx.decode('hex')

    '''
    tx = proto.SignTx()
    tx.ParseFromString(data.decode('hex'))
    print tx
    try:
        signatures = tools.sign_inputs(AlgoFactory(tx.algo), device.seed, tx.inputs, tx.outputs)
        for sig in signatures:
            print (sig[0].encode('hex'), sig[1].encode('hex')).__repr__()
    except:
        client.close()
        raise
    #print tx
    '''

    yesno = YesNo(debug_transport)
    broker = MessageBroker(device, debug_transport, yesno_func=yesno.yesno)

    try:
        loop(transport, broker)
    except KeyboardInterrupt:
        transport.close()
        debug_transport.close()
    except:
        transport.close()
        debug_transport.close()
        raise

    device.save('../device.dat')
