'''Cp2110Transport implements communication with CP2100 HID-to-UART chip as used in Trezor shield.'''

# Local serial port loopback: socat PTY,link=COM8 PTY,link=COM9

import serial
import time
from select import select
from transport import Transport

class FakeRead(object):
    # Let's pretend we have a file-like interface
    def __init__(self, func):
        self.func = func
        
    def read(self, size):
        return self.func(size)

class Cp2110Transport(Transport):
    def __init__(self, device, *args, **kwargs):
        self.serial = None
        self.buffer = ''
        super(Cp2110Transport, self).__init__(device, *args, **kwargs)

    def _open(self):
        self.buffer = ''
        self.serial = serial.Serial(self.device, 115200, timeout=10, writeTimeout=10)

    def _close(self):
        self.buffer = ''
        self.serial.close()
        self.serial = None

    def ready_to_read(self):
        rlist, _, _ = select([self.serial], [], [], 0)
        return len(rlist) > 0

    def _write(self, msg):
        try:
            while len(msg):
                self.serial.write(msg[:63] + '0'*(63-len(msg[:63])))
                msg = msg[63:]

            self.serial.flush()

        except serial.SerialException:
            print "Error while writing to socket"
            raise

    def _read(self):
        try:
            (msg_type, datalen) = self._read_headers(FakeRead(self._raw_read))
            return (msg_type, self._raw_read(datalen))
        except serial.SerialException:
            print "Failed to read from device"
            raise

    def _raw_read(self, length): 
        while len(self.buffer) < length:
            data = self.serial.read(63)
            print "READ", [ ord(x) for x in data ]
            
            if len(data) != 63:
                # Force to use 63-byte messages
                raise Exception("Payload must have exactly 63 bytes")
                         
            self.buffer += data

        ret = self.buffer[:length]
        self.buffer = self.buffer[length:]
        return ret
