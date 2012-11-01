import struct
from bitkey_proto import bitkey_pb2 as proto
from bitkey_proto import mapping

class Transport(object):
    def __init__(self, device, *args, **kwargs):
        self.device = device
        self._open()
    
    def _open(self):
        raise NotImplemented
    
    def _close(self):
        raise NotImplemented
    
    def _write(self, msg):
        raise NotImplemented
    
    def _read(self):
        raise NotImplemented
    
    def close(self):
        self._close()
        
    def write(self, msg):
        ser = msg.SerializeToString()
        header = struct.pack(">HL", mapping.get_type(msg), len(ser))
        self._write("##%s%s" % (header, ser))
            
    def read(self):
        (msg_type, data) = self._read()
        inst = mapping.get_class(msg_type)()
        inst.ParseFromString(data)
        return inst
    
    def _read_headers(self, filelike):
        if filelike.read(2) != '##':
            raise Exception("Header magic is broken")

        try:
            headerlen = struct.calcsize(">HL")
            (msg_type, datalen) = struct.unpack(">HL", filelike.read(headerlen))
        except:
            raise Exception("Cannot parse header length")

        if datalen < 0 or datalen > 10**7:
            raise Exception("Header length mismatch")

        return (msg_type, datalen)