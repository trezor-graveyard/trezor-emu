'''SocketTransport implements TCP socket interface for Transport.'''

from transport import Transport

class SocketTransport(Transport):
    def __init__(self, device, listen=False, *args, **kwargs):
        super(SocketTransport, self).__init__(device, *args, **kwargs)
        
    def _open(self):
        pass
    
    def _close(self):
        pass
    
    def ready_to_read(self):
        return False
    
    def _write(self, msg):
        pass
        
    def _read(self):
        raise NotImplemented