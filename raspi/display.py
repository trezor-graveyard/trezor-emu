class Display(object):
    def __init__(self, buffer, spi=False, virtual=True):
        if spi:
            import display_spi
            self.spi = display_spi.SPIDisplay(buffer)
        else:
            self.spi = None
            
        if virtual:
            import display_virtual
            self.virtual = display_virtual.VirtualDisplay(buffer)
        else:
            self.virtual = None
            
    def init(self):
        if self.spi:
            try:
                self.spi.init()
            except IOError as exc:
                print "SPI display not available: %s" % str(exc)
                self.spi = None                
        if self.virtual:
            self.virtual.init()
    
    def refresh(self):
        if self.spi:
            self.spi.refresh()
        if self.virtual:
            self.virtual.refresh()
            
        