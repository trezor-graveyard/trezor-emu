import time
import spidev

class SPIDisplay(object):
    def __init__(self, buffer):
        self.PIN_OLED_DC  = 23   # RS
        self.PIN_OLED_CS  = 24   # CS
        self.PIN_OLED_RST = 25   # RES
        self.buffer  = buffer
        self.spidev = None

    def init(self):
        self.spidev = spidev.SpiDev()
        self.spidev.open(0, 0)

        self.__writePin(self.PIN_OLED_DC, 0)
        self.__writePin(self.PIN_OLED_RST, 0)
        self.__writePin(self.PIN_OLED_CS, 1) # deselect

        self.__writePin(self.PIN_OLED_RST, 1)
        time.sleep(0.001)
        self.__writePin(self.PIN_OLED_RST, 0)
        time.sleep(0.010)
        self.__writePin(self.PIN_OLED_RST, 1)

        self.__writePin(self.PIN_OLED_CS, 0) # select
        seq = [ 0xAE, 0xD5, 0x80, 0xA8, 0x3F, 0xD3, 0x00, 0x40, 0x8D, 0x14, 0x20, 0x00, 0xA1, 0xC8, 0xDA, 0x12, 0x81, 0xCF, 0xD9, 0xF1, 0xDB, 0x40, 0xA4, 0xA6, 0xAF ]
        self.__sendSPI(seq)
        self.__writePin(self.PIN_OLED_CS, 1) # deselect

        self.refresh()

    def __sendSPI(self, data):
        self.spidev.xfer2(data)

    def __writePin(self, pin, value):
        with open('/sys/class/gpio/gpio%d/value' % pin, 'w') as f:
            f.write(str(value))

    def refresh(self):
        self.__writePin(self.PIN_OLED_CS, 0) # select
        seq = [0x00, 0x10, 0x40]
        self.__sendSPI(seq)
        self.__writePin(self.PIN_OLED_CS, 1) # deselect
        self.__writePin(self.PIN_OLED_DC, 1) # data
        self.__writePin(self.PIN_OLED_CS, 0) # select
        self.__sendSPI(self.buffer.data)
        self.__writePin(self.PIN_OLED_CS, 1) # deselect
        self.__writePin(self.PIN_OLED_DC, 0) # cmd
