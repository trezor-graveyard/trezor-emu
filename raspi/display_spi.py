import time
import wiringpi
import spidev

class SPIDisplay(object):
    def __init__(self, buffer):
        self.PIN_OLED_DC  = 23   # RS
        self.PIN_OLED_CS  = 24   # CS
        self.PIN_OLED_RST = 25   # RES
        self.buffer  = buffer
        self.spidev = None

    def init(self):
        wiringpi.wiringPiSetupGpio()
        self.spidev = spidev.SpiDev()
        self.spidev.open(0, 0)

        wiringpi.pinMode(self.PIN_OLED_DC,  wiringpi.OUTPUT)
        wiringpi.pinMode(self.PIN_OLED_CS,  wiringpi.OUTPUT)
        wiringpi.pinMode(self.PIN_OLED_RST, wiringpi.OUTPUT)

        wiringpi.pinMode(self.PIN_BTN_YES, wiringpi.INPUT)
        wiringpi.pinMode(self.PIN_BTN_NO,  wiringpi.INPUT)

        wiringpi.pullUpDnControl(self.PIN_BTN_YES, wiringpi.PUD_DOWN)
        wiringpi.pullUpDnControl(self.PIN_BTN_NO,  wiringpi.PUD_DOWN)

        wiringpi.digitalWrite(self.PIN_OLED_DC, 0)
        wiringpi.digitalWrite(self.PIN_OLED_RST, 0)
        wiringpi.digitalWrite(self.PIN_OLED_CS, 1) # deselect

        wiringpi.digitalWrite(self.PIN_OLED_RST, 1)
        time.sleep(0.001)
        wiringpi.digitalWrite(self.PIN_OLED_RST, 0)
        time.sleep(0.010)
        wiringpi.digitalWrite(self.PIN_OLED_RST, 1)

        wiringpi.digitalWrite(self.PIN_OLED_CS, 0) # select
        seq = [ 0xAE, 0xD5, 0x80, 0xA8, 0x3F, 0xD3, 0x00, 0x40, 0x8D, 0x14, 0x20, 0x00, 0xA1, 0xC8, 0xDA, 0x12, 0x81, 0xCF, 0xD9, 0xF1, 0xDB, 0x40, 0xA4, 0xA6, 0xAF ]
        self._sendSPI(seq)
        wiringpi.digitalWrite(self.PIN_OLED_CS, 1) # deselect

        self.render()

    def _sendSPI(self, data):
        self.spidev.xfer2(data)

    def refresh(self):
        wiringpi.digitalWrite(self.PIN_OLED_CS, 0) # select
        seq = [0x00, 0x10, 0x40]
        self._sendSPI(seq)
        wiringpi.digitalWrite(self.PIN_OLED_CS, 1) # deselect
        wiringpi.digitalWrite(self.PIN_OLED_DC, 1) # data
        wiringpi.digitalWrite(self.PIN_OLED_CS, 0) # select
        self._sendSPI(self.buffer.data)
        wiringpi.digitalWrite(self.PIN_OLED_CS, 1) # deselect
        wiringpi.digitalWrite(self.PIN_OLED_DC, 0) # cmd