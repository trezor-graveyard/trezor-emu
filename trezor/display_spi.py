import time
import spidev
import RPi.GPIO as GPIO


class SPIDisplay(object):
    def __init__(self, buffer):
        self.PIN_OLED_DC = 23  # RS
        self.PIN_OLED_CS = 25  # CS
        self.PIN_OLED_RST = 24  # RES
        self.buffer = buffer
        self.spidev = None

    def init(self):
        GPIO.setmode(GPIO.BCM)
        GPIO.setwarnings(False)
        GPIO.setup(self.PIN_OLED_DC, GPIO.OUT)
        GPIO.setup(self.PIN_OLED_CS, GPIO.OUT)
        GPIO.setup(self.PIN_OLED_RST, GPIO.OUT)

        self.spidev = spidev.SpiDev()
        self.spidev.open(0, 0)

        self.__writePin(self.PIN_OLED_DC, 0)
        self.__writePin(self.PIN_OLED_RST, 0)
        self.__writePin(self.PIN_OLED_CS, 1)  # deselect

        self.__writePin(self.PIN_OLED_RST, 1)
        time.sleep(0.001)
        self.__writePin(self.PIN_OLED_RST, 0)
        time.sleep(0.010)
        self.__writePin(self.PIN_OLED_RST, 1)

        self.__writePin(self.PIN_OLED_CS, 0)  # select
        seq = [0xAE, 0xD5, 0x80, 0xA8, 0x3F, 0xD3, 0x00, 0x40, 0x8D, 0x14, 0x20, 0x00, 0xA1, 0xC8, 0xDA, 0x12, 0x81,
               0xCF, 0xD9, 0xF1, 0xDB, 0x40, 0xA4, 0xA6, 0xAF]
        self.__sendSPI(seq)
        self.__writePin(self.PIN_OLED_CS, 1)  # deselect

        self.refresh()

    def __sendSPI(self, data):
        self.spidev.xfer2(data[:])

    def __writePin(self, pin, value):
        if value:
            GPIO.output(pin, GPIO.HIGH)
        else:
            GPIO.output(pin, GPIO.LOW)

    def refresh(self):
        self.__writePin(self.PIN_OLED_CS, 0)  # select
        seq = [0x00, 0x10, 0x40]
        self.__sendSPI(seq)
        self.__writePin(self.PIN_OLED_CS, 1)  # deselect
        self.__writePin(self.PIN_OLED_DC, 1)  # data
        self.__writePin(self.PIN_OLED_CS, 0)  # select
        # rotate display data
        data = [((x & 0x01) << 7 | (x & 0x02) << 5 | (x & 0x04) << 3 | (x & 0x08) << 1 | (x & 0x10) >> 1 |
                 (x & 0x20) >> 3 | (x & 0x40) >> 5 | (x & 0x80) >> 7) for x in self.buffer.data[::-1]]
        self.__sendSPI(data)
        self.__writePin(self.PIN_OLED_CS, 1)  # deselect
        self.__writePin(self.PIN_OLED_DC, 0)  # cmd
