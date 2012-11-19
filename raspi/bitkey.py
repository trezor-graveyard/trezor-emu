#!/usr/bin/python
import time
import wiringpi
import spidev

class Bitkey:

    def __init__(self):
        self.PIN_OLED_DC  = 23   # RS
        self.PIN_OLED_CS  = 24   # CS
        self.PIN_OLED_RST = 25   # RES
        self.PIN_BTN_YES = 8
        self.PIN_BTN_NO  = 7
        self.OLED_WIDTH   = 128
        self.OLED_HEIGHT  = 64
        self.oledbuffer  = [0] * (self.OLED_WIDTH * self.OLED_HEIGHT / 8)
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
        self.sendSPI(seq)
        wiringpi.digitalWrite(self.PIN_OLED_CS, 1) # deselect

        self.oledClear()
        self.oledRefresh()

    def sendSPI(self, data):
        self.spidev.xfer2(data)

    def oledClear(self):
        self.oledbuffer  = [0] * (self.OLED_WIDTH * self.OLED_HEIGHT / 8)

    def oledRefresh(self):
        wiringpi.digitalWrite(self.PIN_OLED_CS, 0) # select
        seq = [0x00, 0x10, 0x40]
        self.sendSPI(seq)
        wiringpi.digitalWrite(self.PIN_OLED_CS, 1) # deselect
        wiringpi.digitalWrite(self.PIN_OLED_DC, 1) # data
        wiringpi.digitalWrite(self.PIN_OLED_CS, 0) # select
        self.sendSPI(self.oledbuffer)
        wiringpi.digitalWrite(self.PIN_OLED_CS, 1) # deselect
        wiringpi.digitalWrite(self.PIN_OLED_DC, 0) # cmd

    def oledDrawPixel(self, x, y):
        if (x < 0) or (y < 0) or (x >= self.OLED_WIDTH) or (y >= self.OLED_HEIGHT):
            return
        self.oledbuffer[x+(y/8)*self.OLED_WIDTH] |= (1 << (y%8))

    def oledClearPixel(self, x, y):
        if (x < 0) or (y < 0) or (x >= self.OLED_WIDTH) or (y >= self.OLED_HEIGHT):
            return
        self.oledbuffer[x+(y/8)*self.OLED_WIDTH] &= ~(1 << (y%8))

    def oledDrawChar(self, x, y, c, font):
        if (x >= self.OLED_WIDTH) or (y >= self.OLED_HEIGHT):
            return
        column = [0] * font.width
        if (c >= font.firstchar) and (c <= font.lastchar):
            for col in xrange(font.width):
                column[col] = font.table[((c - font.firstchar) * font.width) + col]
        else:
            for col in xrange(font.width):
                column[col] = 0xFF
        for xoffset in xrange(font.width):
            for yoffset in xrange(font.height):
                if column[xoffset] & (1 << yoffset):
                    self.oledDrawPixel(x + xoffset, y + yoffset)

    def oledDrawString(self, x, y, text, font):
        for i in xrange(len(text)):
            self.oledDrawChar(x + (i * (font.width + 1)), y, ord(text[i]), font)

    def oledInvert(self, x1, y1, x2, y2):
        if (x1 >= self.OLED_WIDTH) or (y1 >= self.OLED_HEIGHT) or (x2 >= self.OLED_WIDTH) or (y2 >= self.OLED_HEIGHT):
            return
        for x in xrange(x1, x2+1):
            for y in xrange(y1, y2+1):
                self.oledbuffer[x+(y/8)*self.OLED_WIDTH] ^= (1 << (y%8))

    def buttonsRead(self):
        return [ wiringpi.digitalRead(self.PIN_BTN_NO) > 0 , wiringpi.digitalRead(self.PIN_BTN_YES) > 0 ]
