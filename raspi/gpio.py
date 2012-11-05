#!/usr/bin/python
import time
import wiringpi

PIN_BTNYES = 7
PIN_BTNNO  = 8

wiringpi.wiringPiSetupSys()

wiringpi.pinMode(PIN_BTNYES, wiringpi.INPUT)
wiringpi.pinMode(PIN_BTNNO,  wiringpi.INPUT)

wiringpi.pullUpDnControl(PIN_BTNYES, wiringpi.PUD_DOWN)
wiringpi.pullUpDnControl(PIN_BTNNO,  wiringpi.PUD_DOWN)

while True:
    print 'yes:', wiringpi.digitalRead(PIN_BTNYES), 'no:', wiringpi.digitalRead(PIN_BTNNO)
    time.sleep(0.1)
