#!/usr/bin/python
import time
import wiringpi

PIN_BTNYES = 11
PIN_BTNNO  = 10

wiringpi.wiringPiSetupSys()

for i in xrange(0, 25):
    wiringpi.pinMode(i, wiringpi.INPUT)
# wiringpi.pinMode(PIN_BTNYES, wiringpi.INPUT)
# wiringpi.pinMode(PIN_BTNNO,  wiringpi.INPUT)

while True:
    for i in xrange(0, 25): 
        print i, wiringpi.digitalRead(i),
    print
#    print 'yes:', wiringpi.digitalRead(PIN_BTNYES), 'no:', wiringpi.digitalRead(PIN_BTNNO)
    time.sleep(0.1)
