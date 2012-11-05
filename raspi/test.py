#!/usr/bin/python
import wiringpi

buf = [1, 2, 3]

wiringpi.wiringPiSPIDataRW(0, buf, len(buf))
