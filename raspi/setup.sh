#!/bin/sh

PIN_BTN_YES=8
PIN_BTN_NO=7
PIN_OLED_DC=23
PIN_OLED_CS=24
PIN_OLED_RST=25

for p in $PIN_BTN_YES $PIN_BTN_NO $PIN_OLED_DC $PIN_OLED_CS $PIN_OLED_RST; do
    echo $p > /sys/class/gpio/export
done

echo 'in' > /sys/class/gpio/gpio$PIN_BTN_YES/direction
echo 'in' > /sys/class/gpio/gpio$PIN_BTN_NO/direction

echo 'out' > /sys/class/gpio/gpio$PIN_OLED_DC/direction
echo 'out' > /sys/class/gpio/gpio$PIN_OLED_CS/direction
echo 'out' > /sys/class/gpio/gpio$PIN_OLED_RST/direction
