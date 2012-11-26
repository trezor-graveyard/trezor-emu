import RPi.GPIO as GPIO

class HwButtons(object):
    def __init__(self):
        self.PIN_BTN_YES = 8
        self.PIN_BTN_NO  = 7
        GPIO.setup(self.PIN_BTN_YES, GPIO.IN, pull_up_down = GPIO.PUD_DOWN)
        GPIO.setup(self.PIN_BTN_NO,  GPIO.IN, pull_up_down = GPIO.PUD_DOWN)

    def read(self):
        no_state  = (GPIO.input(self.PIN_BTN_NO ) == 1)
        yes_state = (GPIO.input(self.PIN_BTN_YES) == 1)

        if no_state:
            return False
        if yes_state:
            return True

        return None
