import wiringpi


class HwButtons(object):
    def __init__(self):
        self.PIN_BTN_YES = 8
        self.PIN_BTN_NO  = 7
        
    def read(self):
        no_state = wiringpi.digitalRead(self.PIN_BTN_NO) > 0
        yes_state = wiringpi.digitalRead(self.PIN_BTN_YES) > 0
        
        if no_state:
            return False
        if yes_state:
            return True
        
        return None
        