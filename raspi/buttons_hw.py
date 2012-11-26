class HwButtons(object):
    def __init__(self):
        self.PIN_BTN_YES = 8
        self.PIN_BTN_NO  = 7

    def __readPin(self, pin):
        with open('/sys/class/gpio/gpio%d/value' % pin, 'r') as f:
            return f.read(1)

    def read(self):
        no_state = (self.__readPin(self.PIN_BTN_NO) == '1')
        yes_state = (self.__readPin(self.PIN_BTN_YES) == '1')

        if no_state:
            return False
        if yes_state:
            return True

        return None
