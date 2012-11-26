class Buttons(object):
    def __init__(self, hw=False, stdin=True, pygame=False):
        if hw:
            import buttons_hw
            self.hw = buttons_hw.HwButtons()
        else:
            self.hw = None
            
        if stdin:
            import buttons_stdin
            self.stdin = buttons_stdin.StdinButtons()
        else:
            self.stdin = None
            
        if pygame:
            import buttons_pygame
            self.pygame = buttons_pygame.PygameButtons()
        else:
            self.pygame = None
            
    def read(self):
        if self.hw:
            but = self.hw.read()
            if but != None:
                return but
            
        if self.stdin:
            but = self.stdin.read()
            if but != None:
                return but
            
        if self.pygame:
            try:
                but = self.pygame.read()
                if but != None:
                    return but

            except Exception as exc:
                print "Pygame buttons requires usage of VirtualDisplay"
                self.pygame = None