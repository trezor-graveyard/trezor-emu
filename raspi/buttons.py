class Buttons(object):
    def __init__(self, hw=False, stdin=True, pygame=False):
        self.pressed = None
        
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
        but = []
        
        # Check current state of buttons, add results to but list
        if self.hw:
            but.append(self.hw.read())
            
        if self.pygame:
            try:
                but.append(self.pygame.read())
            except KeyboardInterrupt:
                raise
            except Exception:
                print "Pygame buttons require usage of VirtualDisplay"
                self.pygame = None
                            
        if self.stdin:
            but.append(self.stdin.read())

        # Now prevent button bouncing by registering current press
        # and reporting the press after releasing the button
        
        # 'No' button has a priority, for security reason
        if False in but and self.pressed != False:
            self.pressed = False
            return None

        elif True in but and self.pressed != True:
            self.pressed = True
            return None
            
        if self.pressed != None and but.count(None) == len(but):
            state = self.pressed
            self.pressed = None
            return state