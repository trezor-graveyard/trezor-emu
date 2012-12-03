import pygame
import sys

class PygameButtons(object):
    def read(self):
        pygame.event.pump()
        bools = pygame.key.get_pressed()       
            
        '''
        for x in range(len(bools)):
            if bools[x]:
                print x
        '''

        if bools[110]: # n
            return False       
     
        if bools[121]: # y
            return True
        
        if pygame.event.peek(pygame.QUIT):
            # Close a window
            raise KeyboardInterrupt("Window closed")

        if bools[99] and bools[306]: # Ctrl+C
            # Workaround for terminating the application from pygame window
            raise KeyboardInterrupt("Ctr+C in pygame window")
            
        return None