#!/usr/bin/python
import os
import pygame
from display_buffer import DisplayBuffer 
        
class VirtualDisplay(object):
    def __init__(self, buffer):
        self.buffer = buffer
        self.black = pygame.Color(0, 0, 0)
        self.white = pygame.Color(255,255,255)
        self.scale = 2
        
        self.drivers = ['x11', 'dga', 'directfb', 'fbcon', 'ggi', 'vgl', 'svgalib', 'aalib']
        self.screen = None
        self.surface = None
        
    def _select_driver(self):
        for driver in self.drivers:
            os.putenv('SDL_VIDEODRIVER', driver)
            try:
                pygame.display.init()
            except pygame.error:
                print 'Driver: {0} failed.'.format(driver)
                continue
            return driver
    
    def init(self):
        driver = self._select_driver()
        if driver == 'x11':
            # Start in window
            self.screen = pygame.display.set_mode((self.buffer.width*self.scale, self.buffer.height*self.scale))
        else:
            # Start in fullscreen
            size = (pygame.display.Info().current_w, pygame.display.Info().current_h)
            self.screen = pygame.display.set_mode(size, pygame.FULLSCREEN)
            self.scale = 1

        self.surface = pygame.Surface((self.buffer.width, self.buffer.height))

    def refresh(self):        
        self.surface.fill(self.black)
        
        set_at = self.surface.set_at
        white = self.white
        width = self.buffer.width
        height = self.buffer.height
        data = self.buffer.data
        
        '''Optimized for performance. Especially inline writedown of get_pixel helped a lot'''
        for x in range(width):
            for y in range(height):
                #pix = get_pixel(x, y)
                pix = data[x+(y/8)*width] & (1 << (y%8)) > 0
                if pix: set_at((x, y), white)
           
        pygame.transform.scale(self.surface, self.screen.get_size(), self.screen)
        pygame.display.flip()