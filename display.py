#!/usr/bin/python

import argparse
import time
import Image

from trezor.display_buffer import DisplayBuffer
from trezor.display import Display
from trezor.layout import Layout
from trezor import DISPLAY_WIDTH, DISPLAY_HEIGHT

def parse_args():
    parser = argparse.ArgumentParser(description='Show a message or a text on SPI display.')

    parser.add_argument('-t', '--text', dest='text', default='', help='Message to display. Use pipe as a line delimiter.')
    parser.add_argument('-i', '--image', dest='image', default='', help='Filename of image to display.')
    parser.add_argument('-p', '--pygame', dest='pygame', action='store_true', help='Use pygame for rendering')
    return parser.parse_args()

def main():
    args = parse_args()

    buff = DisplayBuffer(DISPLAY_WIDTH, DISPLAY_HEIGHT)
    display = Display(buff, spi=not args.pygame, virtual=args.pygame)
    display.init()

    # Initialize layout driver
    layout = Layout(buff)

    if args.text:
      layout.show_message(args.text.split('|'))
    if args.image:
      im = Image.open(args.image) # has to be 1-bit-per-pixel PNG (black-white)
      imd = list(im.getdata())
      img = [0] * (DISPLAY_WIDTH*DISPLAY_HEIGHT/8)
      for y in range(DISPLAY_HEIGHT):
        for x in range(DISPLAY_WIDTH):
          c = imd[x + y * DISPLAY_WIDTH]
          if c[0] + c[1] + c[2] > 384:
            img[(x / 8) + y * DISPLAY_WIDTH / 8] |= (1 << (7 - x % 8))

      layout.show_logo(img)

    display.refresh()

    if args.pygame:
        while True:
            time.sleep(1)

if __name__ == '__main__':
    main()
