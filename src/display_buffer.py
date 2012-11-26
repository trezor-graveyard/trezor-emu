class DisplayBuffer(object):
    def __init__(self, width=128, height=64):
        self.width = width
        self.height = height
        self.clear()

    def clear(self):
        self.data = [0] * (self.width * self.height / 8)

    def draw_bitmap(self, bitmap):
        for x in xrange(self.width):
            for y in xrange(self.height):
                if bitmap[(x/8)+y*self.width/8] & (1 << (7-x%8)):
                    self.data[x+(y/8)*self.width] |= (1 << (y%8))
                else:
                    self.data[x+(y/8)*self.width] &= ~(1 << (y%8))

    def draw_pixel(self, x, y):
        if (x < 0) or (y < 0) or (x >= self.width) or (y >= self.height):
            return
        self.data[x+(y/8)*self.width] |= (1 << (y%8))

    def clear_pixel(self, x, y):
        if (x < 0) or (y < 0) or (x >= self.width) or (y >= self.height):
            return
        self.data[x+(y/8)*self.width] &= ~(1 << (y%8))

    def get_pixel(self, x, y):
        if (x < 0) or (y < 0) or (x >= self.width) or (y >= self.height):
            return None
        return self.data[x+(y/8)*self.width] & (1 << (y%8)) > 0

    def draw_char(self, x, y, c, font):
        if (x >= self.width) or (y >= self.height):
            return
        column = [0] * font.width
        if (c >= font.firstchar) and (c <= font.lastchar):
            for col in xrange(font.width):
                column[col] = font.table[((c - font.firstchar) * font.width) + col]
        else:
            for col in xrange(font.width):
                column[col] = 0xFF
        for xoffset in xrange(font.width):
            for yoffset in xrange(font.height):
                if column[xoffset] & (1 << yoffset):
                    self.draw_pixel(x + xoffset, y + yoffset)

    def draw_string(self, x, y, text, font):
        for i in xrange(len(text)):
            self.draw_char(x + (i * (font.width + 1)), y, ord(text[i]), font)

    def invert(self, x1, y1, x2, y2):
        if (x1 >= self.width) or (y1 >= self.height) or (x2 >= self.width) or (y2 >= self.height):
            return
        for x in xrange(x1, x2+1):
            for y in xrange(y1, y2+1):
                self.data[x+(y/8)*self.width] ^= (1 << (y%8))

    def box(self, x1, y1, x2, y2):
        for x in xrange(x1, x2+1):
            for y in xrange(y1, y2+1):
                self.clear_pixel(x, y)

    def frame(self, x1, y1, x2, y2):
        for x in xrange(x1, x2+1):
            self.draw_pixel(x, y1)
            self.draw_pixel(x, y2)
        for y in xrange(y1+1, y2):
            self.draw_pixel(x1, y)
            self.draw_pixel(x2, y)
