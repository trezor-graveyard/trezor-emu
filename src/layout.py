import smallfonts
import time
import math

class Layout(object):
    def __init__(self, buffer):
        self.line_len_normal = 21
        self.line_len_bold = 16
        self.buffer = buffer
        self.update_delta = 0.05
        self.clear()
        
    def clear(self):
        self.last_update = time.time()
        self.scrolls = []
        
        # Clear the area
        self.buffer.clear()#(0, 0, self.buffer.width-1, self.buffer.height-1)
        self.need_refresh = True

    def update(self):
        '''return proper (is_refresh, is_active) if layout has something to render'''
        
        t = time.time()        
        if t - self.last_update < self.update_delta:
            if len(self.scrolls):
                return True # No need for rendering, but active
            else:
                return False # Nothing to do
        self.last_update = t
        
        if not len(self.scrolls):
            return False # Nothing to do
        
        for item in self.scrolls:
            (direction, wait, pos_x, y, text, font) = item

            width = len(text) * (font.width+1)
            
            if wait:
                item[1] -= 1
                
            elif width >= self.buffer.width:
              
                if pos_x < -width+self.buffer.width+1 and direction == -1:
                    item[0] = 1 # Change direction
                    item[1] = 20 # Set wait cycles
    
                if pos_x >= 0 and direction == 1:
                    item[0] = -1 # Change direction
                    item[1] = 20 # Set wait cycles
    
                
                pos_x += direction            
                item[2] = pos_x
                
                self.need_refresh = True

            self._draw_scroll_text(pos_x, y, text, font)

        return True
    
    def _draw_scroll_text(self, x, y, text, font):
        self.buffer.clear(0, y, self.buffer.width-1, y+font.height)
        self.buffer.draw_string(x, y, text, font)

    def _scroll_text(self, y, text, font):
        # direction, x pos delta, pos_y, text, font
        details = [-1, 30, 0, y, text, font]
        self._draw_scroll_text(0, y, text, font)
        self.scrolls.append(details)
                    
    def show_logo(self, logo):
        self.clear()
        self.buffer.draw_bitmap(logo)
        self.need_refresh = True

    def show_message(self, messages):
        # Print message to console
        self.show_question(messages, '', 'Continue }', '')

    def show_question(self, messages, question, yes_text, no_text):
        # Print message to console
        print '-' * len(' '.join(messages))
        print ' '.join(messages)
        if question:
            print question, ' (y/n)'
        
        self.clear()
        font = smallfonts.Font5x8

        for i in range(len(messages)):
            msg = messages[i]
            self.buffer.draw_string(0, i*font.height+1, msg, font)

        self._show_status(question, yes_text, no_text)
        self.need_refresh = True
        
    def show_question_dummy(self):
        self.show_question(
            # .....................
            ['Tohle je nejaka',
             'zprava, kterou chci',
             'uzivateli zobrazi na',
             'internim displeji',
             'internim displeji'],
            'Question?', 'Confirm', 'Cancel')

    def show_pin_request(self):
        self.show_question(
            ["Please write you",
             "PIN code to",
             "the computer"],
            '', '', '{ Cancel')
        
    def show_otp_request(self, otp):
        self.show_question(
            ["Please rewrite this",
             "one time password",
             "to computer:",
             '',
             otp.rjust(int(10+len(otp)/2), ' ')],
            '', '', '{ Cancel')
                                 
    def show_progress(self, current, maximum, clear=False, logo=None):
        if clear:
            self.clear()
            if logo:
                self.show_logo(logo)
            
            self.buffer.clear(0,self.buffer.height-11, self.buffer.width-1, self.buffer.height-1)
            self.buffer.frame(0,self.buffer.height-10, self.buffer.width-1, self.buffer.height-1)
            
        if current > maximum:
            current = maximum
            
        width = int((self.buffer.width-5) * (current / float(maximum)))
        self.buffer.box(2, self.buffer.height-8, width+2, self.buffer.height-3)
        self.need_refresh = True
        
    def show_transactions(self, txes, more=False):
        self.clear()
        
        for i in range(len(txes)):
            tx = txes[i]
            
            # Write address    
            #self.buffer.draw_string(0, 0, address[:self.line_len_normal], smallfonts.Font5x8)
            self._scroll_text(i*22, tx.address, smallfonts.Font5x8)
                
            # Write amount
            self.buffer.draw_string(0, i*22+10, self._prepare_amount(tx.amount), smallfonts.Font7x8)
            
            # Make amount inverted            
            self.buffer.invert(0, i*22+9, self.buffer.width-1, i*22+17)
            
        self._show_status('Confirm outputs?', 'More \x7e' if more else 'Confirm }', '{ Cancel')
        self.need_refresh = True
        
    def _prepare_amount(self, amount):
        
        if amount > 21*10**14 or amount < 0:
            return "Invalid amount"
        
        amount = float(amount)/10**8    # From satoshis to bitcoins
        s = ("%.08f" % amount).rstrip('0').rstrip('.')
        if len(s) <= self.line_len_bold - 4:
            s = "%s BTC" % s
        elif len(s) <= self.line_len_bold - 2:
            s = "%s \x80" % s
        else:
            s = "%s \x80" % s[:self.line_len_bold - 2]
        
        return s.rjust(self.line_len_bold, ' ')
        
    def _show_status(self, status, yes_text, no_text):
        # Status line
        if status != '':
            pos = self.buffer.width/2 - len(status)*(smallfonts.Font5x8.width+1)/2
            self.buffer.clear(0, self.buffer.height-20, self.buffer.width-1, self.buffer.height-1)
            self.buffer.frame(0, self.buffer.height-20, self.buffer.width-1, self.buffer.height-20)
            self.buffer.draw_string(pos, self.buffer.height-18, status, smallfonts.Font5x8)
        else:
            self.buffer.clear(0, self.buffer.height-11, self.buffer.width-1, self.buffer.height-1)
            self.buffer.frame(0, self.buffer.height-12, self.buffer.width-1, self.buffer.height-12)
            
        # Left button title
        if no_text != '':
            self.buffer.draw_string(1, self.buffer.height-9, no_text, smallfonts.Font5x8)
            self.buffer.invert(0, self.buffer.height-10, len(no_text)*6+1, self.buffer.height-1)
        
        # Right button title
        if yes_text != '':
            self.buffer.draw_string(self.buffer.width-1-len(yes_text)*6, self.buffer.height-9, yes_text, smallfonts.Font5x8)
            self.buffer.invert(self.buffer.width-3-len(yes_text)*6, self.buffer.height-10, self.buffer.width-1, self.buffer.height-1)