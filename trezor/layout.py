import time
import smallfonts
from logo import logo as default_logo

class Layout(object):
    def __init__(self, buff, display):
        self.line_len_normal = 21
        self.line_len_bold = 16
        self.buffer = buff
        self.display = display

        self.clear()

    def clear(self):
        # Clear the area
        self.buffer.clear()  # (0, 0, self.buffer.width-1, self.buffer.height-1)
        self.display.refresh()

    def update(self, button):
        """return proper (is_refresh, is_active) if layout has something to render"""
        return (False, button)

    def show_logo(self, logo=None, label=None):
        self.clear()
        if logo:
            self.buffer.draw_bitmap(logo)
        else:
            self.buffer.draw_bitmap(default_logo)

        if label:
            self._show_status(label, '', '')

        self.display.refresh()

    def show_message(self, messages):
        # Print message to console
        self.show_question(messages, '', '', '')

    def show_verified_message(self, address, message):
        msg = ['_c' + address[:len(address) / 2],
               '_c' + address[len(address) / 2:],
               '_c' + message[:21],
               '_c' + message[21:42],
               '_c' + message[42:63]]
        self.show_question(msg, "Successfully verified", 'Continue', '')
        
    def show_receiving_address(self, address):
        self.show_message(
            # .....................
            ['_cThis address can be',
             '_csafely used for',
             '_creceiving new funds:',
             '_c' + address[:len(address) / 2],
             '_c' + address[len(address) / 2:], ])

    def show_send_tx(self, amount, coin):
        self.show_question(
            #   .....................
            ['',
             '_cReally send amount of',
             '_c' + self._prepare_amount(amount, coin),
             '_cout of the wallet?'],
             'Really send?', 'Confirm', 'Cancel'
        )

    def show_question(self, lines, question, yes_text, no_text):
        # Print message to console
        print '-' * len(' '.join(lines))
        print ' '.join(lines)
        if question:
            print question, ' (y/n)'

        font = smallfonts.Font5x8
        self.clear()

        for i in range(len(lines)):
            msg = lines[i]
            self.buffer.draw_string(0, i * font.height + 1, msg, font)
        self._show_status(question, yes_text, no_text)
        self.display.refresh()

    def request_passphrase(self, msg):
        self.show_message(
            #   .....................
            ['',
             '_cPlease enter',
             '',
             '_cwallet passphrase',
             '',
             '_con computer keyboard'])

    def show_question_dummy(self):
        self.show_question(
            # .....................
            ['Tohle je nejaka',
             'zprava, kterou chci',
             'uzivateli zobrazi na',
             'internim displeji',
             'internim displeji'],
            'Question?', 'Confirm', 'Cancel')

    '''
    def show_pin_request(self):
        self.show_question(
            ["Please write your",
             "PIN code to",
             "the computer"],
            '', '', '{ Cancel')
    '''

    def show_pin_backoff_progress(self, delay):
        start = time.time()
        maximum = int(delay * 10)
        while time.time() - start < delay:
            current = int((time.time() - start) * 10)
            clear = True if current == 0 else False
            
            self.show_progress(current, maximum, clear, default_logo)    
            time.sleep(0.1)

    def show_progress(self, current, maximum, clear=False, logo=None):
        if clear:
            self.clear()
            if logo:
                self.show_logo(logo)

            self.buffer.clear(0, self.buffer.height - 11, self.buffer.width - 1, self.buffer.height - 1)
            self.buffer.frame(0, self.buffer.height - 10, self.buffer.width - 1, self.buffer.height - 1)

        if current > maximum:
            current = maximum

        width = int((self.buffer.width - 5) * (current / float(maximum)))
        self.buffer.box(2, self.buffer.height - 8, width + 2, self.buffer.height - 3)
        self.display.refresh()

    def show_high_fee(self, fee, coin):
        amount_str = self._prepare_amount(fee, coin)
        self.show_question(['Transaction fee', amount_str, 'seem too high!'],
                        'Really pay such fee?', '{ Cancel', 'Confirm }')

    def show_output(self, coin, address, amount):
        amount_str = self._prepare_amount(amount, coin)

        # Quick & dirty splitting address to two lines
        addr_1 = address[:len(address) / 2]
        addr_2 = address[len(address) / 2:]

        self.show_question(["_cSend", "_c" + amount_str, "_cto", "_c" + addr_1, "_c" + addr_2],
                           '', 'Confirm }', '{ Cancel')
                        
    '''
    def show_transactions(self, txes, more=False):
        self.clear()

        for i in range(len(txes)):
            tx = txes[i]

            # Write address
            #self.buffer.draw_string(0, 0, address[:self.line_len_normal], smallfonts.Font5x8)
            self._scroll_text(i * 22, tx.address, smallfonts.Font5x8)

            # Write amount
            self.buffer.draw_string(0, i * 22 + 10, self._prepare_amount(tx.amount), smallfonts.Font7x8)

            # Make amount inverted
            self.buffer.invert(0, i * 22 + 9, self.buffer.width - 1, i * 22 + 17)

        self._show_status('Confirm outputs?', 'More \x7e' if more else 'Confirm }', '{ Cancel')
        self.display.refresh()
    '''

    def _prepare_amount(self, amount, coin):

        if amount > 21 * 10 ** 14 or amount < 0:
            return "Invalid amount"

        amount = float(amount) / 10 ** 8  # From satoshis to bitcoins
        s = ("%.08f" % amount).rstrip('0').rstrip('.')
        s = "%s %s" % (s, coin.coin_shortcut)
        return s

    def _show_status(self, status, yes_text, no_text, invert=False):
        # Status line
        if yes_text or no_text:
            delta = 0
        else:
            delta = -10

        if status != '':
            self.buffer.clear(0, self.buffer.height - delta - 20, self.buffer.width - 1, self.buffer.height - 1)

            self.buffer.frame(0, self.buffer.height - delta - 20, self.buffer.width - 1, self.buffer.height - delta - 20)
            self.buffer.draw_string(0, self.buffer.height - delta - 18, "_c" + status, smallfonts.Font5x8)
        elif yes_text or no_text:

            self.buffer.clear(0, self.buffer.height - delta - 12, self.buffer.width - 1, self.buffer.height - 1)
            self.buffer.frame(0, self.buffer.height - 12, self.buffer.width - 1, self.buffer.height - 12)

        # Left button title
        if no_text != '':
            self.buffer.draw_string(1, self.buffer.height - 9, no_text, smallfonts.Font5x8)
            self.buffer.invert(0, self.buffer.height - 10, len(no_text) * 6 + 1, self.buffer.height - 1)

        # Right button trange = random.shuffle(range(1, 10)) itle
        if yes_text != '':
            self.buffer.draw_string(self.buffer.width - 1 - len(yes_text) * 6, self.buffer.height - 9, yes_text,
                                    smallfonts.Font5x8)
            self.buffer.invert(self.buffer.width - 3 - len(yes_text) * 6, self.buffer.height - 10,
                               self.buffer.width - 1, self.buffer.height - 1)

        if invert:
            self.buffer.invert(0, self.buffer.height - delta - 20, self.buffer.width - 1, self.buffer.height - 1)

    def show_matrix(self, matrix, msg):
        '''Renders combination matrix into field of 3x3'''

        box_width = 16
        box_height = 16
        font = smallfonts.Font5x8
        font_margin_x = 6
        font_margin_y = 5

        left = (self.buffer.width - 3*box_width) / 2
        top = 12

        def draw_box(num, x, y):
            self.buffer.draw_string(left+x*box_width+font_margin_x, top+y*box_height+font_margin_y, str(num), font)
            self.buffer.frame(left+x*box_width, top+y*box_width, left+(x+1)*box_width, top+(y+1)*box_width)

        self.clear()
        print 'Matrix:'
        
        if msg:
            self.buffer.draw_string(0, 2, '_c' + msg, font)
        
        for y in range(3):
            for x in range(3):
                print matrix[x + (2 - y) * 3],
                draw_box(matrix[x + (2 - y) * 3], x, y)

            print

        self.display.refresh()
