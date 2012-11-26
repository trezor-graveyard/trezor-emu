from select import select # For raw_input timeout
import sys

class StdinButtons(object):
    def read(self):
        rlist, _, _ = select([sys.stdin], [], [], 0)
        if not rlist:                
            return None
        
        key = sys.stdin.readline()[0]
        if key == 'y':
            return True
        
        if key == 'n':
            return False
        
        return None
        
                        