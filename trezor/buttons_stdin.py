from select import select  # For raw_input timeout
import sys


class StdinButtons(object):
    def __init__(self):
        print "Press y+<enter> to confirm an action."
        print "Press n+<enter> to cancel an action."

    def read(self):
        rlist, _, _ = select([sys.stdin], [], [], 0)
        if not rlist:
            return None

        keys = sys.stdin.readline()
        if 'n' in keys:
            return False

        if 'y' in keys:
            return True

        return None
