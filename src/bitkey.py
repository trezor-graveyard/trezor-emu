#!/usr/bin/python
'''
    Simulator of hardware bitcoin wallet.
    
    This is not the most elegant Python code I've ever wrote.
    It's purpose is to demonstrate features of hardware wallet
    implemented on microcontroller with very limited resources.
    
    I tried to avoid any dynamic language features, so rewriting
    this prototype to final device should be quite straighforward.
    
    @author: Marek Palatinus (slush) <info@bitcoin.cz>
    @license: GPLv3
'''
import argparse
import time

import bitkey_pb2 as proto
from buttons import Buttons
from layout import Layout
from display import Display
from display_buffer import DisplayBuffer

from wallet import Wallet
from machine import StateMachine

'''
    TODO:
        * PIN-protected seed
        * master private key derived from PIN?
        * Store PIN as a hash
        * SPV
        * P2SH
        * BIP32
        
    Failure codes:
        1 - Unknown method
        2 - Waiting to OTP
        3 - Invalid OTP 
        4 - Cancelled by user ("no" button)
        5 - Waiting to PIN
        6 - Invalid PIN
'''

DISPLAY_WIDTH = 128
DISPLAY_HEIGHT = 64

def parse_args():
    parser = argparse.ArgumentParser(description='Bitkey simulator optimized for Raspberry Pi (but works on any Linux machine).')
    parser.add_argument('-w', '--wallet', dest='wallet', default='wallet.dat', help='Wallet file')
    parser.add_argument('-s', '--shield', dest='shield', action='store_true', help="Use Raspberry Pi shield with OLED display and hardware buttons.")
    parser.add_argument('-t', '--transport', dest='transport', default='serial', help="Transport used for talking with the main computer")
    parser.add_argument('-p', '--path', dest='path', default='/dev/ttyAMA0', help="Path used by the transport (usually serial port)")
    parser.add_argument('-d', '--debuglink', dest='debuglink', action='store_true', help="Enable debugging connection to the main computer")
    parser.add_argument('-dt', '--debuglink-transport', dest='debuglink_transport', default='socket', help="Debuglink transport")
    parser.add_argument('-dp', '--debuglink-path', dest='debuglink_path', default='0.0.0.0:8001', help="Path used by the transport (usually serial port)")
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Enable low-level debugging messages')
    return parser.parse_args()

def get_transport(transport_string, path):
    if transport_string == 'serial':
        from transport_serial import SerialTransport
        return SerialTransport(path)

    if transport_string == 'pipe':
        from transport_pipe import PipeTransport
        return PipeTransport(path, is_device=True)
    
    if transport_string == 'socket':
        print "Socket transport is for development only. NEVER use socket transport with real wallet!"
        from transport_socket import SocketTransport            
        return SocketTransport(path)
    
    if transport_string == 'fake':
        from transport_fake import FakeTransport
        return FakeTransport(path)
    
    raise NotImplemented("Unknown transport")

def main(args):
    # Initialize debuglink transport
    if args.debuglink:
        print "Starting debug connection on '%s'" % args.debuglink_path
        print "Debug connection is for unit tests only. NEVER use debug connection with real wallet!"
        debug_transport = get_transport(args.debuglink_transport, args.debuglink_path)
    else:
        debug_transport = get_transport('fake', None)
        
    # Initialize main transport
    transport = get_transport(args.transport, args.path)
    
    # Load persisted data
    try:
        print "Loading wallet..."
        wallet = Wallet.load(args.wallet)
        if args.verbose:
            print "Using seed:", wallet.get_mnemonic()
    except IOError:
        print "Load failed, starting with new wallet..."
        wallet = Wallet()
    
    # Initialize hardware (screen, buttons)
    but = Buttons(hw=args.shield, stdin=not args.shield, pygame=not args.shield)
    buff = DisplayBuffer(DISPLAY_WIDTH, DISPLAY_HEIGHT)
    display = Display(buff, spi=args.shield, virtual=not args.shield)
    display.init()
    
    # Initialize layout driver
    layout = Layout(buff)
    
    # Startup state machine and switch it to default state
    machine = StateMachine(wallet, layout, is_debuglink=bool(args.debuglink))

    #tx1 = proto.TxOutput(address='1BRMLAB7nryYgFGrG8x9SYaokb8r2ZwAsX', amount=112000000)
    #tx2 = proto.TxOutput(address='1MarekMKDKRb6PEeHeVuiCGayk9avyBGBB', amount=12340123400)
    #layout.show_transactions([tx1, tx2 ], False)
        
    display.refresh()  

    # Main cycle
    while True:
        # Set True if device does something
        # False = device will sleep for a moment
        is_active = False
        
        try:
            # Read button states
            button = but.read()
        except KeyboardInterrupt:
            # User requested to close the app
            break
            
        # Handle debug link connection
        msg = debug_transport.read()
        if msg != None:
            print "Received debuglink", msg.__class__.__name__, msg
            if isinstance(msg, proto.DebugLinkDecision):
                # Press the button
                button = msg.yes_no
            else:
                resp = machine.process_debug_message(msg)
                if resp != None:
                    print "Sending debuglink", resp.__class__.__name__, resp
                    debug_transport.write(resp)
                    is_active = True            
                
            '''
            elif isinstance(msg, proto.DebugLinkGetState):
                # Report device state                
                resp = machine.get_state(msg)
                print "Sending debuglink", resp.__class__.__name__, resp
                debug_transport.write(resp)    
            else:
                raise Exception("Got unexpected object %s" % msg.__class__.__name__)
            '''
                
        if button != None:
            print "Button", button
            is_active = True

            resp = machine.press_button(button)
            if resp != None:
                print "Sending", resp
                transport.write(resp)
                
        '''
        if button == True:
            layout.show_transactions([tx1, tx2 ], False)
            layout.show_question_dummy()
            
        if button == False:
            layout.show_logo(logo)
        '''

        # Handle main connection
        msg = transport.read()
        if msg != None:
            print "Received", msg.__class__.__name__, msg
            resp = machine.process_message(msg)
            if resp != None:
                print "Sending", resp.__class__.__name__, resp
                transport.write(resp)
                is_active = True            
                
        # Display scrolling
        is_active |= layout.update()
        
        if layout.need_refresh:
            # Update display
            display.refresh()
        
        if not is_active:
            # Nothing to do, sleep for a moment
            time.sleep(0.1)
    
    # Save wallet file
    wallet.save(args.wallet)
    
    # Close transports
    transport.close()
    debug_transport.close()
    
if __name__ == '__main__':
    args = parse_args()
    main(args)
