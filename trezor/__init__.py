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

import messages_pb2 as proto
from buttons import Buttons
from layout import Layout
from display import Display
from display_buffer import DisplayBuffer
#from logo import logo                          # uncomment this line if you uncomment 'layout.show_logo(logo)' on line 180

from storage import Storage
from machine import StateMachine

from tools import monkeypatch_google_protobuf_text_format
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
        2 - Waiting to OTPdef monkeypatch_google_protobuf_text_format():
    # monkeypatching: text formatting of protobuf messages
    import google.protobuf.text_format
    import google.protobuf.descriptor

    _oldPrintFieldValue = google.protobuf.text_format.PrintFieldValue

    def _customPrintFieldValue(field, value, out, indent=0, as_utf8=False, as_one_line=False):
        if field.cpp_type == google.protobuf.descriptor.FieldDescriptor.CPPTYPE_STRING and \
            str(field.GetOptions()).strip() == '[binary]:':  # binary option set
                _oldPrintFieldValue(field, 'hex(%s) str(%s)' % (binascii.hexlify(value), value), out, indent, as_utf8, as_one_line)

        else:
            _oldPrintFieldValue(field, value, out, indent, as_utf8, as_one_line)

    google.protobuf.text_format.PrintFieldValue = _customPrintFieldValue
        3 - Invalid OTP
        4 - Cancelled by user ("no" button)
        5 - Waiting to PIN
        6 - Invalid PIN
'''

DISPLAY_WIDTH = 128
DISPLAY_HEIGHT = 64


def parse_args():
    parser = argparse.ArgumentParser(description='TREZOR simulator optimized for Raspberry Pi (but works on any '
                                                 'Linux machine).')

    parser.add_argument('-w', '--wallet', dest='wallet', default='wallet.dat', help='Wallet file')
    parser.add_argument('-s', '--shield', dest='shield', action='store_true',
                        help="Use Raspberry Pi shield with OLED display and hardware buttons.")
    parser.add_argument('-b', '--bootloader', dest='bootloader_mode', action='store_true',
                        help="Simulate bootloader mode (it actually doesn't store the uploaded firmware).")
    parser.add_argument('-t', '--transport', dest='transport', default='cp2110',
                        help="Transport used for talking with the main computer")
    parser.add_argument('-p', '--path', dest='path', default='/dev/ttyAMA0',
                        help="Path used by the transport (usually serial port)")
    parser.add_argument('-d', '--debuglink', dest='debuglink', action='store_true',
                        help="Enable debugging connection to the main computer")
    parser.add_argument('-dt', '--debuglink-transport', dest='debuglink_transport', default='socket',
                        help="Debuglink transport")
    parser.add_argument('-dp', '--debuglink-path', dest='debuglink_path', default='0.0.0.0:8001',
                        help="Path used by the transport (usually serial port)")
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
                        help='Enable low-level debugging messages')
    return parser.parse_args()


def get_transport(transport_string, path):
    if transport_string == 'cp2110':
        # Transport compatible with CP2110 HID-to-UART chip
        # (used by Trezor shield)
        from transport_cp2110 import Cp2110Transport
        return Cp2110Transport(path)

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
    monkeypatch_google_protobuf_text_format()

    # Initialize debuglink transport
    if args.debuglink:
        print "Starting debug connection on '%s'" % args.debuglink_path
        print "Debug connection is for unit tests only. NEVER use debug connection with real wallet!"
        debug_transport = get_transport(args.debuglink_transport, args.debuglink_path)
    else:
        debug_transport = get_transport('fake', None)

    # Initialize main transport
    transport = get_transport(args.transport, args.path)

    # Load persisted data. Create new wallet if file doesn't exist
    print "Loading wallet..."
    storage = Storage(args.wallet, bootloader_mode=args.bootloader_mode)
    # storage.struct.settings.label = 'Slushova penezenka'
    print storage.struct

    # Initialize hardware (screen, buttons)
    but = Buttons(hw=args.shield, stdin=not args.shield, pygame=not args.shield)
    buff = DisplayBuffer(DISPLAY_WIDTH, DISPLAY_HEIGHT)
    display = Display(buff, spi=args.shield, virtual=not args.shield)
    display.init()

    # Initialize layout driver
    layout = Layout(buff, display)

    # Process exponential backoff if there was unsuccesfull PIN attempts
    if storage.get_pin_delay():
        delay = storage.get_pin_delay()
        print "Waiting %s seconds until boot up" % delay
        layout.show_pin_backoff_progress(delay)

    # Startup state machine and switch it to default state
    machine = StateMachine(storage, layout)

    display.refresh()

    # Main cycle
    while True:
        try:
            # Read button states
            button = but.read()
        except KeyboardInterrupt:
            # User requested to close the app
            break

        # Set is_active=True if device does something
        # False = device will sleep for a moment to prevent CPU load
        # Set button=None to use event only for rendering
        # and hide it against state machine
        (is_active, button) = layout.update(button)

        # Handle debug link connection
        msg = debug_transport.read()
        if msg is not None:
            print "Received debuglink", msg.__class__.__name__, msg
            if isinstance(msg, proto.DebugLinkDecision):
                # Press the button
                button = msg.yes_no
            else:
                resp = machine.process_debug_message(msg)
                if resp is not None:
                    print "Sending debuglink", resp.__class__.__name__, resp
                    debug_transport.write(resp)
                    is_active = True

        if button is not None:
            print "Button", button
            is_active = True

            resp = machine.press_button(button)
            if resp is not None:
                print "Sending", resp
                transport.write(resp)

        # Handle main connection
        msg = transport.read()
        if msg is not None:
            print "Received", msg.__class__.__name__, msg
            resp = machine.process_message(msg)
            if resp is not None:
                print "Sending", resp.__class__.__name__, resp
                transport.write(resp)
                is_active = True

        if not is_active:
            # Nothing to do, sleep for a moment
            time.sleep(0.05)

    # Close transports
    transport.close()
    debug_transport.close()


def run():
    args = parse_args()
    main(args)


if __name__ == '__main__':
    run()
