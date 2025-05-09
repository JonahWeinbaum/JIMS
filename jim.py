import struct
from enum import IntEnum
import socket
import threading
import time
import os
from typing import Optional, Dict, List, Any, Tuple
from constants import *
from flap import *
from tlv import *
from client import *
from snac_handler import *
from snac_parser import *
from utils import format_hex_ascii
from auth_server import auth_server
from bos_server import bos_server

try:
    from termcolor import colored
except ImportError:

    def colored(text, *args, **kwargs):
        return text


# Globals
SCREEN_NAME = ""


def main():
    """Run auth and BOS servers in separate threads."""
    # Initialize shared dispatcher and visualizer
    dispatcher = SnacDispatcher()
    parser = SnacParser()

    # Register handlers
    dispatcher.register_handler(SnacService.AUTH, 0x0006, AuthKeyRequestHandler())
    dispatcher.register_handler(SnacService.AUTH, 0x0002, LoginRequestHandler())
    dispatcher.register_handler(SnacService.GENERIC, 0x0017, FamilyVersionHandler())
    dispatcher.register_handler(SnacService.GENERIC, 0x0006, RateRequestHandler())
    dispatcher.register_handler(SnacService.GENERIC, 0x000E, OnlineInfoHandler())
    dispatcher.register_handler(SnacService.GENERIC, 0x0011, IdleTimeHandler())

    parser.register_handler(SnacService.AUTH, 0x0006, AuthKeyRequestParser())
    parser.register_handler(SnacService.AUTH, 0x0002, LoginRequestParser())
    parser.register_handler(SnacService.GENERIC, 0x0017, FamilyVersionParser())
    parser.register_handler(SnacService.GENERIC, 0x0004, ServiceRequestParser())
    parser.register_handler(SnacService.GENERIC, 0x0011, IdleTimeParser())

    # Start auth server
    auth_address, auth_port = AUTH_SERVER_ADDRESS.split(":")
    auth_thread = threading.Thread(
        target=auth_server,
        args=(auth_address, int(auth_port), dispatcher, parser),
    )
    auth_thread.daemon = True
    auth_thread.start()

    # Start BOS server
    bos_address, bos_port = BOS_SERVER_ADDRESS.split(":")
    bos_thread = threading.Thread(
        target=bos_server,
        args=(bos_address, int(bos_port), dispatcher, parser, SCREEN_NAME),
    )
    bos_thread.daemon = True
    bos_thread.start()

    # Wait on all threads completion
    try:
        auth_thread.join()
        bos_thread.join()
    except KeyboardInterrupt:
        print(colored("Shutting down all servers", "blue"))


if __name__ == "__main__":
    main()
