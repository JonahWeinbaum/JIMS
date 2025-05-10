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
from stat_server import stat_server
from dir_server import dir_server
from unknown_server import unk_server

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
    dispatcher.register_handler(SnacService.GENERIC, 0x0002, ClientReadyHandler())
    dispatcher.register_handler(SnacService.GENERIC, 0x0004, ServiceRequestHandler())
    dispatcher.register_handler(SnacService.LOCATION, 0x0002, LocationRightsHandler())
    dispatcher.register_handler(SnacService.LOCATION, 0x0009, DirectoryInfoHandler())
    dispatcher.register_handler(SnacService.LOCATION, 0x0004, SetUserInfoHandler())
    dispatcher.register_handler(SnacService.LOCATION, 0x000B, QueryScreenNameHandler())
    dispatcher.register_handler(SnacService.LOCATION, 0x000F, KeywordInfoHandler())
    dispatcher.register_handler(SnacService.ICBM, 0x0004, ChatParameterHandler())
    dispatcher.register_handler(SnacService.BUDDY, 0x0002, BuddyRightsHandler())

    parser.register_handler(SnacService.AUTH, 0x0006, AuthKeyRequestParser())
    parser.register_handler(SnacService.AUTH, 0x0002, LoginRequestParser())
    parser.register_handler(SnacService.GENERIC, 0x0017, FamilyVersionParser())
    parser.register_handler(SnacService.GENERIC, 0x0004, ServiceRequestParser())
    parser.register_handler(SnacService.GENERIC, 0x0011, IdleTimeParser())
    parser.register_handler(SnacService.GENERIC, 0x0002, ClientReadyParser())
    parser.register_handler(SnacService.LOCATION, 0x0002, LocationRightsParser())
    parser.register_handler(SnacService.LOCATION, 0x0009, DirectoryInfoParser())
    parser.register_handler(SnacService.LOCATION, 0x0004, SetUserInfoParser())
    parser.register_handler(SnacService.LOCATION, 0x000B, QueryScreenNameParser())
    parser.register_handler(SnacService.LOCATION, 0x000F, KeywordInfoParser())
    parser.register_handler(SnacService.ICBM, 0x0004, ChatParameterParser())
    parser.register_handler(SnacService.ICBM, 0x0006, ChatMessageParser())
    parser.register_handler(SnacService.BUDDY, 0x0002, BuddyRightsParser())

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

    # Start STAT server
    stat_address, stat_port = STAT_SERVER_ADDRESS.split(":")
    stat_thread = threading.Thread(
        target=stat_server,
        args=(stat_address, int(stat_port), dispatcher, parser, SCREEN_NAME),
    )
    stat_thread.daemon = True
    stat_thread.start()

    # Start DIR server
    dir_address, dir_port = DIR_SERVER_ADDRESS.split(":")
    dir_thread = threading.Thread(
        target=dir_server,
        args=(dir_address, int(dir_port), dispatcher, parser, SCREEN_NAME),
    )
    dir_thread.daemon = True
    dir_thread.start()

    # Start UNK server
    unk_address, unk_port = UNK_SERVER_ADDRESS.split(":")
    unk_thread = threading.Thread(
        target=unk_server,
        args=(unk_address, int(unk_port), dispatcher, parser, SCREEN_NAME),
    )
    unk_thread.daemon = True
    unk_thread.start()

    # Wait on all threads completion
    try:
        auth_thread.join()
        bos_thread.join()
        stat_thread.join()
    except KeyboardInterrupt:
        print(colored("Shutting down all servers", "blue"))


if __name__ == "__main__":
    main()
