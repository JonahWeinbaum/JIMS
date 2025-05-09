import socket
from typing import Optional, Dict, List, Any, Tuple
from constants import *
from flap import *


class ClientContext:
    """Per-client state and utilities."""

    def __init__(self, socket: socket.socket, addr: Tuple[str, int]):
        self.socket = socket
        self.addr = addr
        self.flap_builder = FlapBuilder()
        self.authenticated = False
        self.screen_name = None

    def send_flap(self, channel: FlapChannel, payload: bytes = None):
        flap = self.flap_builder.create_flap(channel, payload)
        try:
            self.socket.send(flap)
            print(
                colored(
                    f"Sent FLAP: Channel={FlapChannel(channel).name}, SeqNum={self.flap_builder.seq_num-1:04x}",
                    "cyan",
                )
            )
        except (socket.error, BrokenPipeError) as e:
            print(colored(f"Failed to send FLAP to {self.addr}: {e}", "red"))

    def send_snac(
        self, family: int, subtype: int, request_id: int, payload: bytes = None
    ):
        snac_data = struct.pack("!HHHI", family, subtype, 0x0000, request_id)
        if payload:
            snac_data += payload
        self.send_flap(FlapChannel.SNAC, snac_data)
