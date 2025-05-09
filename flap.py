import struct
from constants import *
from typing import Optional, Dict, List, Any, Tuple

try:
    from termcolor import colored
except ImportError:

    def colored(text, *args, **kwargs):
        return text


class FlapBuilder:
    """Class to construct FLAP packets and manage sequence numbers."""

    def __init__(self):
        self.seq_num = 0

    def create_flap(self, channel: FlapChannel, payload: bytes = None) -> bytes:
        if not isinstance(channel, FlapChannel):
            raise ValueError(f"Invalid channel: {channel}")
        payload = bytes() if payload is None else payload
        if len(payload) > 0xFFFF:
            raise ValueError(f"Payload too large: {len(payload)} bytes (max 65535)")
        seq_num = self.seq_num
        self.seq_num = (self.seq_num + 1) % 0x8000
        header = struct.pack("!BBHH", 0x2A, channel, seq_num, len(payload))
        return header + payload


def parse_flap(data: bytes) -> Tuple[Optional[Dict[str, Any]], bytes]:
    if len(data) < 6 or data[0] != 0x2A:
        return None, data
    channel, seq_num, payload_len = struct.unpack("!BHH", data[1:6])
    flap_len = 6 + payload_len
    if len(data) < flap_len:
        return None, data
    payload = data[6:flap_len]
    return {
        "channel": channel,
        "seq_num": seq_num,
        "payload": payload,
        "header": data[:6],
    }, data[flap_len:]


def visualize_flap(flap: Dict[str, Any]) -> str:
    """Visualize a FLAP packet in a colorized tree-like structure."""
    channel_name = FlapChannel(flap["channel"]).name
    lines = [
        colored(f"FLAP:", "cyan"),
        colored(f"├── Channel: {channel_name}", "yellow"),
        colored(f"├── SeqNum: 0x{flap['seq_num']:04x}", "yellow"),
        colored(f"└── Length: {len(flap['payload'])}", "yellow"),
    ]
    return "\n".join(lines)
