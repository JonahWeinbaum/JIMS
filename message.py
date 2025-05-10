import struct
import pickle
from typing import Optional, Dict, List, Any, Tuple
from constants import *
from tlv import *

try:
    from termcolor import colored
except ImportError:

    def colored(text, *args, **kwargs):
        return text


def construct_message(text: str) -> bytes:
    snac = {
        "family": SnacService.ICBM,
        "subtype": 0x0007,
        "flags": 0x0000,
        "request_id": 0x00000000,
    }

    # Construct message payload
    cookie = 5353
    channel = 1
    screen_name = b"Haystack"
    name_length = len(screen_name)
    payload = struct.pack("!QHB", cookie, channel, name_length)
    payload += screen_name
    payload += b"\x00\x00"  # Warning Level
    payload += b"\x00\x04"  # Number of fixed TLV
    payload += create_tlv(0x01, b"\x00\x04")  # User Class
    payload += create_tlv(0x06, b"\x00\x00\x00\x00")  # User Status
    payload += create_tlv(0x0F, b"\x00\x00\x00\x00")  # Online Time
    payload += create_tlv(0x03, b"\x00\x00\x00\x00")  # Account Creation Time

    # ICBM Data
    icbm_data = b"\x05\x01\x00\x01\x00"
    icbm_data += b"\x01\x01"
    text_bytes = text.encode("ascii")
    icbm_length = len(text_bytes) + 4

    icbm_data += icbm_length.to_bytes(2, "big")
    icbm_data += b"\x00\x00\xff\xff"
    icbm_data += text_bytes
    payload += create_tlv(0x02, icbm_data)  # ICBM Data

    snac["payload"] = payload
    snac_bytes = pickle.dumps(snac)
    return snac_bytes


def parse_message(msg: bytes) -> Dict[str, Any]:
    if len(msg) < 11:
        return None
    cookie, channel, name_length = struct.unpack("!QHB", msg[:11])
    data_start = 11 + name_length

    parsed_msg = {
        "cookie": cookie,
        "channel": channel,
        "screen_name": msg[11:data_start],
    }

    data = msg[data_start:]
    # Channel 1 Parser
    if channel == 1:
        message_text = ""
        tlvs = parse_tlv(data)
        for tlv in tlvs:
            # Message Data
            if tlv["type"] == 0x02:
                tlv_data = tlv["value"]
                _, fragement_length = struct.unpack("!HH", tlv_data[:4])
                message_start = 4 + fragement_length + 4 + 4
                message_text = tlv_data[message_start:]
            # ACK Request
            if tlv["type"] == 0x03:
                continue
            # Store Offline
            if tlv["type"] == 0x06:
                continue

        parsed_msg["message"] = message_text
    return parsed_msg


def visualize_message(msg: Dict[str, Any]) -> str:
    return str(msg)
