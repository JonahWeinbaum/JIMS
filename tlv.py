import struct
from typing import Optional, Dict, List, Any, Tuple

try:
    from termcolor import colored
except ImportError:

    def colored(text, *args, **kwargs):
        return text


def create_tlv(type_: int, value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError(f"TLV value too large: {len(value)} bytes (max 65535)")
    return struct.pack("!HH", type_, len(value)) + value


def parse_tlv(data: bytes) -> List[Dict[str, Any]]:
    tlvs = []
    offset = 0
    while offset + 4 <= len(data):
        type_, length = struct.unpack("!HH", data[offset : offset + 4])
        if offset + 4 + length > len(data):
            print(
                colored(
                    f"Invalid TLV: type={type_:04x}, length={length}, remaining={len(data)-offset}",
                    "red",
                )
            )
            break
        value = data[offset + 4 : offset + 4 + length]
        tlvs.append({"type": type_, "value": value})
        offset += 4 + length
    return tlvs
