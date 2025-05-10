import struct
from typing import Optional, Dict, List, Any, Tuple
from constants import *
from tlv import *

try:
    from termcolor import colored
except ImportError:

    def colored(text, *args, **kwargs):
        return text


class SnacParserHandler:
    """Base class for SNAC visualization handlers."""

    def visualize(self, snac: bytes) -> str:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])

        lines = [
            colored(
                f"SNAC: Family=0x{family:04x}, Subtype=0x{subtype:04x}, "
                f"Flags=0x{flags:04x}, RequestID=0x{request_id:08x}",
                "green",
            )
        ]

        data = snac[10:]
        tlvs = parse_tlv(data)

        for i, tlv in enumerate(tlvs):
            type_name = (
                TlvType(tlv["type"]).name
                if tlv["type"] in TlvType
                else f"0x{tlv['type']:04x}"
            )

            value_str = (
                tlv["value"].decode("ascii", errors="ignore")
                if tlv["value"]
                else "empty"
            )
            if i < len(tlvs) - 1:
                lines.append(
                    colored(
                        f"├── TLV: Type={type_name}, Length={len(tlv['value'])}, Value={repr(value_str)}",
                        "yellow",
                    )
                )
            else:
                lines.append(
                    colored(
                        f"└── TLV: Type={type_name}, Length={len(tlv['value'])}, Value={repr(value_str)}",
                        "yellow",
                    )
                )
        return "\n".join(lines)

    def parse(self, snac: bytes) -> Dict[str, Any]:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])

        # TODO Separate TLV fields
        data = snac[10:]
        tlvs = parse_tlv(data)
        return {
            "family": family,
            "subtype": subtype,
            "flags": flags,
            "request_id": request_id,
            "tlvs": tlvs,
            "payload": data,
        }


class DefaultSnacParser(SnacParserHandler):
    """Default visualizer for unregistered SNACs."""


class AuthKeyRequestParser(SnacParserHandler):
    """Parser for SNAC(17,06) - MD5 key request."""


class LoginRequestParser(SnacParserHandler):
    """Parser for SNAC(17,02) - Login request."""


class ClientReadyParser(SnacParserHandler):
    """Parser for SNAC(01,02) - Client ready."""

    def visualize(self, snac: bytes) -> str:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])
        lines = [
            colored(
                f"SNAC: Family=0x{family:04x} (GENERIC), Subtype=0x{subtype:04x} (Client Ready), "
                f"Flags=0x{flags:04x}, RequestID=0x{request_id:08x}",
                "green",
            )
        ]
        lines.append(
            colored(
                f"└── Client ready!",
                "cyan",
            )
        )
        return "\n".join(lines)

    def parse(self, snac: bytes) -> Dict[str, Any]:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])
        return {
            "family": family,
            "subtype": subtype,
            "flags": flags,
            "request_id": request_id,
        }


class QueryScreenNameParser(SnacParserHandler):
    """Parser for SNAC(02,0b) - Query screen name."""

    def visualize(self, snac: bytes) -> str:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])
        lines = [
            colored(
                f"SNAC: Family=0x{family:04x} (LOCATION), Subtype=0x{subtype:04x} (Query User Info), "
                f"Flags=0x{flags:04x}, RequestID=0x{request_id:08x}",
                "green",
            )
        ]
        lines.append(
            colored(
                f"└── Screen Name = {snac[11:]}",
                "cyan",
            )
        )
        return "\n".join(lines)

    def parse(self, snac: bytes) -> Dict[str, Any]:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])
        screen_name = snac[11:]
        return {
            "family": family,
            "subtype": subtype,
            "flags": flags,
            "request_id": request_id,
            "screen_name": screen_name,
        }


class ServiceRequestParser(SnacParserHandler):
    """Parser for SNAC(01,04) - Service request."""

    def visualize(self, snac: bytes) -> str:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id, service = struct.unpack("!HHHIH", snac[:12])
        lines = [
            colored(
                f"SNAC: Family=0x{family:04x} (GENERIC), Subtype=0x{subtype:04x} (Service Request), "
                f"Flags=0x{flags:04x}, RequestID=0x{request_id:08x}",
                "green",
            )
        ]
        lines.append(
            colored(
                f"└── Family = {SnacService(service).name}",
                "cyan",
            )
        )
        return "\n".join(lines)

    def parse(self, snac: bytes) -> Dict[str, Any]:
        if len(snac) < 12:
            return None
        family, subtype, flags, request_id, service = struct.unpack("!HHHIH", snac[:12])
        return {
            "family": family,
            "subtype": subtype,
            "flags": flags,
            "request_id": request_id,
            "service": service,
        }


class SetUserInfoParser(SnacParserHandler):
    """Parser for SNAC(02,04) - Set user info request."""

    def visualize(self, snac: bytes) -> str:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id, service = struct.unpack("!HHHIH", snac[:12])
        type_names: Dict[int, bytes] = {
            0x01: b"ASCII",
            0x02: b"Profile",
            0x03: b"ASCII",
            0x04: b"Away Message",
            0x05: b"Capabilities",
        }
        lines = [
            colored(
                f"SNAC: Family=0x{family:04x} (LOCATION), Subtype=0x{subtype:04x} (Service Request), "
                f"Flags=0x{flags:04x}, RequestID=0x{request_id:08x}",
                "green",
            )
        ]
        data = snac[10:]
        tlvs = parse_tlv(data)

        for i, tlv in enumerate(tlvs):
            type_name = type_names[tlv["type"]]

            value_hex = " ".join(
                a + b for a, b in zip(tlv["value"].hex()[::2], tlv["value"].hex()[1::2])
            )
            value_str = repr(tlv["value"]) if tlv["value"] else "empty"
            if tlv["type"] == 0x05:
                value_str = value_hex
            if i < len(tlvs) - 1:
                lines.append(
                    colored(
                        f"├── TLV: Type={type_name}, Length={len(tlv['value'])}, Value={repr(value_str)}",
                        "yellow",
                    )
                )
            else:
                lines.append(
                    colored(
                        f"└── TLV: Type={type_name}, Length={len(tlv['value'])}, Value={repr(value_str)}",
                        "yellow",
                    )
                )
        return "\n".join(lines)

    def parse(self, snac: bytes) -> Dict[str, Any]:
        if len(snac) < 12:
            return None
        family, subtype, flags, request_id, service = struct.unpack("!HHHIH", snac[:12])
        return {
            "family": family,
            "subtype": subtype,
            "flags": flags,
            "request_id": request_id,
        }


class LocationRightsParser(SnacParserHandler):
    """Parser for SNAC(02,02) - Request location rights."""

    def visualize(self, snac: bytes) -> str:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])
        lines = [
            colored(
                f"SNAC: Family=0x{family:04x} (LOCATION), Subtype=0x{subtype:04x} (Location Rights Request), "
                f"Flags=0x{flags:04x}, RequestID=0x{request_id:08x}",
                "green",
            )
        ]

        return "\n".join(lines)

    def parse(self, snac: bytes) -> Dict[str, Any]:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])
        return {
            "family": family,
            "subtype": subtype,
            "flags": flags,
            "request_id": request_id,
        }


class BuddyRightsParser(SnacParserHandler):
    """Parser for SNAC(03,02) - Request buddy rights."""

    def visualize(self, snac: bytes) -> str:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])
        lines = [
            colored(
                f"SNAC: Family=0x{family:04x} (BUDDY), Subtype=0x{subtype:04x} (Buddy Rights Request), "
                f"Flags=0x{flags:04x}, RequestID=0x{request_id:08x}",
                "green",
            )
        ]

        return "\n".join(lines)

    def parse(self, snac: bytes) -> Dict[str, Any]:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])
        return {
            "family": family,
            "subtype": subtype,
            "flags": flags,
            "request_id": request_id,
        }


class IdleTimeParser(SnacParserHandler):
    """Parser for SNAC(01,11) - Set idle time."""

    def visualize(self, snac: bytes) -> str:
        if len(snac) < 14:
            return None
        family, subtype, flags, request_id, idle_sec = struct.unpack(
            "!HHHII", snac[:14]
        )
        lines = [
            colored(
                f"SNAC: Family=0x{family:04x} (GENERIC), Subtype=0x{subtype:04x} (Set Idle Time), "
                f"Flags=0x{flags:04x}, RequestID=0x{request_id:08x}",
                "green",
            )
        ]
        lines.append(
            colored(
                f"└── Idle Seconds = {idle_sec}",
                "cyan",
            )
        )
        return "\n".join(lines)

    def parse(self, snac: bytes) -> Dict[str, Any]:
        if len(snac) < 14:
            return None
        family, subtype, flags, request_id, idle_sec = struct.unpack(
            "!HHHII", snac[:14]
        )

        return {
            "family": family,
            "subtype": subtype,
            "flags": flags,
            "request_id": request_id,
            "idle_sec": idle_sec,
        }


class DirectoryInfoParser(SnacParserHandler):
    """Parser for SNAC(02,09) - Locate directory info request."""

    def visualize(self, snac: bytes) -> str:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])

        lines = [
            colored(
                f"SNAC: Family=0x{family:04x} (LOCATION) , Subtype=0x{subtype:04x} (Directory Info Request), "
                f"Flags=0x{flags:04x}, RequestID=0x{request_id:08x}",
                "green",
            )
        ]

        data = snac[10:]
        tlvs = parse_tlv(data)
        type_names: Dict[int, bytes] = {
            0x01: b"First Name",
            0x02: b"Last Name",
            0x03: b"Middle Name",
            0x04: b"Maiden Name",
            0x06: b"Country",
            0x07: b"State",
            0x08: b"City",
            0x0A: b"Unknown",
            0x0C: b"Nickname",
            0x0D: b"Zip",
            0x21: b"Address",
        }
        for i, tlv in enumerate(tlvs):
            type_name = type_names[tlv["type"]]
            value_str = (
                tlv["value"].decode("ascii", errors="ignore")
                if tlv["value"]
                else "empty"
            )
            if i < len(tlvs) - 1:
                lines.append(
                    colored(
                        f"├── TLV: Type={type_name}, Length={len(tlv['value'])}, Value={repr(value_str)}",
                        "yellow",
                    )
                )
            else:
                lines.append(
                    colored(
                        f"└── TLV: Type={type_name}, Length={len(tlv['value'])}, Value={repr(value_str)}",
                        "yellow",
                    )
                )
        return "\n".join(lines)

    def parse(self, snac: bytes) -> Dict[str, Any]:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])

        # TODO Separate TLV fields
        data = snac[10:]
        tlvs = parse_tlv(data)
        return {
            "family": family,
            "subtype": subtype,
            "flags": flags,
            "request_id": request_id,
            "tlvs": tlvs,
            "payload": data,
        }


class FamilyVersionParser(SnacParserHandler):
    """Parser for SNAC(01,17) - Version request."""

    def visualize(self, snac: bytes) -> str:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])
        lines = [
            colored(
                f"SNAC: Family=0x{family:04x} (GENERIC), Subtype=0x{subtype:04x} (Version Request), "
                f"Flags=0x{flags:04x}, RequestID=0x{request_id:08x}",
                "green",
            )
        ]
        for i in range(0, len(snac[10:]), 4):
            family = snac[10:][i : i + 2]
            version = snac[10:][i + 2 : i + 4]
            lines.append(
                colored(
                    f"├── Family = {SnacService(int.from_bytes(family, 'big')).name}",
                    "cyan",
                )
            )
            if i < len(snac[10:]) - 5:
                lines.append(
                    colored(
                        f"├── Version = {int.from_bytes(version, 'big'):02x}",
                        "cyan",
                    )
                )
            else:
                lines.append(
                    colored(
                        f"└── Version = {int.from_bytes(version, 'big'):02x}",
                        "cyan",
                    )
                )
        return "\n".join(lines)

    def parse(self, snac: bytes) -> Dict[str, Any]:
        if len(snac) < 10:
            return None
        family, subtype, flags, request_id = struct.unpack("!HHHI", snac[:10])
        family_versions: List[Tuple[int, int]] = []
        for i in range(0, len(snac[10:]), 4):
            family_i = snac[10:][i : i + 2]
            version_i = snac[10:][i + 2 : i + 4]
            family_versions.append(
                (int.from_bytes(family_i, "big"), int.from_bytes(version_i, "big"))
            )
        return {
            "family": family,
            "subtype": subtype,
            "flags": flags,
            "request_id": request_id,
            "family_versions": family_versions,
        }


class SnacParser:
    """Dispatches SNACs to parser handlers."""

    def __init__(self):
        self.handlers: Dict[Tuple[int, int], SnacParserHandler] = {}
        self.default_handler = DefaultSnacParser()

    def register_handler(self, family: int, subtype: int, handler: SnacParserHandler):
        self.handlers[(family, subtype)] = handler
        print(
            colored(f"Registered parser for SNAC({family:04x},{subtype:04x})", "green")
        )

    def visualize(self, snac: bytes) -> str:
        key = (int.from_bytes(snac[:2], "big"), int.from_bytes(snac[2:4], "big"))
        handler = self.handlers.get(key, self.default_handler)
        return handler.visualize(snac)

    def parse(self, snac: bytes) -> str:
        key = (int.from_bytes(snac[:2], "big"), int.from_bytes(snac[2:4], "big"))
        handler = self.handlers.get(key, self.default_handler)
        return handler.parse(snac)
