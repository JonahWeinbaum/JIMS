from typing import Optional, Dict, List, Any, Tuple
from constants import *

try:
    from termcolor import colored
except ImportError:

    def colored(text, *args, **kwargs):
        return text


class SnacVisualizerHandler:
    """Base class for SNAC visualization handlers."""

    def visualize(self, snac: Dict[str, Any]) -> str:
        raise NotImplementedError("Subclasses must implement visualize()")


class DefaultSnacVisualizer(SnacVisualizerHandler):
    """Default visualizer for unregistered SNACs."""

    def visualize(self, snac: Dict[str, Any]) -> str:
        family = snac["family"]
        subtype = snac["subtype"]
        lines = [
            colored(
                f"SNAC: Family=0x{family:04x}, Subtype=0x{subtype:04x}, "
                f"Flags=0x{snac['flags']:04x}, RequestID=0x{snac['request_id']:08x}",
                "green",
            )
        ]
        for i, tlv in enumerate(snac["tlvs"]):
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
            if i < len(snac["tlvs"]) - 1:
                lines.append(
                    colored(
                        f"├── TLV: Type={type_name}, Length={len(tlv['value'])}, Value={value_str}",
                        "yellow",
                    )
                )
            else:
                lines.append(
                    colored(
                        f"└── TLV: Type={type_name}, Length={len(tlv['value'])}, Value={value_str}",
                        "yellow",
                    )
                )
        return "\n".join(lines)


class AuthKeyRequestVisualizer(SnacVisualizerHandler):
    """Visualizer for SNAC(17,06) - MD5 key request."""

    def visualize(self, snac: Dict[str, Any]) -> str:
        lines = [
            colored(
                f"SNAC: Family=0x0017 (AUTH), Subtype=0x0006 (MD5 Key Request), "
                f"Flags=0x{snac['flags']:04x}, RequestID=0x{snac['request_id']:08x}",
                "green",
            )
        ]
        for i, tlv in enumerate(snac["tlvs"]):
            type_name = (
                TlvType(tlv["type"]).name
                if tlv["type"] in TlvType
                else f"0x{tlv['type']:04x}"
            )
            if tlv["type"] == TlvType.SCREEN_NAME:
                value_str = tlv["value"].decode("ascii")
                color = "magenta"
            else:
                value_str = tlv["value"].hex() or "empty"
                color = "yellow"
            if i < len(snac["tlvs"]) - 1:
                lines.append(
                    colored(
                        f"├── TLV: Type={type_name}, Length={len(tlv['value'])}, Value={value_str}",
                        color,
                    )
                )
            else:
                lines.append(
                    colored(
                        f"└── TLV: Type={type_name}, Length={len(tlv['value'])}, Value={value_str}",
                        color,
                    )
                )
        return "\n".join(lines)


class LoginRequestVisualizer(SnacVisualizerHandler):
    """Visualizer for SNAC(17,02) - Login request."""

    def visualize(self, snac: Dict[str, Any]) -> str:
        lines = [
            colored(
                f"SNAC: Family=0x0017 (AUTH), Subtype=0x0002 (Login Request), "
                f"Flags=0x{snac['flags']:04x}, RequestID=0x{snac['request_id']:08x}",
                "green",
            )
        ]
        for i, tlv in enumerate(snac["tlvs"]):
            type_name = (
                TlvType(tlv["type"]).name
                if tlv["type"] in TlvType
                else f"0x{tlv['type']:04x}"
            )
            if tlv["type"] == TlvType.SCREEN_NAME:
                value_str = tlv["value"].decode("ascii")
                color = "magenta"
            elif tlv["type"] == TlvType.AUTH_KEY:
                value_str = tlv["value"].hex()
                color = "cyan"
            else:
                value_str = (
                    tlv["value"].decode("ascii", errors="ignore")
                    if tlv["value"]
                    else "empty"
                )
                color = "yellow"
            if i < len(snac["tlvs"]) - 1:
                lines.append(
                    colored(
                        f"├── TLV: Type={type_name}, Length={len(tlv['value'])}, Value={value_str}",
                        color,
                    )
                )
            else:
                lines.append(
                    colored(
                        f"└── TLV: Type={type_name}, Length={len(tlv['value'])}, Value={value_str}",
                        color,
                    )
                )
        return "\n".join(lines)


class ServiceRequestVisualizer(SnacVisualizerHandler):
    """Visualizer for SNAC(01,04) - Service request."""

    def visualize(self, snac: Dict[str, Any]) -> str:
        lines = [
            colored(
                f"SNAC: Family=0x0001 (GENERIC), Subtype=0x0004 (Service Request), "
                f"Flags=0x{snac['flags']:04x}, RequestID=0x{snac['request_id']:08x}",
                "green",
            )
        ]
        lines.append(
            colored(
                f"└── Family = {SnacService(int.from_bytes(snac['raw_data'][:2], 'big')).name}",
                "cyan",
            )
        )
        return "\n".join(lines)


class FamilyVersionVisualizer(SnacVisualizerHandler):
    """Visualizer for SNAC(1,17) - Version request."""

    def visualize(self, snac: Dict[str, Any]) -> str:
        lines = [
            colored(
                f"SNAC: Family=0x0001 (GENERIC), Subtype=0x0017 (Version Request), "
                f"Flags=0x{snac['flags']:04x}, RequestID=0x{snac['request_id']:08x}",
                "green",
            )
        ]
        for i in range(0, len(snac["raw_data"]), 4):
            family = snac["raw_data"][i : i + 2]
            version = snac["raw_data"][i + 2 : i + 4]
            lines.append(
                colored(
                    f"├── Family = {SnacService(int.from_bytes(family, 'big')).name}",
                    "cyan",
                )
            )
            if i < len(snac["raw_data"]) - 5:
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


class SnacVisualizer:
    """Dispatches SNACs to visualization handlers."""

    def __init__(self):
        self.handlers: Dict[Tuple[int, int], SnacVisualizerHandler] = {}
        self.default_handler = DefaultSnacVisualizer()

    def register_handler(
        self, family: int, subtype: int, handler: SnacVisualizerHandler
    ):
        self.handlers[(family, subtype)] = handler
        print(f"Registered visualizer for SNAC({family:04x},{subtype:04x})")

    def visualize(self, snac: Dict[str, Any]) -> str:
        key = (snac["family"], snac["subtype"])
        handler = self.handlers.get(key, self.default_handler)
        return handler.visualize(snac)
