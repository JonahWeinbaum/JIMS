import struct
from enum import IntEnum
import socket
import threading
import time
import os
from typing import Optional, Dict, List, Any, Tuple

# Try to import termcolor, fall back to plain text if unavailable
try:
    from termcolor import colored
except ImportError:

    def colored(text, *args, **kwargs):
        return text

# Globals
SCREEN_NAME = ""
    
# Constants
AUTH_SERVER_ADDRESS = "127.0.0.1:5190"
BOS_SERVER_ADDRESS = "127.0.0.1:4040"

class FlapChannel(IntEnum):
    CONN_NEW = 0x01
    SNAC = 0x02
    ERROR = 0x03
    CONN_CLOSE = 0x04
    KEEPALIVE = 0x05


class TlvType(IntEnum):
    SCREEN_NAME = 0x01
    SIGNON_TIME = 0x03
    ERROR_URL = 0x04
    BOS_SERVER = 0x05
    MEMBER_SINCE = 0x05
    USER_STATUS = 0x06
    AUTH_COOKIE = 0x06
    ERROR_CODE = 0x08
    EXTERNAL_IP = 0x0a
    IDLE_TIME = 0x0f
    EMAIL_ADDR = 0x11
    UNKNOWN_1E = 0x1e
    AUTH_KEY = 0x25
    BETA_BUILD = 0x40
    BETA_URL = 0x41
    BETA_INFO = 0x42
    BETA_NAME = 0x43
    RELEASE_BUILD = 0x44
    RELEASE_URL = 0x45
    RELEASE_NAME = 0x46
    BETA_MD5 = 0x48
    RELEASE_MD5 = 0x49
    UNKNOWN_4B = 0x4B
    PASS_CHANGE_URL = 0x54
    UNKNOWN_5A = 0x5A


class SnacService(IntEnum):
    GENERIC = 0x0001
    LOCATION = 0x0002
    BUDDY = 0x0003
    ICBM = 0x0004
    ADS = 0x005
    INVITES = 0x0006
    ADMIN = 0x0007
    POPUP = 0x0008
    PRIVACY = 0x0009
    USER_LOOKUP = 0x000a
    STATS = 0x000b
    TRANSLATION = 0x000c
    CHAT_NAV = 0x000d
    CHAT = 0x000e
    DIR_SEARCH = 0x000f
    SSBI = 0x0010
    SSI = 0x0013
    ICQ = 0x0015
    AUTH = 0x0017
    UNKNOWN_18 = 0x0018
    BROADCAST = 0x0085
    
class UserClass(IntEnum):    	
    CLASS_UNCONFIRMED   = 0x0001
    CLASS_ADMINISTRATOR = 0x0002
    CLASS_AOL  	        = 0x0004
    CLASS_COMMERCIAL  	= 0x0008
    CLASS_FREE  	= 0x0010
    CLASS_AWAY  	= 0x0020
    CLASS_ICQ  	        = 0x0040
    CLASS_WIRELESS  	= 0x0080
    CLASS_UNKNOWN100  	= 0x0100
    CLASS_UNKNOWN200  	= 0x0200
    CLASS_UNKNOWN400  	= 0x0400
    CLASS_UNKNOWN800  	= 0x0800

class UserStatus(IntEnum):
    TODO = 0x01

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


def parse_snac(payload: bytes) -> Optional[Dict[str, Any]]:
    if len(payload) < 10:
        return None
    family, subtype, flags, request_id = struct.unpack("!HHHI", payload[:10])
    data = payload[10:]
    tlvs = parse_tlv(data)
    return {
        "family": family,
        "subtype": subtype,
        "flags": flags,
        "request_id": request_id,
        "tlvs": tlvs,
        "raw_data": data,
    }


def format_hex_ascii(data: bytes) -> str:
    """Format bytes as hex and printable ASCII."""
    hex_str = data.hex()
    ascii_str = "".join(
        c if 32 <= ord(c) <= 126 else "." for c in data.decode("ascii", errors="ignore")
    )
    return f"{hex_str} ({ascii_str})"


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
        for i in range(0, len(snac['raw_data']), 4):
            family = snac['raw_data'][i:i+2]
            version = snac['raw_data'][i+2:i+4]
            lines.append(
                    colored(
                        f"├── Family = {SnacService(int.from_bytes(family, 'big')).name}",
                        "cyan",
                    )
                )
            if i < len(snac['raw_data']) - 5:
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


class SnacHandler:
    """Base class for SNAC handlers."""

    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        raise NotImplementedError("Subclasses must implement handle()")


class AuthKeyRequestHandler(SnacHandler):
    """Handler for SNAC(17,06) - MD5 key request."""

    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        screen_name = None
        for tlv in snac["tlvs"]:
            if tlv["type"] == TlvType.SCREEN_NAME:
                screen_name = tlv["value"].decode("ascii")
        client.screen_name = screen_name
        global SCREEN_NAME
        SCREEEN_NAME = screen_name
        auth_key = b"fake_auth"
        return {
            "family": SnacService.AUTH,
            "subtype": 0x0007,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": len(auth_key).to_bytes(4, "big") + auth_key,
        }


class LoginRequestHandler(SnacHandler):
    """Handler for SNAC(17,02) - Login request."""

    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        auth_cookie = os.urandom(16)
        tlvs = (
            create_tlv(TlvType.SCREEN_NAME, client.screen_name.encode("ascii"))
            + create_tlv(TlvType.BOS_SERVER, b"127.0.0.1:4040")
            + create_tlv(TlvType.AUTH_COOKIE, auth_cookie)
            + create_tlv(TlvType.EMAIL_ADDR, b"Jonah.Weinbaum@gmail.com")
            + create_tlv(TlvType.PASS_CHANGE_URL, b"www.youtube.com")
        )
        return {
            "family": SnacService.AUTH,
            "subtype": 0x0003,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": tlvs,
        }

class FamilyVersionHandler(SnacHandler):
    """Handler for SNAC(1,17) - Version request."""
    
    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        return {
            "family": SnacService.GENERIC,
            "subtype": 0x0018,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": snac['raw_data'],
        }

class RateRequestHandler(SnacHandler):
    """Handler for SNAC(01,06) - Rate limit request."""
    
    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        return {
            "family": SnacService.GENERIC,
            "subtype": 0x0007,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": b'\x00\x00', #No rate limit
        }
    
class OnlineInfoHandler(SnacHandler):
    """Handler for SNAC(01,0e) - Online info request."""
    
    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        tlvs = (
            create_tlv(TlvType.SCREEN_NAME, UserClass.CLASS_AOL.to_bytes(4, 'big'))
            + create_tlv(TlvType.USER_STATUS, b'\x00\x00\x00\x00')
            + create_tlv(TlvType.EXTERNAL_IP, b'\x00\x00\x00\x00')
            + create_tlv(TlvType.MEMBER_SINCE, b'\x00\x00\x00\x00')
            + create_tlv(TlvType.SIGNON_TIME, b'\x00\x00\x00\x00')
            + create_tlv(TlvType.IDLE_TIME, b'\x00\x00\x00\x00')
            + create_tlv(TlvType.UNKNOWN_1E, b'\x00\x00\x00\x00')
        )
        preamble = (
            len(client.screen_name.encode('ascii')).to_bytes(1, 'big')
            + client.screen_name.encode('ascii')
            + b'\x00\x00' #No warning level
            + len(tlvs).to_bytes(2, 'big')
        )
        return {
            "family": SnacService.GENERIC,
            "subtype": 0x000f,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": preamble + tlvs
        }

class NewServiceHandler(SnacHandler):
    """Handler for SNAC(01,04) - Service request."""
    
    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        tlvs = (
            create_tlv(TlvType.SCREEN_NAME, UserClass.CLASS_AOL.to_bytes(4, 'big'))
            + create_tlv(TlvType.USER_STATUS, b'\x00\x00\x00\x00')
            + create_tlv(TlvType.EXTERNAL_IP, b'\x00\x00\x00\x00')
            + create_tlv(TlvType.MEMBER_SINCE, b'\x00\x00\x00\x00')
            + create_tlv(TlvType.SIGNON_TIME, b'\x00\x00\x00\x00')
            + create_tlv(TlvType.IDLE_TIME, b'\x00\x00\x00\x00')
            + create_tlv(TlvType.UNKNOWN_1E, b'\x00\x00\x00\x00')
        )
        preamble = (
            len(client.screen_name.encode('ascii')).to_bytes(1, 'big')
            + client.screen_name.encode('ascii')
            + b'\x00\x00' #No warning level
            + len(tlvs).to_bytes(2, 'big')
        )
        return {
            "family": SnacService.GENERIC,
            "subtype": 0x0005,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": preamble + tlvs
        }

    
class SnacDispatcher:
    """Dispatches SNACs to registered handlers."""

    def __init__(self):
        self.handlers: Dict[Tuple[int, int], SnacHandler] = {}

    def register_handler(self, family: int, subtype: int, handler: SnacHandler):
        self.handlers[(family, subtype)] = handler
        print(f"Registered handler for SNAC({family:04x},{subtype:04x})")

    def dispatch(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        key = (snac["family"], snac["subtype"])
        handler = self.handlers.get(key)
        if handler:
            try:
                return handler.handle(snac, client)
            except Exception as e:
                print(
                    colored(
                        f"Error handling SNAC({key[0]:04x},{key[1]:04x}): {e}", "red"
                    )
                )
                return None
        else:
            print(colored(f"No handler for SNAC({key[0]:04x},{key[1]:04x})", "red"))
            return None


def auth_server(
    address: str, port: int, dispatcher: SnacDispatcher, visualizer: SnacVisualizer
):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port))
    server.listen(5)
    print(colored(f"AUTH server listening on {address}:{port}", "blue"))

    def handle_client(client_socket: socket.socket, addr: Tuple[str, int]):
        print(colored(f"Client connected: {addr}", "blue"))
        client = ClientContext(client_socket, addr)
        buffer = bytes()

        # Send initial FLAP
        client.send_flap(FlapChannel.CONN_NEW)

        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    print(colored("Client disconnected", "red"))
                    break

                buffer += data
                while buffer:
                    flap, buffer = parse_flap(buffer)
                    if flap is None:
                        print(
                            colored(
                                f"Partial FLAP received ({len(buffer)} bytes), waiting for more data",
                                "yellow",
                            )
                        )
                        break

                    # Visualize FLAP
                    print(visualize_flap(flap))

                    if (
                        flap["channel"] == FlapChannel.CONN_NEW
                        and len(flap["payload"]) == 4
                    ):
                        continue
                    elif flap["channel"] == FlapChannel.KEEPALIVE:
                        continue
                    elif flap["channel"] == FlapChannel.SNAC:
                        snac = parse_snac(flap["payload"])
                        if snac:
                            # Visualize SNAC
                            print(visualizer.visualize(snac))
                            response = dispatcher.dispatch(snac, client)
                            if response:
                                client.send_snac(
                                    response["family"],
                                    response["subtype"],
                                    response["request_id"],
                                    response.get("payload"),
                                )
                        else:
                            print(colored("Invalid SNAC payload", "red"))

                    else:
                        print(
                            colored(
                                f"Unhandled FLAP channel: {flap['channel']:02x}", "red"
                            )
                        )

        except (socket.error, BrokenPipeError) as e:
            print(colored(f"Client disconnected with error: {e}", "red"))
        finally:
            client_socket.close()

    try:
        while True:
            client_socket, addr = server.accept()
            client_thread = threading.Thread(
                target=handle_client, args=(client_socket, addr)
            )
            client_thread.start()
    except KeyboardInterrupt:
        print(colored("Server shutting down", "blue"))
        server.close()

def bos_server(
        address: str, port: int, dispatcher: SnacDispatcher, visualizer: SnacVisualizer, screen_name: str
):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port))
    server.listen(5)
    print(colored(f"BOS server listening on {address}:{port}", "blue"))

    def handle_client(client_socket: socket.socket, addr: Tuple[str, int]):
        print(colored(f"Client connected: {addr}", "blue"))
        client = ClientContext(client_socket, addr)
        client.screen_name = screen_name
        buffer = bytes()

        # Begin protocol negotiation
        families = (
            SnacService.GENERIC.to_bytes(2, 'big')
            + SnacService.CHAT.to_bytes(2, 'big')
        )
        print(families)

        client.send_snac(SnacService.GENERIC, 0x0003, 0x0000, families)

        
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    print(colored("Client disconnected", "red"))
                    break

                buffer += data
                while buffer:
                    flap, buffer = parse_flap(buffer)
                    if flap is None:
                        print(
                            colored(
                                f"Partial FLAP received ({len(buffer)} bytes), waiting for more data",
                                "yellow",
                            )
                        )
                        break

                    # Visualize FLAP
                    print(visualize_flap(flap))

                    if (
                        flap["channel"] == FlapChannel.CONN_NEW
                        and len(flap["payload"]) == 4
                    ):
                        continue
                    elif flap["channel"] == FlapChannel.KEEPALIVE:
                        continue
                    elif flap["channel"] == FlapChannel.SNAC:
                        snac = parse_snac(flap["payload"])
                        if snac:
                            # Visualize SNAC
                            print(visualizer.visualize(snac))
                            response = dispatcher.dispatch(snac, client)
                            if response:
                                client.send_snac(
                                    response["family"],
                                    response["subtype"],
                                    response["request_id"],
                                    response.get("payload"),
                                )
                        else:
                            print(colored("Invalid SNAC payload", "red"))

                    else:
                        print(
                            colored(
                                f"Unhandled FLAP channel: {flap['channel']:02x}", "red"
                            )
                        )

        except (socket.error, BrokenPipeError) as e:
            print(colored(f"Client disconnected with error: {e}", "red"))
        finally:
            client_socket.close()

    try:
        while True:
            client_socket, addr = server.accept()
            client_thread = threading.Thread(
                target=handle_client, args=(client_socket, addr)
            )
            client_thread.start()
    except KeyboardInterrupt:
        print(colored("Server shutting down", "blue"))
        server.close()

def main():
    """Run auth and BOS servers in separate threads."""
    # Initialize shared dispatcher and visualizer
    dispatcher = SnacDispatcher()
    visualizer = SnacVisualizer()

    # Register handlers
    dispatcher.register_handler(SnacService.AUTH, 0x0006, AuthKeyRequestHandler())
    dispatcher.register_handler(SnacService.AUTH, 0x0002, LoginRequestHandler())
    dispatcher.register_handler(SnacService.GENERIC, 0x0017, FamilyVersionHandler())
    dispatcher.register_handler(SnacService.GENERIC, 0x006, RateRequestHandler())
    dispatcher.register_handler(SnacService.GENERIC, 0x00e, OnlineInfoHandler())

    visualizer.register_handler(SnacService.AUTH, 0x0006, AuthKeyRequestVisualizer())
    visualizer.register_handler(SnacService.AUTH, 0x0002, LoginRequestVisualizer())
    visualizer.register_handler(SnacService.GENERIC, 0x0017, FamilyVersionVisualizer())
    visualizer.register_handler(SnacService.GENERIC, 0x0004, ServiceRequestVisualizer())

    # Start auth server
    auth_address, auth_port = AUTH_SERVER_ADDRESS.split(':')
    auth_thread = threading.Thread(
        target=auth_server,
        args=(auth_address, int(auth_port), dispatcher, visualizer),
    )
    auth_thread.daemon = True
    auth_thread.start()

    # Start BOS server
    bos_address, bos_port = BOS_SERVER_ADDRESS.split(':')
    bos_thread = threading.Thread(
        target=bos_server,
        args=(bos_address, int(bos_port), dispatcher, visualizer, SCREEN_NAME)
    )
    bos_thread.daemon = True
    bos_thread.start()

    try:
        auth_thread.join()
    # bos_thread.join()
    except KeyboardInterrupt:
        print(colored("Shutting down all servers", "blue"))


if __name__ == "__main__":
    main()
