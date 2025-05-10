import os
from typing import Optional, Dict, List, Any, Tuple
from client import ClientContext
from constants import *
from tlv import *


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
            + create_tlv(TlvType.BOS_SERVER, BOS_SERVER_ADDRESS.encode("ascii"))
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
        # Send back identical family versions
        versions = b"".join(
            struct.pack(">HH", a, b) for a, b in snac["family_versions"]
        )
        return {
            "family": SnacService.GENERIC,
            "subtype": 0x0018,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": versions,
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
            "payload": b"\x00\x00",  # No rate limit
        }


class IdleTimeHandler(SnacHandler):
    """Handler for SNAC(01,11) - Set idle time."""

    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        return None


class ClientReadyHandler(SnacHandler):
    """Handler for SNAC(01,02) - Client ready."""

    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        return None


class SetUserInfoHandler(SnacHandler):
    """Handler for SNAC(02,04) - Set user info."""

    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        return None


class OnlineInfoHandler(SnacHandler):
    """Handler for SNAC(01,0e) - Online info request."""

    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        tlvs = (
            create_tlv(TlvType.SCREEN_NAME, UserClass.CLASS_AOL.to_bytes(4, "big"))
            + create_tlv(TlvType.USER_STATUS, b"\x00\x00\x00\x00")
            + create_tlv(TlvType.EXTERNAL_IP, b"\x00\x00\x00\x00")
            + create_tlv(TlvType.MEMBER_SINCE, b"\x00\x00\x00\x00")
            + create_tlv(TlvType.SIGNON_TIME, b"\x00\x00\x00\x00")
            + create_tlv(TlvType.IDLE_TIME, b"\x00\x00\x00\x00")
            + create_tlv(TlvType.UNKNOWN_1E, b"\x00\x00\x00\x00")
        )
        preamble = (
            len(client.screen_name.encode("ascii")).to_bytes(1, "big")
            + client.screen_name.encode("ascii")
            + b"\x00\x00"  # No warning level
            + len(tlvs).to_bytes(2, "big")
        )
        return {
            "family": SnacService.GENERIC,
            "subtype": 0x000F,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": preamble + tlvs,
        }


class LocationRightsHandler(SnacHandler):
    """Handler for SNAC(02,02) - Location rights request."""

    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        tlvs = (
            create_tlv(0x01, int(100).to_bytes(2, "big"))
            + create_tlv(0x02, int(100).to_bytes(2, "big"))
            + create_tlv(0x03, b"\x00\x0a")
            + create_tlv(0x04, b"\x10\x00")
        )

        return {
            "family": SnacService.LOCATION,
            "subtype": 0x0003,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": tlvs,
        }


class DirectoryInfoHandler(SnacHandler):
    """Handler for SNAC(02,09) - Directory info request."""

    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:

        return {
            "family": SnacService.LOCATION,
            "subtype": 0x0003,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": b"\x00\x01",
        }


class BuddyRightsHandler(SnacHandler):
    """Handler for SNAC(03,02) - Buddy rights request."""

    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        tlvs = (
            create_tlv(0x01, int(100).to_bytes(2, "big"))
            + create_tlv(0x02, int(100).to_bytes(2, "big"))
            + create_tlv(0x03, b"\x00\x0a")
        )

        return {
            "family": SnacService.BUDDY,
            "subtype": 0x0003,
            "flags": 0x0003,
            "request_id": snac["request_id"],
            "payload": tlvs,
        }


class QueryScreenNameHandler(SnacHandler):
    """Handler for SNAC(02,0b) - Query screen name request."""

    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        tlvs = (
            create_tlv(0x01, int(100).to_bytes(2, "big"))
            + create_tlv(0x02, int(100).to_bytes(2, "big"))
            + create_tlv(0x03, b"\x00\x0a")
        )

        return {
            "family": SnacService.LOCATION,
            "subtype": 0x000C,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": b"",
        }


class ServiceRequestHandler(SnacHandler):
    """Handler for SNAC(01,04) - service request."""

    def handle(
        self, snac: Dict[str, Any], client: ClientContext
    ) -> Optional[Dict[str, Any]]:
        tlvs = create_tlv(0x0D, SnacService.STATS.to_bytes(2, "big")) + create_tlv(
            0x06, b"cookie"
        )

        if snac["service"] == SnacService.STATS:
            tlvs += create_tlv(0x05, STAT_SERVER_ADDRESS.encode("ascii"))

        if snac["service"] == SnacService.DIR_SEARCH:
            tlvs += create_tlv(0x05, DIR_SERVER_ADDRESS.encode("ascii"))

        if snac["service"] == SnacService.UNKNOWN_18:
            tlvs += create_tlv(0x05, UNK_SERVER_ADDRESS.encode("ascii"))

        return {
            "family": SnacService.GENERIC,
            "subtype": 0x0005,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": tlvs,
        }


class SnacDispatcher:
    """Dispatches SNACs to registered handlers."""

    def __init__(self):
        self.handlers: Dict[Tuple[int, int], SnacHandler] = {}

    def register_handler(self, family: int, subtype: int, handler: SnacHandler):
        self.handlers[(family, subtype)] = handler
        print(
            colored(f"Registered handler for SNAC({family:04x},{subtype:04x})", "green")
        )

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
            print(
                colored(
                    f"No request handler for SNAC({key[0]:04x},{key[1]:04x})", "red"
                )
            )
            return None
