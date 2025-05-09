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
            "payload": snac["raw_data"],
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


class NewServiceHandler(SnacHandler):
    """Handler for SNAC(01,04) - Service request."""

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
            "subtype": 0x0005,
            "flags": 0x0000,
            "request_id": snac["request_id"],
            "payload": preamble + tlvs,
        }


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
