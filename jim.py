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
from snac_visualizer import *
from utils import format_hex_ascii

try:
    from termcolor import colored
except ImportError:

    def colored(text, *args, **kwargs):
        return text


# Globals
SCREEN_NAME = ""


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
    address: str,
    port: int,
    dispatcher: SnacDispatcher,
    visualizer: SnacVisualizer,
    screen_name: str,
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
        families = SnacService.GENERIC.to_bytes(2, "big") + SnacService.CHAT.to_bytes(
            2, "big"
        )

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
    dispatcher.register_handler(SnacService.GENERIC, 0x00E, OnlineInfoHandler())

    visualizer.register_handler(SnacService.AUTH, 0x0006, AuthKeyRequestVisualizer())
    visualizer.register_handler(SnacService.AUTH, 0x0002, LoginRequestVisualizer())
    visualizer.register_handler(SnacService.GENERIC, 0x0017, FamilyVersionVisualizer())
    visualizer.register_handler(SnacService.GENERIC, 0x0004, ServiceRequestVisualizer())

    # Start auth server
    auth_address, auth_port = AUTH_SERVER_ADDRESS.split(":")
    auth_thread = threading.Thread(
        target=auth_server,
        args=(auth_address, int(auth_port), dispatcher, visualizer),
    )
    auth_thread.daemon = True
    auth_thread.start()

    # Start BOS server
    bos_address, bos_port = BOS_SERVER_ADDRESS.split(":")
    bos_thread = threading.Thread(
        target=bos_server,
        args=(bos_address, int(bos_port), dispatcher, visualizer, SCREEN_NAME),
    )
    bos_thread.daemon = True
    bos_thread.start()

    # Wait on all threads completion
    try:
        auth_thread.join()
        bos_thread.join()
    except KeyboardInterrupt:
        print(colored("Shutting down all servers", "blue"))


if __name__ == "__main__":
    main()
