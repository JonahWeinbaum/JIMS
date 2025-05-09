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
from snac_parser import *
from utils import format_hex_ascii

try:
    from termcolor import colored
except ImportError:

    def colored(text, *args, **kwargs):
        return text


# Globals
SCREEN_NAME = ""


def auth_server(
    address: str, port: int, dispatcher: SnacDispatcher, parser: SnacParser
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
                        if flap.get("payload"):
                            # Visualize SNAC
                            print(parser.visualize(flap["payload"]))
                            snac = parser.parse(flap["payload"])
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
    parser: SnacParser,
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
                        if flap.get("payload"):
                            # Visualize SNAC
                            print(parser.visualize(flap["payload"]))
                            snac = parser.parse(flap["payload"])
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
    parser = SnacParser()

    # Register handlers
    dispatcher.register_handler(SnacService.AUTH, 0x0006, AuthKeyRequestHandler())
    dispatcher.register_handler(SnacService.AUTH, 0x0002, LoginRequestHandler())
    dispatcher.register_handler(SnacService.GENERIC, 0x0017, FamilyVersionHandler())
    dispatcher.register_handler(SnacService.GENERIC, 0x0006, RateRequestHandler())
    dispatcher.register_handler(SnacService.GENERIC, 0x000E, OnlineInfoHandler())
    dispatcher.register_handler(SnacService.GENERIC, 0x0011, IdleTimeHandler())

    parser.register_handler(SnacService.AUTH, 0x0006, AuthKeyRequestParser())
    parser.register_handler(SnacService.AUTH, 0x0002, LoginRequestParser())
    parser.register_handler(SnacService.GENERIC, 0x0017, FamilyVersionParser())
    parser.register_handler(SnacService.GENERIC, 0x0004, ServiceRequestParser())
    parser.register_handler(SnacService.GENERIC, 0x0011, IdleTimeParser())

    # Start auth server
    auth_address, auth_port = AUTH_SERVER_ADDRESS.split(":")
    auth_thread = threading.Thread(
        target=auth_server,
        args=(auth_address, int(auth_port), dispatcher, parser),
    )
    auth_thread.daemon = True
    auth_thread.start()

    # Start BOS server
    bos_address, bos_port = BOS_SERVER_ADDRESS.split(":")
    bos_thread = threading.Thread(
        target=bos_server,
        args=(bos_address, int(bos_port), dispatcher, parser, SCREEN_NAME),
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
