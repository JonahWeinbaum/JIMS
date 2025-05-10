import socket
import pickle
import threading
from queue import Queue
from snac_handler import *
from snac_parser import *
from flap import *

message_socket = None
client = None


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
    print(colored(f"[BOS] Server listening on {address}:{port}", "blue"))

    def connect_to_messages():
        message_address, message_port = MESSAGE_SERVER_ADDRESS.split(":")
        global message_socket
        message_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            message_socket.connect((message_address, int(message_port)))
            print(
                colored(
                    f"[BOS] Connected to message server at {message_address}:{message_port}",
                    "green",
                )
            )
            return message_socket
        except socket.error as e:
            print(colored(f"[BOS] Failed to connect to message server: {e}", "red"))
            return None

    def message_server_handler():
        message_socket = connect_to_messages()
        if not message_socket:
            return

        buffer = bytes()
        try:
            while True:
                try:
                    message_socket.settimeout(1.0)  # Non-blocking receive
                    data = message_socket.recv(1024)
                    if not data:
                        print(colored("[BOS] Message server disconnected", "red"))
                        break
                    if client:
                        snac = pickle.loads(data)
                        print(snac)
                        print(client.screen_name)
                        client.send_snac(
                            snac["family"],
                            snac["subtype"],
                            snac["request_id"],
                            snac.get("payload"),
                        )

                except socket.timeout:
                    continue
                except socket.error as e:
                    print(
                        colored(
                            f"[BOS] Error receiving from message server: {e}", "red"
                        )
                    )
                    break

        except Exception as e:
            print(colored(f"[BOS] Message handler error: {e}", "red"))
        finally:
            message_socket.close()

    # Start message handler in a separate thread
    message_thread = threading.Thread(target=message_server_handler, daemon=True)
    message_thread.start()

    def handle_client(client_socket: socket.socket, addr: Tuple[str, int]):
        print(colored(f"[BOS] Client connected: {addr}", "blue"))
        global client
        client = ClientContext(client_socket, addr)
        client.screen_name = screen_name
        buffer = bytes()

        # Begin protocol negotiation
        families = (
            SnacService.GENERIC.to_bytes(2, "big")
            + SnacService.LOCATION.to_bytes(2, "big")
            + SnacService.BUDDY.to_bytes(2, "big")
            + SnacService.ICBM.to_bytes(2, "big")
            + SnacService.ADS.to_bytes(2, "big")
            + SnacService.INVITES.to_bytes(2, "big")
            + SnacService.ADMIN.to_bytes(2, "big")
            + SnacService.POPUP.to_bytes(2, "big")
            # + SnacService.PRIVACY.to_bytes(2, 'big')
            + SnacService.USER_LOOKUP.to_bytes(2, "big")
            + SnacService.STATS.to_bytes(2, "big")
            + SnacService.TRANSLATION.to_bytes(2, "big")
            # + SnacService.CHAT_NAV.to_bytes(2, "big")
            + SnacService.CHAT.to_bytes(2, "big")
            + SnacService.DIR_SEARCH.to_bytes(2, "big")
            # + SnacService.FEEDBAG.to_bytes(2, "big")
            + SnacService.BART.to_bytes(2, "big")
            + SnacService.ALERT.to_bytes(2, "big")
        )

        client.send_snac(SnacService.GENERIC, 0x0003, 0x0000, families)

        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    print(colored("[BOS] Client disconnected", "red"))
                    break

                buffer += data
                while buffer:
                    flap, buffer = parse_flap(buffer)
                    if flap is None:
                        print(
                            colored(
                                f"[BOS] Partial FLAP received ({len(buffer)} bytes), waiting for more data",
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
                            print("[BOSS] " + parser.visualize(flap["payload"]))
                            snac = parser.parse(flap["payload"])
                            response = dispatcher.dispatch(snac, client, message_socket)
                            if response:
                                client.send_snac(
                                    response["family"],
                                    response["subtype"],
                                    response["request_id"],
                                    response.get("payload"),
                                )
                        else:
                            print(colored("[BOS] Invalid SNAC payload", "red"))

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
