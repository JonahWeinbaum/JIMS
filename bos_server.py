import socket
import threading
from snac_handler import *
from snac_parser import *
from flap import *


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

    def handle_client(client_socket: socket.socket, addr: Tuple[str, int]):
        print(colored(f"[BOS] Client connected: {addr}", "blue"))
        client = ClientContext(client_socket, addr)
        client.screen_name = screen_name
        buffer = bytes()

        # Begin protocol negotiation
        families = (
            SnacService.GENERIC.to_bytes(2, "big")
            + SnacService.LOCATION.to_bytes(2, "big")
            + SnacService.BUDDY.to_bytes(2, "big")
            + SnacService.CHAT.to_bytes(2, "big")
            
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
                            response = dispatcher.dispatch(snac, client)
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
