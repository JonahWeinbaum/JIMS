import socket
import threading
from snac_handler import *
from snac_parser import *
from flap import *


def auth_server(
    address: str, port: int, dispatcher: SnacDispatcher, parser: SnacParser
):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((address, port))
    server.listen(5)
    print(colored(f"[AUTH] Server listening on {address}:{port}", "blue"))

    def handle_client(client_socket: socket.socket, addr: Tuple[str, int]):
        print(colored(f"[AUTH] Client connected: {addr}", "blue"))
        client = ClientContext(client_socket, addr)
        buffer = bytes()

        # Send initial FLAP
        client.send_flap(FlapChannel.CONN_NEW)

        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    print(colored("[AUTH] Client disconnected", "red"))
                    break

                buffer += data
                while buffer:
                    flap, buffer = parse_flap(buffer)
                    if flap is None:
                        print(
                            colored(
                                f"[AUTH] Partial FLAP received ({len(buffer)} bytes), waiting for more data",
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
                            print("[AUTH] "+parser.visualize(flap["payload"]))
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
                            print(colored("[AUTH] Invalid SNAC payload", "red"))

                    else:
                        print(
                            colored(
                                f"[AUTH] Unhandled FLAP channel: {flap['channel']:02x}", "red"
                            )
                        )

        except (socket.error, BrokenPipeError) as e:
            print(colored(f"[AUTH] Client disconnected with error: {e}", "red"))
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
