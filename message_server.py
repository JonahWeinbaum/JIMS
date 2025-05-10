import socket
import threading
from snac_handler import *
from snac_parser import *
from flap import *
from message import parse_message, visualize_message, construct_message

bos_socket = None


def message_server(
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
    print(colored(f"[MESSAGE] Server listening on {address}:{port}", "blue"))

    def input_loop():
        global bos_socket
        while True:
            command = input()  # Wait for user to type something
            if bos_socket:
                try:
                    msg = construct_message(command)
                    bos_socket.sendall(msg)
                except Exception as e:
                    print(colored(f"[MESSAGE] Failed to send: {e}", "red"))
            else:
                print(colored("[MESSAGE] No BOS socket connected", "yellow"))

    def handle_bos(bos_socket: socket.socket, addr: Tuple[str, int]):
        print(colored(f"[MESSAGE] BOS server connected: {addr}", "blue"))
        buffer = bytes()

        try:
            while True:
                data = bos_socket.recv(1024)
                if not data:
                    print(colored("[MESSAGE] BOS server disconnected", "red"))
                    break

                buffer += data
                if len(data) > 0:
                    parsed_msg = parse_message(data)
                    print("PARSING MESSAGE")
                    print(parsed_msg)
                    print(visualize_message(parsed_msg))

        except (socket.error, BrokenPipeError) as e:
            print(colored(f"BOS server disconnected with error: {e}", "red"))
        finally:
            bos_socket.close()

    try:
        threading.Thread(target=input_loop, daemon=True).start()
        while True:
            global bos_socket
            bos_socket, addr = server.accept()
            bos_thread = threading.Thread(target=handle_bos, args=(bos_socket, addr))
            bos_thread.start()
    except KeyboardInterrupt:
        print(colored("Server shutting down", "blue"))
        server.close()
