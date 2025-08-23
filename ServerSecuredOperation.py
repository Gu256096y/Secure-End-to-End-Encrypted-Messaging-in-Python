#Guy Rav On - 315044743
#server secured operations

import socket
import ssl
import threading
from ServerRequestHandler import *

ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")

def handle_client_connection(client_socket):
    try:
        handle_client_request(client_socket)
    except Exception as e:
        print(f"Error handling client connection: {e}")
    finally:
        client_socket.close()

def start_tls_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 4343))
    server_socket.listen(5)

    print("TLS server listening on port 4343...")

    while True:
        try:
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")

            secure_socket = ssl_context.wrap_socket(client_socket, server_side=True)

            client_thread = threading.Thread(target=handle_client_connection, args=(secure_socket,))
            client_thread.start()

        except Exception as e:
            print(f"Error accepting connection: {e}")
