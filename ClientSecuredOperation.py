#Guy Rav On - 315044743
import socket
import ssl

#communication with secured TLS channel with the server
def create_tls_connection(server_address):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection(server_address)
    tls_sock = context.wrap_socket(sock, server_hostname=server_address[0])
    return tls_sock


