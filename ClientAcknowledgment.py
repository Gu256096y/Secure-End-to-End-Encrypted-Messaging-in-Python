#Guy Rav On - 315044743
from Protocol import create_message_header
from ClientSecuredOperation import create_tls_connection

#Function for sending the acknowledgment message after receiving a message from another client
def send_acknowledgment(server_address_target, sender_id_target):
    try:
        receiver_id = b"00000"  # Placeholder
        message_id = b"00000"  # Placeholder
        content_hash = b"\x00" * 32  # Placeholder

        header = create_message_header(4, sender_id_target, receiver_id, message_id, content_hash)

        with create_tls_connection(server_address_target) as sock:
            print("Sending acknowledgment...")
            sock.sendall(header)

            sock.recv(1024)

    except Exception as e:
        print(f"Error sending acknowledgment: {e}")
