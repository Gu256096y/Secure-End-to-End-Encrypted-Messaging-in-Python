#Guy Rav On 
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad
from ClientSecuredOperation import *
from ClientResponseHandler import *
from ClientDataHandler import *
from Protocol import create_message_header

#sending the register message while sending the public RSA key via a TLS safe channel and 6 digits authentication
#reciving the encrypted AES key and saving it to the client data file for future encrypt
def send_registration_message(server_address_target, sender_id_target, receiver_id_target, public_key_to_send, private_key_to_use):
    try:
        message_id_generated = b"00000"
        header = create_message_header(1, sender_id_target, receiver_id_target, message_id_generated, public_key_to_send)

        with create_tls_connection(server_address_target) as sock:
            print("Sending registration message...")
            sock.sendall(header + public_key_to_send)
            random_code = sock.recv(1024).decode('utf-8')
            print(f"Received Code from Server: {random_code}")
            sock.sendall(random_code.encode('utf-8'))
            response = sock.recv(2048)
            if response:
                response_data = json.loads(response.decode('utf-8'))

                if response_data.get("status") == "success":
                    encrypted_aes_key = bytes.fromhex(response_data["encrypted_aes_key"])
                    rsa_key = RSA.import_key(private_key_to_use)
                    cipher_rsa = PKCS1_OAEP.new(rsa_key)
                    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
                    save_client_data(sender_id_target, private_key_to_use, aes_key)
                    print("Registration completed successfully.")
                else:
                    print(f"Registration failed: {response_data.get('message')}")
            else:
                print("No response received from server.")
    except Exception as e:
        print(f"Error during registration: {e}")

#send message to another client, while the message and its hash are encrypted by the AES key
def send_message(server_address_target, sender_id_target, receiver_id_target, aes_key, plaintext_content):
    try:
        message_id_generated = f"{int.from_bytes(os.urandom(3), 'big') % 100000:05}".encode('utf-8')

        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=b'\x00' * 16)
        encrypted_content = cipher_aes.encrypt(pad(plaintext_content, AES.block_size))

        header = create_message_header(2, sender_id_target, receiver_id_target, message_id_generated, encrypted_content)

        with create_tls_connection(server_address_target) as sock:
            print("Sending message (AES encrypted)...")
            sock.sendall(header + encrypted_content)

            response = sock.recv(2048)
            if response:
                print(f"Server Response: {response.decode('utf-8')}")
            else:
                print("No response received from server for message.")

    except Exception as e:
        print(f"Error sending message: {e}")

#asking the server for messages
def send_receive_message_request(server_address_target, sender_id_target):
    try:
        aes_key = load_client_data(sender_id_target)
        if not aes_key:
            print("Error: AES key not found. Ensure the client is registered and the key is saved.")
            return

        receiver_id = b"00000"
        message_id = b"00000"
        content_hash = b"\x00" * 32
        header = create_message_header(3, sender_id_target, receiver_id, message_id, content_hash)

        with create_tls_connection(server_address_target) as sock:
            print("Sending receive message request...")
            sock.sendall(header)

            response = sock.recv(2048)
            if response:
                handle_received_message(response, aes_key)
            else:
                print("No response received from server for op_code 3.")
    except Exception as e:
        print(f"Error sending receive message: {e}")



