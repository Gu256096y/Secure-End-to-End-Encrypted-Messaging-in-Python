#Guy Rav On
import json
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Protocol import *
from ServerDB import *
import random
from threading import Lock

#Locks for shared resources
clients_db_lock = Lock()
messages_db_lock = Lock()

#requests control
def handle_client_request(client_socket):
    try:
        header_size = struct.calcsize(
            f"<B{MESSAGE_STRUCTURE['sender_id']}s{MESSAGE_STRUCTURE['receiver_id']}s{MESSAGE_STRUCTURE['message_id']}s{MESSAGE_STRUCTURE['hash']}s"
        )
        header = client_socket.recv(header_size)
        if not header or len(header) < header_size:
            raise ValueError("Invalid header received.")

        op_code = struct.unpack("<B", header[:1])[0]

        if op_code == 1:
            handle_registration(client_socket, header)
        elif op_code == 2:
            content = client_socket.recv(2048)
            handle_message(client_socket, header, content)
        elif op_code == 3:
            handle_receive_message_request(client_socket, header)
        elif op_code == 4:
            handle_acknowledgment(header)
        else:
            print(f"Unknown op_code {op_code}. Ignoring.")
    except ConnectionAbortedError:
        print("Client connection was aborted.")
    except Exception as e:
        print(f"Error handling client request: {e}")
    finally:
        client_socket.close()

#parse register request
def handle_registration(client_socket, header):
    try:
        print("Receiving registration message...")
        op_code, sender_id, receiver_id, message_id, content_hash = parse_header(header)
        body = client_socket.recv(2048 - len(header))
        calculated_hash = calculate_hash(body)
        if calculated_hash != content_hash:
            raise ValueError("Hash mismatch.")

        rsa_key = RSA.import_key(body)
        aes_key = get_random_bytes(32)
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        with clients_db_lock:
            clients_db[sender_id] = {
                "public_key": body,
                "aes_key": aes_key
            }

        response = json.dumps({
            "status": "success",
            "encrypted_aes_key": encrypted_aes_key.hex()
        })

        if not send_by_secure_channel(client_socket):
            print(f"Secure channel authentication failed for client {sender_id}.")
            return  # Exit if authentication fails
        client_socket.sendall(response.encode('utf-8'))
        print(f"Client {sender_id} registered successfully. Public Key and AES Key saved.")
    except Exception as e:
        print(f"Error handling registration: {e}")

#parse send message request
def handle_message(client_socket, header, content):
    try:
        op_code, sender_id, receiver_id, message_id, received_hash = parse_header(header)

        with clients_db_lock:
            if sender_id not in clients_db:
                response = json.dumps({
                    "status": "error",
                    "message": f"Client {sender_id} not registered."
                })
                client_socket.sendall(response.encode('utf-8'))
                return

        aes_key = clients_db[sender_id]["aes_key"]
        calculated_hash = calculate_hash(content)
        if calculated_hash != received_hash:
            raise ValueError("Hash mismatch.")

        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=b'\x00' * 16)
        decrypted_content = unpad(cipher_aes.decrypt(content), AES.block_size)

        with messages_db_lock:
            messages_db[message_id] = {
                "sender_id": sender_id,
                "receiver_id": receiver_id,
                "content": decrypted_content.decode('utf-8')
            }

        response = json.dumps({
            "status": "success",
            "message": "Message received and saved."
        })
        client_socket.sendall(response.encode('utf-8'))

    except Exception as e:
        print(f"Error handling message: {e}")
        response = json.dumps({
            "status": "error",
            "message": f"Exception occurred: {str(e)}"
        })
        client_socket.sendall(response.encode('utf-8'))

#handling receive message requests
def handle_receive_message_request(client_socket, header):
    try:
        op_code, sender_id, receiver_id, message_id, content_hash = parse_header(header)

        with clients_db_lock:
            if sender_id not in clients_db:
                response = json.dumps({
                    "status": "error",
                    "message": f"Client {sender_id} not registered."
                })
                client_socket.sendall(response.encode('utf-8'))
                return

        with messages_db_lock:
            matching_message_id = None
            matching_message = None
            for msg_id, msg_data in messages_db.items():
                if msg_data["receiver_id"] == sender_id:
                    matching_message_id = msg_id
                    matching_message = msg_data
                    break

            if not matching_message:
                response = json.dumps({
                    "status": "no_message",
                    "message": "No messages found for the client."
                })
                client_socket.sendall(response.encode('utf-8'))
                return

            del messages_db[matching_message_id]

        aes_key = clients_db[sender_id]["aes_key"]
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=b'\x00' * 16)

        content_to_encrypt = matching_message["content"].encode('utf-8')
        encrypted_content = cipher_aes.encrypt(pad(content_to_encrypt, AES.block_size))

        content_hash = calculate_hash(content_to_encrypt)
        encrypted_hash = cipher_aes.encrypt(pad(content_hash, AES.block_size))

        response = {
            "status": "success",
            "sender_id": matching_message["sender_id"],  # Include sender_id
            "encrypted_message": encrypted_content.hex(),
            "encrypted_hash": encrypted_hash.hex()
        }
        client_socket.sendall(json.dumps(response).encode('utf-8'))

    except Exception as e:
        print(f"Error handling message receive request: {e}")
        response = json.dumps({
            "status": "error",
            "message": f"Exception occurred: {str(e)}"
        })
        client_socket.sendall(response.encode('utf-8'))

#as asked the 6 digits function
def send_by_secure_channel(client_socket):
    try:
        random_code = f"{random.randint(100000, 999999)}"
        print(f"Generated Code: {random_code}")

        client_socket.sendall(random_code.encode('utf-8'))
        print("Code sent to client.")

        client_response = client_socket.recv(1024).decode('utf-8')
        print(f"Client Response: {client_response}")

        if client_response == random_code:
            print("Authentication successful!")
            return True
        else:
            print("Authentication failed.")
            return False

    except Exception as e:
        print(f"Error in SendBySecureChannel: {e}")
        return False

#receiving acknowledgment
def handle_acknowledgment(header):
    try:
        op_code, sender_id, receiver_id, message_id, content_hash = parse_header(header)

        with clients_db_lock:
            if sender_id not in clients_db:
                print(f"Received acknowledgment from unregistered Client {sender_id}. Ignoring.")
                return

        print(f"Received acknowledgment from Client {sender_id}.")
        # No response is sent back to the client.

    except Exception as e:
        print(f"Error handling acknowledgment: {e}")

