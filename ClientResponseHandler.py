#Guy Rav On - 315044743
import json
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES
from Protocol import *
from ClientAcknowledgment import send_acknowledgment

#handle response from the server - message received, decrypt it and hash validation.
def handle_received_message(response, aes_key):
    try:
        response_data = json.loads(response.decode('utf-8'))
        if response_data.get("status") == "success":
            encrypted_message = bytes.fromhex(response_data["encrypted_message"])
            encrypted_hash = bytes.fromhex(response_data["encrypted_hash"])
            sender_id = response_data.get("sender_id", "Unknown")  # Get sender_id or "Unknown" if not provided

            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=b'\x00' * 16)
            decrypted_message = unpad(cipher_aes.decrypt(encrypted_message), AES.block_size).decode('utf-8')

            decrypted_hash = unpad(cipher_aes.decrypt(encrypted_hash), AES.block_size)

            calculated_hash = calculate_hash(decrypted_message.encode('utf-8'))

            print(f"Decrypted Message: {decrypted_message}")
            print(f"Message Sender ID: {sender_id}")

            if decrypted_hash == calculated_hash:
                print("Hash verification succeeded. The message is authentic.")
                #Send acknowledgment to the server
                send_acknowledgment(('localhost', 4343), sender_id.encode('utf-8'))
            else:
                print("Hash verification failed. The message might be tampered with.")
        else:
            print(f"Server Response: {response_data.get('message')}")
    except Exception as e:
        print(f"Error handling received message: {e}")

