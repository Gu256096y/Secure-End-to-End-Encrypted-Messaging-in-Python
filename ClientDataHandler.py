#Guy Rav On - 315044743
import os
from Crypto.PublicKey import RSA

#function to create a pair of A-symetric RSA keys
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key_generated = key.export_key()
    public_key_generated = key.publickey().export_key()
    return private_key_generated, public_key_generated

#save the client data - id, keys in a file.
def save_client_data(client_id, private_key, aes_key=None):
    file_name = f"client_{client_id.decode('utf-8').strip()}.txt"
    with open(file_name, "w", encoding="utf-8") as file:
        file.write(f"PRIVATE_KEY:\n{private_key.decode('utf-8')}\n")
        if aes_key:
            file.write(f"AES_KEY:\n{aes_key.hex()}\n")
    print(f"Client data saved to {file_name}.")

#load the client data from the file
def load_client_data(client_id):
    file_name = f"client_{client_id.decode('utf-8').strip()}.txt"
    if os.path.exists(file_name):
        with open(file_name, "r", encoding="utf-8") as file:
            data = file.read()
            if "AES_KEY:" in data:
                aes_key_hex = data.split("AES_KEY:")[1].strip()
                aes_key = bytes.fromhex(aes_key_hex)
                return aes_key
    return None