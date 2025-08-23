#Guy Rav On - 315044743
import hashlib
import struct

#Message structure
MESSAGE_STRUCTURE = {
    "op_code": 1,         # 1 byte for operation code
    "sender_id": 5,       # 5 bytes for sender's unique ID
    "receiver_id": 5,     # 5 bytes for receiver's unique ID
    "message_id": 5,      # 5 bytes for message ID
    "hash": 32,           # 32 bytes for SHA-256 hash
    "encrypted_content": None  # Variable length for encrypted content
}

#to calculate hashes
def calculate_hash(content: bytes) -> bytes:
    return hashlib.sha256(content).digest()

#to create headers
def create_message_header(op_code: int, sender_id: bytes, receiver_id: bytes, message_id: bytes, encrypted_content: bytes) -> bytes:
    if len(sender_id) != MESSAGE_STRUCTURE["sender_id"]:
        raise ValueError(f"Sender ID must be {MESSAGE_STRUCTURE['sender_id']} bytes.")
    if len(receiver_id) != MESSAGE_STRUCTURE["receiver_id"]:
        raise ValueError(f"Receiver ID must be {MESSAGE_STRUCTURE['receiver_id']} bytes.")
    if len(message_id) != MESSAGE_STRUCTURE["message_id"]:
        raise ValueError(f"Message ID must be {MESSAGE_STRUCTURE['message_id']} bytes.")

    content_hash = calculate_hash(encrypted_content)

    header = struct.pack(
        f"<B{MESSAGE_STRUCTURE['sender_id']}s{MESSAGE_STRUCTURE['receiver_id']}s{MESSAGE_STRUCTURE['message_id']}s{MESSAGE_STRUCTURE['hash']}s",
        op_code,
        sender_id,
        receiver_id,
        message_id,
        content_hash
    )

    return header

#to parse headers
def parse_header(header):
    try:
        unpacked_header = struct.unpack(
            f"<B{MESSAGE_STRUCTURE['sender_id']}s{MESSAGE_STRUCTURE['receiver_id']}s{MESSAGE_STRUCTURE['message_id']}s{MESSAGE_STRUCTURE['hash']}s",
            header
        )
        op_code, sender_id, receiver_id, message_id, content_hash = unpacked_header
        sender_id = sender_id.decode('utf-8').strip()
        receiver_id = receiver_id.decode('utf-8').strip()
        message_id = message_id.decode('utf-8').strip()
        return op_code, sender_id, receiver_id, message_id, content_hash
    except Exception as e:
        raise ValueError(f"Failed to parse header: {e}")

