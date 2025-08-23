#Guy Rav On - 315044743
import time
from ServerDB import messages_db
from ServerRequestHandler import messages_db_lock

#to keep only 2 messages for each client
def cleanup_messages():
    while True:
        time.sleep(120)
        with messages_db_lock:
            print("Running messages cleanup...")
            #group messages by receiver_id
            grouped_messages = {}
            for message_id, message_data in messages_db.items():
                receiver_id = message_data["receiver_id"]
                if receiver_id not in grouped_messages:
                    grouped_messages[receiver_id] = []
                grouped_messages[receiver_id].append(message_id)

            #only the 2 newest messages for each receiver_id
            for receiver_id, message_ids in grouped_messages.items():
                #only the 2 most recent messages (last ones in insertion order)
                newest_message_ids = message_ids[-2:]
                messages_to_delete = [msg_id for msg_id in message_ids if msg_id not in newest_message_ids]
                for message_id in messages_to_delete:
                    del messages_db[message_id]

            print("Messages cleanup completed.")

