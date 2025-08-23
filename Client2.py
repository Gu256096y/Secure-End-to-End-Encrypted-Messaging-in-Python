#Guy Rav On - 315044743
#A main function for a client

from ClientRequestHandler import *
from ClientDataHandler import load_client_data

#The client program is interactive and lets the user self operation.
def interactive_client():
    server_address_main = ('localhost', 4343)
    #The user must insert a valid client id - 5 digits sequence.
    while True:
        sender_id_main = input("Enter client ID (5-digit number): ").strip()
        if sender_id_main.isdigit() and len(sender_id_main) == 5:
            sender_id_main = sender_id_main.encode('utf-8')
            break
        else:
            print("Invalid client ID. Please enter a 5-digit number.")
    # the user chooses what action to take next.
    while True:
        print("\nChoose an action:")
        print("1. Register")
        print("2. Send a message")
        print("3. Check for messages")
        print("4. Exit")

        choice = input("Enter the action number: ")

        if choice == "1":
            # Registration
            aes_key_main = load_client_data(sender_id_main)
            #If the client file is already exists it means that there is an existing registered client id as this one.
            if aes_key_main:
                print("Client is already registered.")
                while True:
                    sender_id_main = input("Enter client ID (5-digit number): ").strip()
                    if sender_id_main.isdigit() and len(sender_id_main) == 5:
                        sender_id_main = sender_id_main.encode('utf-8')
                        break
                    else:
                        print("Invalid client ID. Please enter a 5-digit number.")
            else:
                private_key_main, public_key_main = generate_rsa_keys()
                send_registration_message(server_address_main, sender_id_main, b"00000", public_key_main, private_key_main)

        elif choice == "2":
            #Send a message to another client - must be a valid id
            while True:
                receiver_id_main = input("Enter receiver client ID (5-digit number): ").strip()
                if receiver_id_main.isdigit() and len(receiver_id_main) == 5:
                    receiver_id_main = receiver_id_main.encode('utf-8')
                    break
                else:
                    print("Invalid receiver ID. Please enter a 5-digit number.")
            message_content = input("Enter message content: ").encode('utf-8')
            #encrypting the message using the client's symetric key.
            aes_key_main = load_client_data(sender_id_main)
            #the client might not be registered and still trying to send a message
            if not aes_key_main:
                print("You must register before sending messages.")
            else:
                send_message(server_address_main, sender_id_main, receiver_id_main, aes_key_main, message_content)

        elif choice == "3":
            #Check for messages
            send_receive_message_request(server_address_main, sender_id_main)

        elif choice == "4":
            #Exit
            print("Exiting the application.")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    interactive_client()