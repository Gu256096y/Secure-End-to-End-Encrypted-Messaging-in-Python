#Guy Rav On 
#server main

from ServerMessagesCleanup import cleanup_messages
from ServerSecuredOperation import *
import threading

if __name__ == "__main__":
    # Start the cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_messages, daemon=True)
    cleanup_thread.start()

    # Start the TLS server
    start_tls_server()

