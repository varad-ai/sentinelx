import socket
from datetime import datetime


HOST = "0.0.0.0"
PORT = 2222
LOG_FILE = "honeypot/connections.log"


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(5)

print(f"SentinelX listener running on port {PORT}")


while True:
    client, address = server.accept()

    timestamp = datetime.now().isoformat()

    source_ip = address[0]
    source_port = address[1]
    event_type = "connection"
    service = "tcp"

    log_entry = (
        f"{timestamp} | "
        f"EVENT={event_type} | "
        f"IP={source_ip} | "
        f"PORT={source_port} | "
        f"SERVICE={service}\n"
    )

    print(
        f"Connection received from "
        f"{source_ip}:{source_port}"
    )

    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry)

    client.close()