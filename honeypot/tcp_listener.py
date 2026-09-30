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

    ip = address[0]
    source_port = address[1]

    log_entry = f"{timestamp} | IP={ip} | PORT={source_port}\n"

    print(f"Connection received from {ip}:{source_port}")

    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_entry)

    client.close()