from datetime import datetime

LOG_FILE = "honeypot/connections.log"


def parse_log_line(line):
    try:
        parts = line.strip().split(" | ")

        timestamp = datetime.fromisoformat(parts[0])
        ip = parts[1].split("=")[1]
        port = int(parts[2].split("=")[1])

        return {
            "timestamp": timestamp,
            "ip": ip,
            "port": port
        }

    except (ValueError, IndexError):
        print(f"Invalid log entry: {line.strip()}")
        return None


with open(LOG_FILE, "r") as log_file:
    for line in log_file:
        event = parse_log_line(line)

        if event:
            print(event)