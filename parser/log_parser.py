from datetime import datetime
from ioc.extractor import extract_iocs


LOG_FILE = "honeypot/connections.log"


def parse_log_line(line):
    try:
        parts = line.strip().split(" | ")

        timestamp = datetime.fromisoformat(parts[0])
        event_type = parts[1].split("=")[1]
        ip = parts[2].split("=")[1]
        port = int(parts[3].split("=")[1])
        service = parts[4].split("=")[1]

        return {
            "timestamp": timestamp,
            "event_type": event_type,
            "ip": ip,
            "port": port,
            "service": service
        }

    except (ValueError, IndexError):
        print(f"Invalid log entry: {line.strip()}")
        return None


with open(LOG_FILE, "r") as log_file:
    for line in log_file:
        event = parse_log_line(line)

        if event:
            print("Event:", event)

            iocs = extract_iocs(event)

            print("IOCs:", iocs)

