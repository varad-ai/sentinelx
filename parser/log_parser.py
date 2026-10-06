from datetime import datetime

from ioc.extractor import extract_iocs
from detection.engine import detect_event
from risk_engine.engine import calculate_risk

from database.db import (
    initialize_database,
    save_event,
    save_detections,
    save_iocs
)


LOG_FILE = "honeypot/connections.log"


def parse_log_line(line):
    try:
        parts = line.strip().split(" | ")

        timestamp = datetime.fromisoformat(parts[0])
        event_type = parts[1].split("=", 1)[1]
        ip = parts[2].split("=", 1)[1]
        port = int(parts[3].split("=", 1)[1])
        service = parts[4].split("=", 1)[1]
        data = parts[5].split("=", 1)[1]

        return {
            "timestamp": timestamp,
            "event_type": event_type,
            "ip": ip,
            "port": port,
            "service": service,
            "data": data
        }

    except (ValueError, IndexError):
        print(f"Invalid log entry: {line.strip()}")
        return None


# Initialize database
initialize_database()


# Read honeypot logs
with open(LOG_FILE, "r") as log_file:

    for line in log_file:

        event = parse_log_line(line)

        if event:

            print("\n==============================")
            print("EVENT")
            print("==============================")

            print("Event:", event)

            # Extract IOCs
            iocs = extract_iocs(event)

            print("\nIOCs:", iocs)

            # Detect suspicious activity
            detections = detect_event(event, iocs)

            print("\nDetections:", detections)

            # Calculate risk
            risk = calculate_risk(detections)

            print("\nRisk:", risk)

            # Save event to database
            event_id = save_event(event, risk)

            # Save detections
            save_detections(event_id, detections)

            # Save IOCs
            save_iocs(event_id, iocs)

            print("\nDatabase: Event saved")
            print("Event ID:", event_id)

            print("==============================")