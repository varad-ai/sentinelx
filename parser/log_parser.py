
from datetime import datetime

from ioc.extractor import extract_iocs
from detection.engine import detect_event
from risk_engine.engine import calculate_risk

from database.db import (
    initialize_database,
    get_parser_offset,
    set_parser_offset,
    get_event_count,
    save_processed_event
)


LOG_FILE = "honeypot/connections.log"


def parse_log_line(line):
    try:
        parts = line.strip().split(" | ", 5)

        if len(parts) != 6:
            raise ValueError("Incorrect log format")

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


def main():

    initialize_database()

    # Get saved parser position
    offset = get_parser_offset()

    # First run: existing database records are preserved.
    # Start from the current end of the log file.
    if offset is None:

        offset = 0

        if get_event_count() > 0:
            import os
            offset = os.path.getsize(LOG_FILE)

            set_parser_offset(offset)

            print("Existing database detected.")
            print("Starting from the end of existing logs.")

        else:
            print("First parser run. Processing existing logs.")

    print(f"\nStarting parser from byte position: {offset}")

    processed_count = 0

    with open(LOG_FILE, "rb") as log_file:

        log_file.seek(offset)

        while True:

            line_start = log_file.tell()
            raw_line = log_file.readline()

            if not raw_line:
                break

            # Ignore incomplete lines.
            if not raw_line.endswith(b"\n"):
                log_file.seek(line_start)
                break

            next_offset = log_file.tell()

            line = raw_line.decode("utf-8", errors="replace")

            event = parse_log_line(line)

            if event is None:
                # Skip malformed complete lines safely.
                set_parser_offset(next_offset)
                continue

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

            # Save event and checkpoint atomically
            event_id = save_processed_event(
                event,
                risk,
                detections,
                iocs,
                next_offset
            )

            processed_count += 1

            print("\nDatabase: Event saved")
            print("Event ID:", event_id)
            print("==============================")

    print("\n================================")
    print("PARSER FINISHED")
    print("New events processed:", processed_count)
    print("================================")


if __name__ == "__main__":
    main()
