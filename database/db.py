import sqlite3

DATABASE_FILE = "database/sentinelx.db"


def get_connection():
    return sqlite3.connect(DATABASE_FILE)


def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT,
            source_ip TEXT,
            source_port INTEGER,
            service TEXT,
            data TEXT,
            risk_score INTEGER,
            risk_level TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            rule TEXT,
            match TEXT,
            severity TEXT,
            FOREIGN KEY (event_id) REFERENCES events(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            ioc_type TEXT,
            ioc_value TEXT,
            FOREIGN KEY (event_id) REFERENCES events(id)
        )
    """)

    connection.commit()
    connection.close()


def save_event(event, risk):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO events (
            timestamp,
            event_type,
            source_ip,
            source_port,
            service,
            data,
            risk_score,
            risk_level
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event["timestamp"].isoformat(),
        event["event_type"],
        event["ip"],
        event["port"],
        event["service"],
        event["data"],
        risk["score"],
        risk["risk_level"]
    ))

    event_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return event_id


def save_detections(event_id, detections):
    connection = get_connection()
    cursor = connection.cursor()

    for detection in detections:
        cursor.execute("""
            INSERT INTO detections (
                event_id,
                rule,
                match,
                severity
            )
            VALUES (?, ?, ?, ?)
        """, (
            event_id,
            detection["rule"],
            detection["match"],
            detection["severity"]
        ))

    connection.commit()
    connection.close()


def save_iocs(event_id, iocs):
    connection = get_connection()
    cursor = connection.cursor()

    for ip in iocs.get("ips", []):
        cursor.execute("""
            INSERT INTO iocs (
                event_id,
                ioc_type,
                ioc_value
            )
            VALUES (?, ?, ?)
        """, (event_id, "ip", ip))

    for domain in iocs.get("domains", []):
        cursor.execute("""
            INSERT INTO iocs (
                event_id,
                ioc_type,
                ioc_value
            )
            VALUES (?, ?, ?)
        """, (event_id, "domain", domain))

    for url in iocs.get("urls", []):
        cursor.execute("""
            INSERT INTO iocs (
                event_id,
                ioc_type,
                ioc_value
            )
            VALUES (?, ?, ?)
        """, (event_id, "url", url))

    for file_hash in iocs.get("hashes", []):
        cursor.execute("""
            INSERT INTO iocs (
                event_id,
                ioc_type,
                ioc_value
            )
            VALUES (?, ?, ?)
        """, (event_id, "hash", file_hash))

    connection.commit()
    connection.close()