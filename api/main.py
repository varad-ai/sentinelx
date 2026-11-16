
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import sqlite3


DATABASE_FILE = "database/sentinelx.db"


app = FastAPI(
    title="SentinelX API",
    description="Adaptive Honeypot and Threat Intelligence Platform",
    version="1.0.0"
)


# Serve dashboard static files
app.mount(
    "/static",
    StaticFiles(directory="dashboard"),
    name="static"
)


def get_connection():
    connection = sqlite3.connect(DATABASE_FILE)
    connection.row_factory = sqlite3.Row
    return connection


@app.get("/")
def root():
    return {
        "message": "SentinelX API is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.get("/dashboard")
def dashboard():
    return FileResponse("dashboard/index.html")


@app.get("/events")
def get_events():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM events
        ORDER BY id DESC
    """)

    events = [dict(row) for row in cursor.fetchall()]
    connection.close()

    return {
        "total": len(events),
        "events": events
    }


@app.get("/detections")
def get_detections():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM detections
        ORDER BY id DESC
    """)

    detections = [dict(row) for row in cursor.fetchall()]
    connection.close()

    return {
        "total": len(detections),
        "detections": detections
    }


@app.get("/iocs")
def get_iocs():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM iocs
        ORDER BY id DESC
    """)

    iocs = [dict(row) for row in cursor.fetchall()]
    connection.close()

    return {
        "total": len(iocs),
        "iocs": iocs
    }


@app.get("/stats")
def get_stats():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(DISTINCT source_ip)
        FROM events
        WHERE source_ip IS NOT NULL
    """)
    unique_ips = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM events
        WHERE risk_level = 'high'
    """)
    high_risk_events = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM events
        WHERE risk_level = 'critical'
    """)
    critical_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM iocs")
    total_iocs = cursor.fetchone()[0]

    connection.close()

    return {
        "total_events": total_events,
        "unique_ips": unique_ips,
        "high_risk_events": high_risk_events,
        "critical_events": critical_events,
        "total_iocs": total_iocs
    }


@app.get("/timeline")
def get_timeline():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            substr(timestamp, 1, 13) AS hour,
            COUNT(*) AS event_count
        FROM events
        GROUP BY hour
        ORDER BY hour ASC
    """)

    timeline = [
        dict(row) for row in cursor.fetchall()
    ]

    connection.close()

    return {
        "timeline": timeline
    }


@app.get("/top-ips")
def get_top_ips():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            source_ip,
            COUNT(*) AS event_count
        FROM events
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY event_count DESC
        LIMIT 5
    """)

    top_ips = [
        dict(row) for row in cursor.fetchall()
    ]

    connection.close()

    return {
        "total": len(top_ips),
        "top_ips": top_ips
    }
