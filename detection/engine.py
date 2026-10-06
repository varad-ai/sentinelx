def detect_event(event, iocs):
    detections = []

    data = event.get("data", "").lower()

    # Rule 1: Suspicious command detection
    suspicious_commands = [
        "whoami",
        "uname",
        "passwd",
        "sudo",
        "chmod",
        "curl",
        "wget",
        "nc",
        "bash",
        "sh"
    ]

    for command in suspicious_commands:
        if command in data:
            detections.append({
                "rule": "suspicious_command",
                "match": command,
                "severity": "medium"
            })

    # Rule 2: Suspicious IOC detection
    if (
        iocs.get("domains")
        or iocs.get("urls")
        or iocs.get("hashes")
    ):
        detections.append({
            "rule": "ioc_detected",
            "match": "IOC found in event",
            "severity": "high"
        })

    return detections