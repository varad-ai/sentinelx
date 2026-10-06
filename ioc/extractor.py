import ipaddress
import re


def extract_iocs(event):
    iocs = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": []
    }

    # Extract source IP
    ip = event.get("ip")

    if ip:
        try:
            ipaddress.ip_address(ip)
            iocs["ips"].append(ip)
        except ValueError:
            pass

    # Only inspect actual event data
    text = event.get("data", "")

    if not isinstance(text, str):
        text = str(text)

    # Extract URLs
    urls = re.findall(
        r"https?://[^\s'\"<>]+",
        text
    )

    for url in urls:
        if url not in iocs["urls"]:
            iocs["urls"].append(url)

    # Extract domains
    domains = re.findall(
        r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
        text
    )

    for domain in domains:
        if domain not in iocs["domains"]:
            iocs["domains"].append(domain)

    # Extract MD5, SHA1 and SHA256 hashes
    hashes = re.findall(
        r"\b[a-fA-F0-9]{32}\b"
        r"|\b[a-fA-F0-9]{40}\b"
        r"|\b[a-fA-F0-9]{64}\b",
        text
    )

    for file_hash in hashes:
        if file_hash not in iocs["hashes"]:
            iocs["hashes"].append(file_hash)

    return iocs