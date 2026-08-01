import hashlib

def generate_fingerprint(finding):

    cve_ids = finding.cve_ids

    if not cve_ids:
        return None

    cve = sorted(cve_ids)[0]


    asset = (
        finding.target_host
        or finding.target_url
        or "unknown"
    )

    severity = finding.severity_level

    fingerprint_string = (
        f"{cve}|{asset}|{severity}"
    )

    return hashlib.sha256(
        fingerprint_string.encode()
    ).hexdigest()