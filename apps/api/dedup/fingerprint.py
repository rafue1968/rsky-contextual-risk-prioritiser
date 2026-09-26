import hashlib
from urllib.parse import urlsplit, urlunsplit


def generate_fingerprint(finding):

    cve_ids = getattr(finding, "cve_ids", None) or []
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    cve_ids = sorted(
        {
            str(cve).strip().upper()
            for cve in cve_ids
            if str(cve).strip().upper() not in {"NONE", "NOCVE", "UNKNOWN"}
        }
    )

    if not cve_ids:
        return None

    cve = ",".join(cve_ids)

    asset = getattr(finding, "target_host", None) or getattr(finding, "target_url", None) or "unknown"
    asset = str(asset).strip().lower().rstrip("/")
    if "://" in asset:
        parsed_asset = urlsplit(asset)
        asset = urlunsplit((parsed_asset.scheme, parsed_asset.netloc, parsed_asset.path.rstrip("/"), "", ""))

    severity = str(getattr(finding, "severity_level", None) or "informational").lower()

    fingerprint_string = (
        f"{cve}|{asset}|{severity}"
    )

    return hashlib.sha256(
        fingerprint_string.encode()
    ).hexdigest()