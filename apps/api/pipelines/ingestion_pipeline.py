from connectors.zap import parse_zap_file
from normalisers.core import normalise_finding

def run_ingestion_pipeline(file_path: str):
    """
    End-to-end ingestion pipeline:
    Connector → Normaliser
    """

    raw_findings = parse_zap_file("zap.json")

    final_findings = [
        normalise_finding(f)
        for f in raw_findings
    ]

    return final_findings