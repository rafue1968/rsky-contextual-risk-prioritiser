from connectors.zap import parse_zap_file
from normalisers.core import normalise_finding
import logging

logger = logging.getLogger(__name__)

def run_ingestion_pipeline(file_path: str):

    """
    End-to-end ingestion pipeline:
    Connector → Normaliser
    """

    logger.info("Starting ingestion pipeline")

    # raw_findings = parse_zap_file("zap.json")
    raw_findings = parse_zap_file(file_path)

    if not raw_findings:
        logger.error("No findings found")
        return []

    logger.info(f"Found {len(raw_findings)} findings")

    final_findings = [
        normalise_finding(f)
        for f in raw_findings
    ]

    logger.info(f"Found {len(final_findings)} normalised findings")

    return final_findings