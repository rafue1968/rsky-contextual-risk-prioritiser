from connectors.zap import parse_zap_file
from connectors.openvas import parse_openvas_file
from normalisers.core import normalise_finding
import logging
from normalisers.zap import ZapNormalizer
from normalisers.openvas import OpenVASNormalizer
from db.findings_repo import upsert_findings_bulk
from schemas.finding import Finding
from uuid import uuid4

logger = logging.getLogger(__name__)

def run_ingestion_pipeline(scanner: str, file_path: str, supabase):

    """
    End-to-end ingestion pipeline:
    Connector → Normaliser
    """

    scan_id = str(uuid4())

    logger.info(f"Starting {scanner} ingestion pipeline")

    # raw_findings = parse_zap_file("zap.json")
    if scanner == "zap":
        raw_findings = parse_zap_file(file_path)
        normalizer = ZapNormalizer()
    elif scanner == "openvas":
        raw_findings = parse_openvas_file(file_path)
        normalizer = OpenVASNormalizer()
    else:
        raise ValueError(f"Unsupported scanner: {scanner}")


    if not raw_findings:
        logger.error("No findings found")
        return []

    logger.info(f"Found {len(raw_findings)} findings")

    findings = []

    for f in raw_findings:
        f["scan_id"] = scan_id
        findings.append(
            normalizer.normalize(f)
        )


    result = upsert_findings_bulk(supabase, findings)

    


    logger.info(f"Upserted {len(result)} findings")

    return findings