from connectors.zap import parse_zap_file
from connectors.openvas import parse_openvas_file
import logging
from normalisers.zap import ZapNormalizer
from normalisers.openvas import OpenVASNormalizer
from db.findings_repo import upsert_findings_bulk
from uuid import uuid4
from dedup.fingerprint import generate_fingerprint
from dedup.canonical import classify_findings

logger = logging.getLogger(__name__)

def run_ingestion_pipeline(scanner: str, file_path: str, supabase):

    """
    End-to-end ingestion pipeline:
    Connector → Normaliser
    """

    scanner = scanner.strip().lower()
    scanner_configs = {
        "zap": (parse_zap_file, ZapNormalizer),
        "openvas": (parse_openvas_file, OpenVASNormalizer),
    }
    if scanner not in scanner_configs:
        raise ValueError(f"Unsupported scanner: {scanner}")

    connector, normalizer_type = scanner_configs[scanner]
    scan_id = str(uuid4())
    logger.info("Starting %s ingestion pipeline", scanner)

    raw_findings = connector(file_path)
    if not raw_findings:
        logger.info("No findings found for scanner=%s file=%s", scanner, file_path)
        return []

    logger.info("Found %s raw findings for scanner=%s", len(raw_findings), scanner)
    normalizer = normalizer_type()
    findings = []

    for raw_finding in raw_findings:
        finding_input = {**raw_finding, "scan_id": scan_id}
        finding = normalizer.normalize(finding_input)
        finding.fingerprint = generate_fingerprint(finding)
        findings.append(finding)

    classify_findings(supabase, findings)
    result = upsert_findings_bulk(supabase, findings)

    logger.info("Upserted %s findings for scanner=%s", len(result), scanner)

    return findings