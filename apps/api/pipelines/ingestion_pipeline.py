from connectors.zap import parse_zap_file
from connectors.openvas import parse_openvas_file
from normalisers.core import normalise_finding
import logging
from normalisers.zap import UnifiedFindingNormalizer as ZapNormalizer
from normalisers.openvas import UnifiedFindingNormalizer as OpenVASNormalizer


logger = logging.getLogger(__name__)

def run_ingestion_pipeline(scanner: str, file_path: str):

    """
    End-to-end ingestion pipeline:
    Connector → Normaliser
    """

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

    # final_findings = [
    #     normalise_finding(f)
    #     for f in raw_findings
    # ]

    # logger.info(f"Found {len(final_findings)} normalised findings")

    # return final_findings

    return [
        normalizer.normalize(f)
        for f in raw_findings
    ]