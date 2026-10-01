from supabase import create_client

from config import settings
from pipelines.ingestion_pipeline import run_ingestion_pipeline


supabase = create_client(
    settings.SUPABASE_URL,
    settings.SUPABASE_SERVICE_KEY,
)


results = run_ingestion_pipeline(
    scanner="zap",
    file_path="tests/data/zap_export.json",
    supabase=supabase
)


print(f"Ingested {len(results)} findings")

for finding in results:
    print(
        finding.title,
        finding.severity_level,
        finding.target_host
    )