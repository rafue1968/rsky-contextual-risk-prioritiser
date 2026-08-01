import os

from supabase import create_client

from pipelines.ingestion_pipeline import run_ingestion_pipeline


SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]


supabase = create_client(
    SUPABASE_URL,
    SUPABASE_KEY
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