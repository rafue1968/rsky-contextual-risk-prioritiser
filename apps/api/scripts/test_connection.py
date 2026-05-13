import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from supabase import create_client
from config import settings

supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_KEY)

response = supabase.table("findings").select("*").limit(1).execute()

print(response)