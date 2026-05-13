# This file is used to load environment variables from a .env file to make them accessible throughout the app using the `settings` object. 
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    SUPABASE_URL: str
    SUPABASE_SERVICE_KEY: str

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()