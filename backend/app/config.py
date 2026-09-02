from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings; secrets belong in environment variables, never event data."""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="CYBERBUG_")
    database_url: str = Field(default=f"sqlite:///{Path(__file__).parents[1] / 'cyberbug.db'}")
    pseudonymization_secret: str = "development-only-replace-before-deployment"
    high_risk_threshold: int = 75
    intent_confidence_threshold: float = 0.70
    collector_token: str | None = None
    environment: str = "development"
    auto_create_schema: bool = True
    seed_demo_data: bool = True


settings = Settings()
