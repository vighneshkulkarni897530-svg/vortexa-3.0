import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "PromptShield Policy & Database Layer"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_V1_STR: str = "/api/v1"

    # Database
    # Default to local sqlite database file if PostgreSQL is not specified
    DATABASE_URL: str = "sqlite:///./promptshield.db"
    DATABASE_ECHO: bool = False

    # Security & Tokens
    JWT_SECRET_KEY: str = "insecure_dev_secret_key_change_in_production_min_32_bytes_long"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Fail-Secure Safety Guarantee
    FAIL_SECURE_MODE: bool = True
    DEFAULT_FAIL_SECURE_ACTION: str = "BLOCK"

    # Redaction
    SECRET_MASK: str = "[REDACTED_SECRET]"
    REDACTED_CONTENT_MAX_LEN: int = 256

    # CORS
    CORS_ORIGINS: List[str] = ["*"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
