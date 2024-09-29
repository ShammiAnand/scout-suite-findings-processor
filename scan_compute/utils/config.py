"""App level config."""

from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Address
from typing import TYPE_CHECKING

from pydantic import (
    MongoDsn,
    RedisDsn,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

if TYPE_CHECKING:
    from pydantic_settings.sources import DotenvType


class Settings(BaseSettings):
    """Global Config."""

    API_KEY: str

    DATABASE_HOST: IPv4Address
    DATABASE_READ_HOST: str
    DATABASE_PORT: int
    DATABASE_NAME: str
    DATABASE_USER_NAME: str
    DATABASE_PASSWORD: str

    CACHE_HOST: str
    CACHE_PORT: int

    REDIS_DSN: RedisDsn
    MONGODB_DSN: MongoDsn

    AWS_ACCESS_KEY_ID: str
    AWS_SECRET_ACCESS_KEY: str

    S3_BUCKET_REGION_NAME: str
    S3_BUCKET_NAME_FOR_SCAN_REPORT: str

    # FOR SECRET WORKFLOW
    GCP_WORKFLOW_CREDENTIAL: str
    GCP_WORKFLOW_PROJECT_ID: str
    GCP_WORKFLOW_LOCATION: str
    GCP_WORKFLOW_IDENTIFIER: str

    # FOR IDENTITY
    GCP_CREDENTIALS_FOR_IDENTITY: str
    ANOMALY_JOB_PROJECT_NAME: str
    ANOMALY_JOB_REGION: str
    ANOMALY_JOB_NAME: str
    ANOMALY_JOB_TIMEOUT_IN_SECONDS: int

    IDENTITY_WORKFLOW_PROJECT_NAME: str
    IDENTITY_WORKFLOW_PROJECT_LOCATION: str
    IDENTITY_WORKFLOW_PROJECT_ID: str

    IP_INSIGHT_PROJECT_NAME: str
    IP_INSIGHT_JOB_LOCATION: str
    IP_INSIGHT_JOB_NAME: str

    IDENTITY_SCANNER_API: str

    BACKEND_API_IP: str

    WORKLOAD_API_IP: str

    # FOR DATA SECURITY
    DS_SQS_QUEUE_URL: str

    # For Visualizer
    # Example - http://127.0.0.1:4000
    VISUALIZER_API: str
    VISUALIZER_API_KEY: str


@lru_cache
def get_settings(env_path: DotenvType | None = ".env") -> Settings:
    """Get Setting instance."""

    class EnvSettings(Settings):
        model_config = SettingsConfigDict(env_file=env_path)

    return EnvSettings()  # type: ignore[reportCallIssue, call-arg]


settings = get_settings()
