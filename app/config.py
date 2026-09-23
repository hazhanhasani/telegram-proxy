from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Telegram Proxy Control"
    app_env: str = "production"
    secret_key: str = "change-me-before-production"
    encryption_key: str = ""
    database_url: str = "sqlite:///./data/panel.db"
    admin_email: str = "admin@example.com"
    admin_password: str = ""
    session_https_only: bool = False
    ssh_timeout: int = 20
    ssh_connect_timeout: int = 12
    health_interval: int = 60
    public_base_url: str = "http://localhost:8080"
    api_token: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
