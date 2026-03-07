from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore"
    )

    # App
    APP_NAME: str = "MailGuard"
    DEBUG: bool = False
    SECRET_KEY: str = "change-me-in-production"

    # Admin
    ADMIN_PASSWORD: str = ""

    # CORS
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:8000"

    # Encryption
    ENCRYPTION_KEY: str = ""

    # Database
    DATABASE_URL: str = "sqlite:////tmp/mailguard.db"

    # Multi-tenant
    MULTI_TENANT_MODE: str = "false"

    # Seed tenant
    SEED_TENANT_NAME: str = ""
    SEED_TENANT_DOMAIN: str = ""
    SEED_TENANT_ID: str = ""
    SEED_CLIENT_ID: str = ""
    SEED_CLIENT_SECRET: str = ""
    SEED_GWS_REFRESH_TOKEN: str = ""

    # Google OAuth
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/api/v1/google/callback"

    @property
    def multi_tenant_mode(self) -> bool:
        return self.MULTI_TENANT_MODE.lower() in ("true", "1", "yes")

    def get_allowed_origins(self) -> List[str]:
        if self.ALLOWED_ORIGINS == "*":
            return ["*"]
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",")]


settings = Settings()
