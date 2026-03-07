from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    APP_NAME: str = "MailGuard"
    DEBUG: bool = False
    SECRET_KEY: str = "change-me-in-production"
    ADMIN_PASSWORD: str = ""
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:8000"
    ENCRYPTION_KEY: str = ""
    DATABASE_URL: str = "sqlite:////tmp/mailguard.db"
    MULTI_TENANT_MODE: str = "false"
    SEED_TENANT_NAME: str = ""
    SEED_TENANT_DOMAIN: str = ""
    SEED_TENANT_ID: str = ""
    SEED_CLIENT_ID: str = ""
    SEED_CLIENT_SECRET: str = ""
    SEED_GWS_REFRESH_TOKEN: str = ""
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

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


settings = Settings()
