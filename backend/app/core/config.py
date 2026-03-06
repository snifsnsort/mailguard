from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # App
    APP_NAME: str = "MailGuard"
    DEBUG: bool = False
    SECRET_KEY: str = "change-me-in-production"

    # CORS - accepts either "*" or comma-separated origins
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:8000"

    # Encryption key for storing tenant client secrets at rest (Fernet)
    ENCRYPTION_KEY: str = ""

    # Database
    DATABASE_URL: str = "sqlite:////tmp/mailguard.db"

    # Multi-tenant SaaS mode — stored as str to tolerate empty-string env vars.
    # Azure sets unset booleans as "" which pydantic v2 rejects for bool fields.
    MULTI_TENANT_MODE: str = "false"

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


settings = Settings()
