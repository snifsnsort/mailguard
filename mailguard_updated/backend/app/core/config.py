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
    DATABASE_URL: str = "sqlite:///./mailguard.db"

    # Multi-tenant SaaS mode (requires Clerk)
    MULTI_TENANT_MODE: bool = False

    def get_allowed_origins(self) -> List[str]:
        if self.ALLOWED_ORIGINS == "*":
            return ["*"]
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",")]

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
