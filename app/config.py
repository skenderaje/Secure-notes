"""Settings read from the environment. Secrets never have a default in production."""

import os
import secrets


class Settings:
    def __init__(self) -> None:
        self.env = os.getenv("APP_ENV", "development")
        self.database_url = os.getenv("DATABASE_URL", "sqlite:///./securenotes.db")
        secret = os.getenv("SECRET_KEY")
        if not secret:
            if self.is_production:
                raise RuntimeError("SECRET_KEY must be set in production")
            # Development only: a fresh key per process logs everyone out on restart.
            secret = secrets.token_urlsafe(32)
        self.secret_key = secret
        self.session_max_age = int(os.getenv("SESSION_MAX_AGE", str(60 * 60 * 8)))

    @property
    def is_production(self) -> bool:
        return self.env == "production"


settings = Settings()
