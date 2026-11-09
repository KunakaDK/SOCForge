from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover - optional in minimal environments
    pass


@dataclass(frozen=True)
class Settings:
    db_path: str = os.getenv("SOCFORGE_DB_PATH", "./data/socforge.db")
    hmac_secret: str = os.getenv("SOCFORGE_HMAC_SECRET", "local-development-only-change-me")
    require_signatures: bool = os.getenv("SOCFORGE_REQUIRE_SIGNATURES", "true").lower() in {"1", "true", "yes"}
    environment: str = os.getenv("SOCFORGE_ENV", "development")
    api_host: str = os.getenv("SOCFORGE_API_HOST", "127.0.0.1")
    api_port: int = int(os.getenv("SOCFORGE_API_PORT", "8000"))

    def ensure_data_directory(self) -> None:
        Path(self.db_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


settings = Settings()
