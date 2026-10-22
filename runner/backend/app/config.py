from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from dotenv import load_dotenv

BACKEND_DIR: Final[Path] = Path(__file__).resolve().parents[1]
PROJECT_ROOT: Final[Path] = BACKEND_DIR.parent
FRONTEND_DIR: Final[Path] = PROJECT_ROOT / "frontend"
LOGS_DIR: Final[Path] = BACKEND_DIR / "logs"
SCRIPTS_DIR: Final[Path] = PROJECT_ROOT / "scripts"
ENV_FILE: Final[Path] = BACKEND_DIR / ".env"

# Clean v2 rule:
# PostgreSQL is the official source of truth for settings, credentials,
# alerts, playbooks, executions, reports and scan snapshots.
# Files are kept only for runtime logs, license files, static assets and
# temporary materialized scripts during execution.
for folder in [LOGS_DIR, SCRIPTS_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

load_dotenv(ENV_FILE)

ZOHO_ACCOUNTS_URL: Final[str] = os.getenv("ZOHO_ACCOUNTS_URL", "https://accounts.zoho.com")
ZOHO_CLIENT_ID: Final[str] = os.getenv("ZOHO_CLIENT_ID", "")
ZOHO_CLIENT_SECRET: Final[str] = os.getenv("ZOHO_CLIENT_SECRET", "")
ZOHO_REFRESH_TOKEN: Final[str] = os.getenv("ZOHO_REFRESH_TOKEN", "")
EC_BASE_URL: Final[str] = os.getenv(
    "EC_BASE_URL", "https://endpointcentral.manageengine.com"
).rstrip("/")
REQUEST_TIMEOUT: Final[int] = int(os.getenv("REQUEST_TIMEOUT", "60"))
SECURITY_BACKEND_URL: Final[str] = os.getenv("SECURITY_BACKEND_URL", "http://127.0.0.1:3000").rstrip("/")
APP_PORT: Final[int] = int(os.getenv("APP_PORT", "8000"))
