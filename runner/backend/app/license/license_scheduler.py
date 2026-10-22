from __future__ import annotations

import asyncio
import os

from app.license.license_service import license_service


async def run_license_scheduler() -> None:
    interval = int(os.getenv("LICENSE_CHECK_INTERVAL_SECONDS", "3600"))
    while True:
        await asyncio.sleep(interval)
        license_service.validate()
