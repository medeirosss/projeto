from __future__ import annotations
import asyncio
from app.services.security_monitoring_service import tick

async def run_security_monitoring_scheduler():
    while True:
        try: await asyncio.to_thread(tick)
        except Exception as exc: print(f'[security-monitoring] {exc}')
        await asyncio.sleep(60)
