from __future__ import annotations
import asyncio, os
from app.repositories.target_repository import claim_due_scans
from app.services.target_service import execute_scan
from app.services.deep_inventory_service import enqueue_due_periodic

async def run_discovery_scheduler():
    interval=max(10,int(os.getenv("DISCOVERY_SCHEDULER_INTERVAL_SECONDS","30")))
    while True:
        try:
            for scan in claim_due_scans(limit=2):
                asyncio.create_task(asyncio.to_thread(execute_scan,scan,"scheduled"))
            await asyncio.to_thread(enqueue_due_periodic, 20)
        except Exception as exc:
            print(f"[discovery-scheduler] {exc}")
        await asyncio.sleep(interval)
