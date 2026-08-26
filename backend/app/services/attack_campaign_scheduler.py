from __future__ import annotations
import asyncio, os
from app.services.attack_campaign_service import process_campaigns_once

async def run_attack_campaign_scheduler():
    interval=max(5,int(os.getenv('ATTACK_CAMPAIGN_SCHEDULER_INTERVAL_SECONDS','10')))
    while True:
        try: await asyncio.to_thread(process_campaigns_once)
        except Exception as exc: print(f'[attack-campaign-scheduler] {exc}')
        await asyncio.sleep(interval)
