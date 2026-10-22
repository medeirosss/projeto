from __future__ import annotations

from pathlib import Path
from typing import Any

from .eventlogs import EventLogCollector
from .filesystem import FileCollector
from .network import NetworkCollector
from .processes import ProcessCollector


class EvidenceCollector:
    def collect(self, collect_cfg: dict[str, Any], job_dir: Path) -> dict[str, Any]:
        evidence: dict[str, Any] = {}
        collect_cfg = collect_cfg or {}

        if collect_cfg.get("processes"):
            evidence["processes"] = ProcessCollector().collect()
        if collect_cfg.get("network"):
            evidence["network"] = NetworkCollector().collect()
        files = collect_cfg.get("files") or []
        if files:
            evidence["files"] = FileCollector().collect(files, job_dir)
        if collect_cfg.get("eventlogs"):
            ev_cfg = collect_cfg.get("eventlogs")
            channels = ev_cfg.get("channels") if isinstance(ev_cfg, dict) else None
            max_events = int(ev_cfg.get("max_events", 30)) if isinstance(ev_cfg, dict) else 30
            evidence["eventlogs"] = EventLogCollector().collect(channels, max_events)
        return evidence
