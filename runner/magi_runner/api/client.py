from __future__ import annotations

import logging
from typing import Any

import requests
from requests import exceptions as request_exceptions

from magi_runner.core.config import RunnerConfig
from magi_runner.core.version import __version__


class MagiApiClient:
    def __init__(self, config: RunnerConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger.getChild("api")
        self.session = self._new_session()

    def _new_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = self.config.verify_tls
        if self.config.runner_secret:
            session.headers.update({"X-Runner-Secret": self.config.runner_secret})
        if self.config.runner_id:
            session.headers.update({"X-Runner-ID": self.config.runner_id})
        return session

    def reset_session(self) -> None:
        try:
            self.session.close()
        except Exception:
            pass
        self.session = self._new_session()

    def _url(self, path: str) -> str:
        return f"{self.config.server_url.rstrip('/')}{path}"

    def register(self, host_info: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "runner_name": self.config.runner_name,
            "registration_token": self.config.registration_token,
            "host_info": host_info,
        }
        response = self.session.post(self._url("/api/runners/register"), json=payload, timeout=20)
        response.raise_for_status()
        data = response.json()
        self.config.runner_id = data.get("runner_id")
        self.config.runner_secret = data.get("runner_secret")
        self.session.headers.update({"X-Runner-ID": self.config.runner_id or "", "X-Runner-Secret": self.config.runner_secret or ""})
        return data

    def heartbeat(self, host_info: dict[str, Any]) -> None:
        if not self.config.runner_id:
            raise RuntimeError("Runner is not registered")
        response = self.session.post(self._url("/api/runners/heartbeat"), json={"host_info": host_info, "runner_version": __version__, "status": "online"}, timeout=20)
        response.raise_for_status()

    def get_job(self) -> dict[str, Any] | None:
        if not self.config.runner_id:
            raise RuntimeError("Runner is not registered")
        response = self.session.get(self._url("/api/runners/jobs/next"), timeout=20)
        response.raise_for_status()
        data = response.json()
        job = data.get("job") if isinstance(data, dict) and "job" in data else data
        if not job or not job.get("job_id"):
            return None
        if "executor" not in job and job.get("job_type"):
            job["executor"] = job.get("job_type")
        if "type" not in job and job.get("job_type"):
            job["type"] = job.get("job_type")
        return job

    def send_result(self, job_id: str, result: dict[str, Any]) -> None:
        if not self.config.runner_id:
            raise RuntimeError("Runner is not registered")
        response = self.session.post(self._url(f"/api/runners/jobs/{job_id}/result"), json=result, timeout=60)
        response.raise_for_status()


    def ping(self) -> dict[str, Any]:
        response = self.session.get(self._url("/api/runners/ping"), timeout=10)
        response.raise_for_status()
        return response.json()
