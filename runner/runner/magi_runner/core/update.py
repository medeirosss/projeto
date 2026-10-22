from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from magi_runner.core.config import RunnerConfig
from magi_runner.core.version import __version__


@dataclass
class UpdateCheckResult:
    update_available: bool
    current_version: str
    latest_version: str | None = None
    package_url: str | None = None
    sha256: str | None = None
    notes: str | None = None
    raw_manifest: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "update_available": self.update_available,
            "current_version": self.current_version,
            "latest_version": self.latest_version,
            "package_url": self.package_url,
            "sha256": self.sha256,
            "notes": self.notes,
            "raw_manifest": self.raw_manifest or {},
        }


def _parse_version(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for token in value.replace("-", ".").split("."):
        digits = "".join(ch for ch in token if ch.isdigit())
        parts.append(int(digits or 0))
    return tuple(parts)


class UpdateManager:
    def __init__(self, config: RunnerConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger.getChild("update")
        self.data_path = config.data_path
        self.update_path = self.data_path / "updates"
        self.backup_path = self.update_path / "backup"
        self.last_check_file = self.update_path / "last_check.json"

    def _manifest_url(self) -> str:
        if self.config.update_manifest_url:
            return self.config.update_manifest_url
        return f"{self.config.server_url.rstrip('/')}/api/runners/updates/manifest"

    def _read_local_manifest(self, path: Path) -> dict[str, Any]:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    def _http_get_json(self, url: str) -> dict[str, Any]:
        response = requests.get(url, timeout=self.config.update_download_timeout_seconds, verify=self.config.verify_tls)
        response.raise_for_status()
        return response.json()

    def get_manifest(self) -> dict[str, Any]:
        url = self._manifest_url()
        parsed = urlparse(url)
        if parsed.scheme in ("", "file"):
            path = Path(parsed.path if parsed.scheme == "file" else url).expanduser().resolve()
            return self._read_local_manifest(path)
        return self._http_get_json(url)

    def check(self) -> UpdateCheckResult:
        if not self.config.update_enabled:
            return UpdateCheckResult(False, __version__, notes="Updates disabled in settings.json")
        manifest = self.get_manifest()
        latest_version = str(manifest.get("version") or "")
        package_url = manifest.get("package_url")
        sha256 = manifest.get("sha256")
        notes = manifest.get("notes")
        available = bool(latest_version and _parse_version(latest_version) > _parse_version(__version__))
        result = UpdateCheckResult(available, __version__, latest_version, package_url, sha256, notes, manifest)
        self.update_path.mkdir(parents=True, exist_ok=True)
        with self.last_check_file.open("w", encoding="utf-8") as fh:
            json.dump({"checked_at": time.time(), **result.as_dict()}, fh, indent=2, ensure_ascii=False)
        return result

    def _download_package(self, package_url: str) -> Path:
        self.update_path.mkdir(parents=True, exist_ok=True)
        target = self.update_path / "runner_update.zip"
        parsed = urlparse(package_url)
        if parsed.scheme in ("", "file"):
            source = Path(parsed.path if parsed.scheme == "file" else package_url).expanduser().resolve()
            shutil.copy2(source, target)
            return target
        with requests.get(package_url, stream=True, timeout=self.config.update_download_timeout_seconds, verify=self.config.verify_tls) as response:
            response.raise_for_status()
            with target.open("wb") as fh:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        fh.write(chunk)
        return target

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _project_root(self) -> Path:
        # magi_runner/core/update.py -> project root
        return Path(__file__).resolve().parents[2]

    def _backup_current(self, root: Path) -> Path:
        if self.backup_path.exists():
            shutil.rmtree(self.backup_path)
        self.backup_path.mkdir(parents=True, exist_ok=True)
        for item in root.iterdir():
            if item.name in {"runner_data", ".venv", "__pycache__"}:
                continue
            destination = self.backup_path / item.name
            if item.is_dir():
                shutil.copytree(item, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            else:
                shutil.copy2(item, destination)
        return self.backup_path

    def _extract_root(self, package: Path) -> Path:
        temp_dir = Path(tempfile.mkdtemp(prefix="magi_runner_update_"))
        with zipfile.ZipFile(package, "r") as archive:
            archive.extractall(temp_dir)
        entries = [p for p in temp_dir.iterdir() if not p.name.startswith("__MACOSX")]
        if len(entries) == 1 and entries[0].is_dir():
            return entries[0]
        return temp_dir

    def apply(self, allow_same_version: bool = False) -> dict[str, Any]:
        result = self.check()
        if not result.update_available and not allow_same_version:
            return {"status": "skipped", **result.as_dict()}
        if not result.package_url:
            raise RuntimeError("Update manifest does not define package_url")
        package = self._download_package(result.package_url)
        package_hash = self._sha256(package)
        expected_hash = (result.sha256 or "").lower().strip()
        if expected_hash and package_hash.lower() != expected_hash:
            raise RuntimeError(f"Update package SHA-256 mismatch. expected={expected_hash} actual={package_hash}")

        root = self._project_root()
        self._backup_current(root)
        extracted_root = self._extract_root(package)
        try:
            for item in extracted_root.iterdir():
                if item.name in {"runner_data", ".venv", "__pycache__"}:
                    continue
                target = root / item.name
                if target.exists():
                    if target.is_dir():
                        shutil.rmtree(target)
                    else:
                        target.unlink()
                if item.is_dir():
                    shutil.copytree(item, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
                else:
                    shutil.copy2(item, target)
            marker = self.update_path / "pending_restart.json"
            marker.write_text(json.dumps({
                "status": "updated",
                "from_version": __version__,
                "to_version": result.latest_version,
                "updated_at": time.time(),
                "package_sha256": package_hash,
            }, indent=2), encoding="utf-8")
            return {"status": "updated", "restart_required": True, "package_sha256": package_hash, **result.as_dict()}
        except Exception:
            self.logger.exception("Update failed. Attempting rollback.")
            self.rollback()
            raise

    def rollback(self) -> dict[str, Any]:
        root = self._project_root()
        if not self.backup_path.exists():
            return {"status": "no_backup"}
        for item in self.backup_path.iterdir():
            target = root / item.name
            if target.exists():
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            if item.is_dir():
                shutil.copytree(item, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            else:
                shutil.copy2(item, target)
        return {"status": "rolled_back", "restart_required": True}
