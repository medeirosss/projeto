from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from app.config import SCRIPTS_DIR
from app.repositories.playbooks_repository import (
    disable_playbook_by_name,
    get_playbook_by_name,
    list_playbooks,
    save_playbook,
)

ALLOWED_EXTENSIONS = {'.ps1', '.sh'}
META_PREFIX = '@centric-'
RUNTIME_DIR = SCRIPTS_DIR / '.runtime'


def _safe_name(name: str) -> str:
    clean = Path(str(name or '')).name.strip()
    if not clean:
        raise ValueError('Nome de script inválido.')
    if Path(clean).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise ValueError('Somente arquivos .ps1 e .sh são suportados.')
    return clean


def parse_script_metadata_content(content: str, fallback_name: str = '') -> Dict[str, Any]:
    required: List[str] = []
    optional: List[str] = []
    metadata: Dict[str, Any] = {
        'name': Path(fallback_name).stem if fallback_name else '',
        'required': required,
        'optional': optional,
        'credential': '',
        'description': '',
    }
    for raw in str(content or '').splitlines()[:40]:
        line = raw.strip().lstrip('#').strip()
        if not line.startswith(META_PREFIX):
            continue
        key, _, value = line.partition(':')
        key = key.replace(META_PREFIX, '').strip().lower()
        value = value.strip()
        if key in {'required', 'optional'}:
            metadata[key] = [part.strip() for part in value.split(',') if part.strip()]
        elif key in {'name', 'credential', 'description'}:
            metadata[key] = value
    if not metadata.get('name'):
        metadata['name'] = Path(fallback_name).stem if fallback_name else 'Playbook'
    return metadata


def parse_script_metadata(path: Path) -> Dict[str, Any]:
    try:
        return parse_script_metadata_content(path.read_text(encoding='utf-8', errors='ignore'), path.name)
    except Exception:
        return parse_script_metadata_content('', path.name)


def list_scripts() -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for item in list_playbooks():
        metadata = item.get('metadata') or {}
        items.append({
            'id': item.get('id'),
            'name': item.get('name') or '',
            'extension': item.get('script_type') or item.get('extension') or '',
            'size': 0,
            'updated_at': item.get('updated_at') or '',
            'metadata': metadata,
        })
    return items


def save_script_from_upload(filename: str, content: str) -> Dict[str, Any]:
    name = _safe_name(filename)
    metadata = parse_script_metadata_content(content, name)
    description = str(metadata.get('description') or '')
    required = metadata.get('required') or []
    return save_playbook({
        'name': name,
        'description': description,
        'script_type': Path(name).suffix.lower(),
        'script_content': content,
        'required_variables': required,
        'metadata': metadata,
    })


def delete_script(script_name: str) -> bool:
    try:
        name = _safe_name(script_name)
    except Exception:
        return False
    return disable_playbook_by_name(name)


def materialize_script(script_name: str) -> Path:
    name = _safe_name(script_name)
    playbook = get_playbook_by_name(name, include_content=True)
    if not playbook:
        raise FileNotFoundError('Script não encontrado no banco.')
    content = str(playbook.get('script_content') or '')
    if not content.strip():
        raise FileNotFoundError('Script sem conteúdo cadastrado.')
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    runtime_name = re.sub(r'[^A-Za-z0-9_.-]+', '_', name)
    path = (RUNTIME_DIR / runtime_name).resolve()
    if path.parent != RUNTIME_DIR.resolve():
        raise ValueError('Nome de script inválido.')
    path.write_text(content, encoding='utf-8')
    if path.suffix.lower() == '.sh':
        path.chmod(0o700)
    return path
