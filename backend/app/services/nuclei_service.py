from __future__ import annotations
from typing import Any

# Sprint 4.1 starts with a curated, metadata-only catalog. The Runner owns
# actual template files/binary; backend never downloads or executes Nuclei.
STARTER_TEMPLATES = [
    {
        "task_key": "NUCLEI-HTTP-EXPOSED-PANELS",
        "name": "HTTP exposed panels",
        "description": "Validação Nuclei para painéis HTTP conhecidos/expostos.",
        "category": "Web Exposure", "platform": "Web", "impact": "low",
        "template": "http/exposed-panels/", "protocol": "http",
        "ports": [80, 443, 8080, 8443], "tags": ["http", "panel", "exposure"],
        "severity": "info,low,medium,high,critical",
    },
    {
        "task_key": "NUCLEI-HTTP-MISCONFIG",
        "name": "HTTP misconfiguration",
        "description": "Validação de configurações HTTP inseguras suportadas pelos templates locais do Runner.",
        "category": "Web Misconfiguration", "platform": "Web", "impact": "low",
        "template": "http/misconfiguration/", "protocol": "http",
        "ports": [80, 443, 8080, 8443], "tags": ["http", "misconfig"],
        "severity": "low,medium,high,critical",
    },
    {
        "task_key": "NUCLEI-CVE-HTTP",
        "name": "HTTP CVE validation",
        "description": "Validação orientada a CVE para serviços HTTP/HTTPS usando templates CVE instalados no Runner.",
        "category": "CVE Validation", "platform": "Web", "impact": "low",
        "template": "http/cves/", "protocol": "http",
        "ports": [80, 443, 8080, 8443], "tags": ["http", "cve"],
        "severity": "medium,high,critical",
    },
]

def as_validation_tasks() -> list[dict[str, Any]]:
    rows=[]
    for item in STARTER_TEMPLATES:
        meta={k:item[k] for k in ("template","protocol","ports","tags","severity")}
        rows.append({
            "repository_key":"nuclei", "task_key":item["task_key"], "name":item["name"],
            "description":item["description"], "category":item["category"], "platform":item["platform"],
            "executor":"nuclei", "impact":item["impact"], "requires_admin":False,
            "approved":True, "enabled":True,
            "detection":{"type":"nuclei_template","template":item["template"],"ports":item["ports"],"protocol":item["protocol"]},
            "remediation":"Revise a evidência retornada pelo template e aplique a correção específica do produto/CVE confirmado.",
            "references":[], "metadata":meta,
        })
    return rows
