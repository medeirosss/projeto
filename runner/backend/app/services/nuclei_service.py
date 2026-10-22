from __future__ import annotations
from typing import Any

PROFILES=[
    {
        "task_key":"NUCLEI-CVE-HTTP","name":"CVE HTTP/HTTPS","description":"Valida CVEs aplicáveis a serviços HTTP/HTTPS usando o runtime Nuclei homologado do MAGI.",
        "category":"CVE Validation","platform":"Web","impact":"low","profile_name":"CVE HTTP/HTTPS",
        "template":"http/cves/","protocol":"http","ports":[80,443,8080,8443],"tags":["http","cve"],"severity":"medium,high,critical",
    },
    {
        "task_key":"NUCLEI-CVE-NETWORK","name":"CVE de serviços de rede","description":"Valida CVEs de protocolos e serviços de rede suportados pelos templates Nuclei.",
        "category":"CVE Validation","platform":"Network","impact":"low","profile_name":"CVE Network",
        "template":"network/cves/","protocol":"network","ports":[21,22,23,25,53,110,135,139,143,389,445,465,587,636,993,995,1433,3306,3389,5432,5985,5986],"tags":["network","cve"],"severity":"medium,high,critical",
    },
    {
        "task_key":"NUCLEI-HTTP-EXPOSED-PANELS","name":"Painéis HTTP expostos","description":"Procura painéis de administração e consoles HTTP conhecidos acessíveis pelo alvo.",
        "category":"Web Exposure","platform":"Web","impact":"low","profile_name":"Painéis HTTP expostos",
        "template":"http/exposed-panels/","protocol":"http","ports":[80,443,8080,8443],"tags":["http","panel","exposure"],"severity":"info,low,medium,high,critical",
    },
    {
        "task_key":"NUCLEI-HTTP-MISCONFIG","name":"Misconfiguration HTTP","description":"Valida configurações HTTP inseguras suportadas pelo catálogo homologado.",
        "category":"Web Misconfiguration","platform":"Web","impact":"low","profile_name":"Misconfiguration HTTP",
        "template":"http/misconfiguration/","protocol":"http","ports":[80,443,8080,8443],"tags":["http","misconfig"],"severity":"low,medium,high,critical",
    },
    {
        "task_key":"NUCLEI-TECH-DETECT","name":"Detecção de tecnologia Web","description":"Identifica tecnologias Web para melhorar a seleção de validações posteriores.",
        "category":"Technology Discovery","platform":"Web","impact":"low","profile_name":"Technology Detection",
        "template":"http/technologies/","protocol":"http","ports":[80,443,8080,8443],"tags":["http","tech"],"severity":"info,low,medium,high,critical",
    },
]

def as_validation_tasks()->list[dict[str,Any]]:
    rows=[]
    for item in PROFILES:
        meta={k:item[k] for k in ("template","protocol","ports","tags","severity","profile_name")}
        rows.append({
            "repository_key":"nuclei","task_key":item["task_key"],"name":item["name"],
            "description":item["description"],"category":item["category"],"platform":item["platform"],
            "executor":"nuclei","impact":item["impact"],"requires_admin":False,"approved":True,"enabled":True,
            "detection":{"type":"nuclei_profile","template":item["template"],"ports":item["ports"],"protocol":item["protocol"]},
            "remediation":"Revise a evidência confirmada e aplique a correção específica do produto, configuração ou CVE identificado.",
            "references":[],"metadata":meta,
        })
    return rows
