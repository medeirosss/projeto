# Sistema Magi - Motor CVE v1.1

Arquivos alterados:

- backend/app/data/cve_intelligence.json
- backend/app/services/cve_intelligence_service.py
- backend/app/routers/cve_intelligence.py
- backend/app/services/dashboard_service.py
- backend/app/services/scanner_service.py
- backend/main.py
- frontend/home.html
- frontend/home.js
- frontend/style.css

Mudança principal:

O motor não retorna mais apenas `patch_urgent`. Ele separa:

- defesa imediata: contenção, restrição de serviço, monitoramento, isolamento se exposto;
- remediação: aplicar patch, aguardar vendor, agendar correção.

Sinais usados:

- exploit disponível;
- patch disponível;
- CVSS;
- tipo provável de exploração;
- quantidade de sistemas afetados.

Após copiar:

```powershell
git add backend/app/data/cve_intelligence.json backend/app/services/cve_intelligence_service.py backend/app/routers/cve_intelligence.py backend/app/services/dashboard_service.py backend/app/services/scanner_service.py backend/main.py frontend/home.html frontend/home.js frontend/style.css
git commit -m "Add CVE engine v1.1 defense decision model"
git push
git tag v1.0.14
git push origin v1.0.14
```
