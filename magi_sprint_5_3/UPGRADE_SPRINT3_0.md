# Upgrade — Sprint 3.0

## Backend
O container continua aplicando Alembic no startup. O novo head é `20260807_0020`.

## Runner
Substitua os arquivos do Runner pela versão incluída neste pacote. O Runtime adiciona `service_discovery` automaticamente quando um `settings.json` antigo já possui `nmap_discovery`, evitando exigir alteração manual da lista de executores.

A leitura do JSON agora aceita UTF-8 com ou sem BOM. A escrita continua em UTF-8 sem BOM.

Confirme:

```powershell
& "C:\Program Files\Magi\Runner\.venv\Scripts\python.exe" -m magi_runner --version
& "C:\Program Files\Magi\Runner\.venv\Scripts\python.exe" -m magi_runner --config settings.json --doctor
```

Versão esperada: `2.12.0`.

## Nmap
O Magi não instala Nmap no Runner. O Nmap deve continuar instalado pelo administrador.
