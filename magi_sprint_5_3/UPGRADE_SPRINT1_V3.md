# Upgrade — Sprint 1 v3

1. Publique a aplicação e execute as migrations Alembic até `20260726_0015`.
2. Configure no backend:

```env
DISCOVERY_PROVIDER=runner
DISCOVERY_RUNNER_TIMEOUT_SECONDS=180
DISCOVERY_SCHEDULER_INTERVAL_SECONDS=30
```

3. Atualize o Runner Windows usando o conteúdo do diretório `runner/`.
4. No `settings.json`, mantenha `nmap_discovery` em `allowed_executors`.
5. Instale o Nmap manualmente no Windows do Runner.
6. Reinicie o serviço do Runner e execute:

```powershell
python -m magi_runner --config settings.json --doctor
```

7. Aguarde um heartbeat e valide na tela Scan.
