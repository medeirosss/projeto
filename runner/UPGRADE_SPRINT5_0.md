# Upgrade — MAGI 4.2 -> 5.0

1. Fazer backup do banco e do `settings.json` do Runner.
2. Atualizar backend/frontend/runner com o pacote 5.0.
3. Reiniciar backend para sincronizar o repositório `magi_attack`.
4. No Runner existente, não é obrigatório editar manualmente `allowed_executors`: ao carregar uma configuração que já contenha `nuclei`, a migração forward-compatible adiciona `attack_simulation` automaticamente.
5. Reiniciar o Runner.
6. Abrir `/attack-simulator` e executar primeiro **Planejar**.
7. Fazer a primeira execução em ambiente de homologação.

Nenhuma migração destrutiva de banco foi adicionada na Build 5.0. O módulo reutiliza as tabelas de catálogo e histórico do Validation Engine.
