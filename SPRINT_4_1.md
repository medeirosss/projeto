# MAGI Sprint 4.1 — Nuclei Integration + Deep Validation

## Implementado
- Executor `nuclei` no Runner.
- Nuclei permanece executado pelo Runner, nunca pelo backend.
- Catálogo Nuclei inicial controlado pelo MAGI.
- Repositório Nuclei passa a `available=true`.
- Tarefas podem ser filtradas entre MAGI Checks e Nuclei Validations.
- Saída JSONL do Nuclei é normalizada em evidence/finding.
- Sem match: `success / not_detected`.
- Com match: `success / detected`.
- Binário ausente: `failed / not_evaluated`.
- Atomic Red Team permanece congelado/pós-ataque.

## Instalação do Runner
O Runner deve possuir `nuclei.exe` no PATH ou em:
`C:\Program Files\Magi\Runner\tools\nuclei.exe`

Os templates são responsabilidade do Runner. O backend armazena apenas catálogo/metadata e não baixa payloads.
