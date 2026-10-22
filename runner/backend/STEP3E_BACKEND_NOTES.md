# Backend - Ajustes necessários para 3E

Para execução real, criar runner_job com payload completo.

## Payload execute_lab

```json
{
  "mode": "execute_lab",
  "technique_id": "T1033",
  "atomic_test_number": 1,
  "executor_name": "powershell",
  "risk_level": "low",
  "approved_for_execution": true,
  "approved_for_lab": true,
  "allow_real_execution": true,
  "requires_reboot": false,
  "requires_admin": false,
  "approved_by": "admin",
  "approved_at": "2026-05-31T00:00:00Z"
}
```

## Regra obrigatória no backend

Antes de criar job `execute_lab`, validar:

```text
current_user.role == admin
atomic_tests.approved_for_execution = true
atomic_tests.approved_for_lab = true
atomic_tests.risk_level = low
atomic_tests.requires_reboot = false
atomic_tests.executor_name = powershell
```

O Runner também revalida como defesa em profundidade.