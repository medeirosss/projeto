# Test Plan — MAGI Build 5.0

## 1. Smoke test
1. Subir backend e banco.
2. Confirmar `/api/attack-simulator/summary`.
3. Confirmar que o catálogo contém 13 simulações.
4. Confirmar que o Runner aparece online.

## 2. Runner
1. Atualizar `settings.json` e confirmar `attack_simulation` em `allowed_executors`.
2. Executar `python -m pytest runner/tests/test_attack_simulation.py -q`.
3. Validar geração de `stdout.txt`, `metadata.json`, `evidence.json` e ZIP do job.

## 3. Endpoint / Lateral Movement Surface
- RDP 3389: host com RDP ativo e outro sem RDP.
- WinRM 5985/5986: host com e sem listener.
- SMB 445: host com e sem acesso de rede.

Esperado: `detected` quando a superfície responder; `not_detected` quando não responder. Nenhuma sessão autenticada deve ser criada.

## 4. Active Directory
Executar LDAP/LDAPS/Kerberos contra um DC de homologação e contra um host que não seja DC.
Esperado: evidência de conectividade apenas; nenhuma enumeração de objetos ou solicitação de ticket.

## 5. Network Node
Executar SSH/Telnet contra equipamento de homologação.
Esperado: banner quando disponível, sem tentativa de login.

## 6. Application
Executar HTTP/HTTPS canary contra uma aplicação de homologação.
Validar nos logs de proxy/WAF/aplicação a presença de:
- `User-Agent: MAGI-Attack-Simulator/5.0`
- `X-MAGI-Simulation: benign-control-validation`
- rota `/magi-attack-simulation`

## 7. Regressão
Executar os testes existentes do Runner, especialmente security_check, reachability e Nuclei. A Build 5.0 não deve alterar a semântica da Build 4.2.
