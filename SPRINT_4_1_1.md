# MAGI Sprint 4.1.1

Correções de estabilização da Sprint 4.1:
- provisionamento Nuclei movido para antes do Doctor;
- release do Nuclei resolvida dinamicamente pelo repositório oficial;
- health/capability do Nuclei Engine e templates no Doctor;
- executor registra todos os caminhos pesquisados quando o engine está ausente;
- `executed_real_test=false` quando engine/template não existe;
- polling Runner↔Backend recupera de ConnectionError/RemoteDisconnected com nova sessão e backoff;
- Atomic Red Team permanece congelado.
