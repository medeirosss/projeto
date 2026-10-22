# MAGI 5.7.3.2.4 — Windows DHCP inventory hotfix

- Normaliza stdout/stderr do PowerShell, incluindo envelopes CLIXML e escapes `_xNNNN_`.
- Extrai o JSON do inventário sem confundir mensagens informativas com dados.
- Trata diagnóstico de `DhcpServerMigration.psd1` como warning **somente se** o processo e o JSON do inventário forem bem-sucedidos. Erros reais de WinRM, autenticação, timeout ou ausência de cmdlets permanecem fatais.
- Mantém script WinRM, adição temporária/restauração de TrustedHosts, integração DHCP e Campaign inalterados.
- Testes automatizados em `runner/tests/test_windows_dhcp_streams_57324.py`.

**Validação adicional necessária:** teste de ponta a ponta em Windows com DHCP Server/RSAT e credenciais reais; o ambiente de empacotamento não oferece WinRM.
