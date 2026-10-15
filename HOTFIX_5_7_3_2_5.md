# MAGI 5.7.3.2.5 — DHCP localization hotfix

Base: complete 5.7.3.2.4 delivery. Only `runner/magi_runner/executors/windows_dhcp_inventory.py` is changed.

- Remote inventory checks `pt-BR/DhcpServerMigration.psd1` and `en-US/DhcpServerMigration.psd1`.
- When pt-BR is missing and en-US exists, the remote PowerShell thread temporarily selects en-US UI culture during module import, restoring the previous culture in `finally`.
- A warning records the fallback. No Windows system file is copied or modified.
- Existing CLIXML/stdout/stderr, TrustedHosts restoration, WinRM, DHCP inventory and Campaign are retained.

Caveat: the internal DHCP module may import localized data after module import. A real Windows Server/WinRM integration test is required to confirm the fallback eliminates the localized warning. Valid inventory accompanied by that known warning remains accepted.

Run on a configured development environment: `python -m pytest runner/tests/test_windows_dhcp_* -q` (from repository root with `runner` on PYTHONPATH).
