# MAGI Runner — Metasploit Provider 5.5.0

Metasploit Framework is an optional external provider. It is not bundled inside `runner/tools`.

Detection order:
1. `metasploit_path` in Runner settings
2. `MAGI_METASPLOIT_PATH`
3. Windows/POSIX PATH (`msfconsole` / `msfconsole.bat`)
4. known Windows installation paths such as `C:\metasploit-framework\bin\msfconsole.bat`

Initial allowlist:
- MAGI-M-ATK-END-001 -> auxiliary/scanner/smb/smb_version
- MAGI-M-ATK-AD-001 -> auxiliary/scanner/kerberos/kerberos_login
- MAGI-M-ATK-APP-001 -> auxiliary/scanner/http/options
- MAGI-M-ATK-NET-001 -> auxiliary/scanner/snmp/snmp_enum

The provider does not accept arbitrary Metasploit module names from the backend/UI.
Kerberos 5.5.0 validates a single selected credential; it does not run wordlists or brute force.
SNMP 5.5.0 performs enumeration only; it does not run SNMP SET.
