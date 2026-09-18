# MAGI 5.6.0 Hotfix 2

## Host Name Resolution Pipeline

- Keeps DNS/PTR as the first discovery enrichment.
- Service Discovery now performs bounded Windows name enrichment when TCP 139/445 is open.
- Windows Runner tries `nbtstat -A <ip>` first (5 s timeout).
- If unresolved, Nmap runs `smb-os-discovery` against 139/445 with an 8 s script timeout and 12 s process timeout.
- Name enrichment is best-effort and never changes a successful Service Discovery into a failure.
- Backend persists hostname/FQDN learned through NetBIOS/SMB only when the asset does not already have a hostname.
- Asset Identity identifiers receive the new hostname/FQDN with source/confidence metadata.
- Credential Engine remains independent: WMI/WinRM authentication failures are preserved and do not erase network-derived identity.
- Runner version: 2.18.5.
