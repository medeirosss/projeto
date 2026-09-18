# MAGI 5.6.0 Hotfix 1

Discovery reliability hotfix. Runner 2.18.4.

- Persists `nmap.xml` immediately after Nmap exits, before DNS enrichment.
- Bounds Windows/system PTR fallback so `socket.gethostbyaddr()` cannot hold a discovery job indefinitely.
- Adds a total DNS enrichment budget (default 30 seconds, maximum 60 seconds).
- DNS timeout/budget exhaustion is non-fatal: the host remains discovered without a DNS name.
- Adds Runner progress logs for Discovery start, Nmap start/completion, DNS progress, and Discovery completion.
- Discovery duration now includes post-Nmap enrichment.
- No database migration and no backend schema change.
