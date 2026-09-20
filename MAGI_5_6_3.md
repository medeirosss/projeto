# MAGI 5.6.3

Baseline: 5.6.2.2.

## Delivered
- Attack Simulator / Correlation: asset-oriented simulation plan, checkbox multi-select and independent queued executions.
- Web Assets: manual WEB-* identity, URL normalization, DNS/HTTP discovery, redirects/headers/fingerprint, Scan Now and history persistence.
- Attack Knowledge cumulative snapshot 2026.09.002 with broader Endpoint, AD, Network Node and Application knowledge. Informational HIGH entries never become executable merely by existing in Knowledge.
- Existing SNMP read-only Network Node discovery/simulation remains integrated with Asset correlation; no SNMP SET.
- Existing Attack remains free/manual; Campaign behavior is unchanged.

## Safety / semantics
Attack Knowledge != applicability != execution. Correlation only exposes techniques that have an executable mapping and observed asset preconditions. Batch execution creates independent jobs/logs/evidence.
