# MAGI Build Notes

## 5.6.2 — Scan Engine V2 + Attack Exposure

Baseline: 5.6.1.

### Architecture
- Scan profiles support multiple Credential Store references with priority; secrets are never copied into scans/assets/history.
- Credential rotation is centralized: editing a stored credential affects all scans/assets that reference its ID.
- Windows domain/local, SNMP and future SSH credentials share the same routing model.
- Scan exclusions support individual IP, CIDR and range and are sent to Nmap before discovery.
- Asset/Scan N:N relation keeps last successful credential/method for fast reuse.
- `Scan Now` is identity-first: hostname/FQDN before last IP; IP alone can never rebind/overwrite a TGT asset.
- Attack Exposure correlates services/findings/credentials with the cumulative Attack Knowledge snapshot.
- `Ataques` may include SAFE/LOW/MEDIUM/HIGH informational knowledge; `Simulações` only contains executable mapped techniques.
- Network inventory schema is prepared for read-only SNMP enrichment (`sysName`, `sysDescr`, `sysObjectID`, vendor/model/firmware).

### Safety invariants
- No HIGH technique is executed by Attack Exposure.
- Asset identity conflict never overwrites an existing asset.
- Knowledge and execution remain separate layers.
