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

## 5.6.2.1 — Scan Engine V2 integration/UX
- Asset list counters now read persisted Attack Exposure and executable Simulation mappings.
- Asset Simulation panel can execute a mapped technique contextually and display sanitized persistent execution logs/evidence.
- Scan form replaces multi-select credentials with an explicit checkbox list and separates exclusions into their own managed panel.
- Asset list exposes Last Scan / rescan status; Scan Now immediately refreshes the row and preserves identity-first semantics.

## 5.6.2.2 — Asset Simulation Credential Reuse
- Contextual simulations launched from an Asset reuse a credential already confirmed on that exact Asset.
- Credential selection is protocol-aware: Windows for SMB/WinRM/Kerberos, SNMP for SNMP, SSH/Linux for SSH.
- Only `credential_id` is persisted in jobs; the current secret is injected transiently from Credential Store when Runner pulls the job.
- All `magi_attack` repository tasks use the `attack_simulation` job lifecycle even when the concrete Runner executor is `credential_validate`.
- This fixes contextual SMB/WinRM/SNMP/SSH simulations being incorrectly scheduled as `security_check`, which prevented transient credential injection.
