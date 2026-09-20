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

## 5.6.3 — Asset Intelligence, Attack Knowledge and Correlation
- 5.6.2.2 remains the Scan Engine V2 stable baseline.
- Attack Knowledge and executable Simulation are separate concepts. Knowledge may include SAFE/LOW/MEDIUM/HIGH; executable simulations remain controlled SAFE/LOW.
- Knowledge snapshot `2026.09.002` is cumulative and expands the contextual attack catalog. Knowledge updates never install executable Runner code.
- Attack Simulator adds **Correlation**: select a known Asset, review only executable techniques justified by observed services/exposures, select by checkbox and queue independent executions with individual logs/evidence.
- **Attack** remains the free/manual single-target mode. **Campaign** remains controlled path/lateral exploration.
- Web is a first-class manually registered Asset type (`WEB-*`). Web identity is URL-oriented (scheme + hostname + port + base path); resolved IPs are observations and never define identity. Web Scan Now keeps historical observations and performs DNS, HTTP status/redirect/header/fingerprint collection.
- Network Node enrichment continues to use SNMP as read-only discovery/inventory; SNMP SET is outside this build.

## 5.6.3.1 — Web Asset Correlation integration
- Correlation target selector now merges discovered network assets (`TGT-*`) and persistent Web Assets (`WEB-*`).
- Web Assets keep URL identity; resolved IP is not used as the correlation identity.
- Web correlation proposes only installed Application simulations compatible with the observed HTTP/HTTPS scheme and a reachable Web Asset.
- Correlation execution sends the original/normalized URL to the existing Application execution pipeline, preserving Runner DNS resolution and VHOST behavior.
- Each selected Web simulation remains an independent execution with its own History/log/evidence.
- Host correlation behavior from 5.6.3 is unchanged.

## Build 5.6.4 — Validation Intelligence / Correlation credential policy

- Baseline: 5.6.3.1 frozen.
- Correlation now exposes credential requirement per simulation: NONE / OPTIONAL / REQUIRED.
- Zero-Credential Guarantee: a technique marked NONE never receives `credential_id`, even if the asset has a previously confirmed credential.
- Credential lookup is performed only for REQUIRED techniques. OPTIONAL is reserved for explicit technique semantics; it is not auto-filled by Correlation.
- Correlation UI shows Credential and Evidence capability columns.
- Added `Criar Evidência MAGI no alvo quando suportado` to Correlation.
- Remote evidence is capability-gated (`SUPPORTED` / `NOT_SUPPORTED`); requesting evidence cannot turn a read-only technique into a write operation.
- Initial remote evidence support is limited to authenticated native SMB and WinRM access validation. Other simulations retain durable MAGI logs/evidence only.
- Correlation evidence paths are technique-specific under `C:\MAGI\Evidence\<Asset ID>\<Technique>.txt`.
- Runner 2.18.6.
