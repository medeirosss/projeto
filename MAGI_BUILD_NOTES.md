# MAGI Build Notes

## 5.6.0 — Asset Identity & Historical Foundation

Base: 5.5.3. No Attack Knowledge behavior is introduced in this build.

- `target_uuid` is the stable public Asset ID; `targets.id` remains the internal FK.
- Added deterministic Asset Identity Resolver. IP-only continuity is `MATCH_PROBABLE` (35), never confirmed identity.
- Strong identifier conflicts do not merge histories.
- Added `asset_identifiers` and `asset_identity_events`.
- Deep Inventory contributes hostname, serial number and FQDN identifiers.
- Campaign assets and Validation/Pentest executions can correlate to `target_id` without changing Runner target/IP contracts.
- Added `exposure_finding_occurrences` to preserve reopen/resolution cycles.
- Existing assets/findings are backfilled by Alembic migration 0028.
- Runner remains 2.18.3 because no Runner protocol/executor behavior changed.

## Build 5.6.1 — Attack Knowledge Catalog
- Baseline: 5.6.0 Hotfix 2. Discovery/Asset Identity pipeline remains unchanged.
- Adds versioned local Attack Knowledge separated from executable simulations.
- Attack Knowledge may classify informational attacks as SAFE/LOW/MEDIUM/HIGH. HIGH entries are knowledge only and are not executable MAGI simulations.
- Knowledge Version is a cumulative full snapshot. Updates always jump directly to the latest compatible snapshot; intermediate Knowledge Versions are never prerequisites.
- Software version, Alembic database revision, Knowledge Schema and Knowledge Version are independent concepts.
- Initial bundled snapshot: `2026.09.001`, Knowledge Schema 1, minimum MAGI 5.6.1.
- Stable IDs: `MAGI-KB-*`. Deprecated knowledge is retained for historical references rather than deleted.
- The same transactional importer is the contract for bundled, future online and offline Knowledge updates. Offline packages should write through this importer/database contract, not execute arbitrary SQL.
- Knowledge updates contain data/rules/mappings only; they do not deliver Runner code, scripts, payloads or arbitrary Metasploit execution.
- 5.6.1 provides catalog/version/import foundations. Per-asset automatic Attack Exposure correlation and inventory counters remain 5.6.2 scope.
