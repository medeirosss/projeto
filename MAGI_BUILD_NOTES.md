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
