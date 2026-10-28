# MAGI 6.2.2 — Campaign Diagnostics & UI Refinement

- Campaign details are displayed in a standalone view within the Campaign module, with a deep-link hash (`#campaign/<uuid>`). The list and creator are hidden while details are open; close restores the list.
- Evidence classification uses actual result/reason fields. DISCOVERY is no longer automatically labeled confirmed.
- Hosts known in coverage but not reached are listed as such, without inventing protocol-level failures.
- Technical evidence and Runner Job identifiers remain accessible.
- Global dark canvas is black (`#000000`), without changing card/accent tokens.

## Limits
- No Runner/backend changes; if protocol-specific error telemetry was not recorded, the UI explicitly says it is unavailable.
- Test in Docker with a completed Campaign, DHCP snapshot, and a failed discovery event.
