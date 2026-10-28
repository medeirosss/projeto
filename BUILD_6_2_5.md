# MAGI 6.2.5 — Global Theme Consolidation

Scope: frontend-only CSS consolidation based on 6.2.4. Backend, Runner, database, and Campaign execution unchanged.

- Canonical semantic palette defined in frontend/design-system/tokens.css (dark and light).
- Removed duplicate token declarations from magi-design-system.css and magi-global-6.2.4.css, retaining legacy component styles for compatibility.
- Every HTML entrypoint now loads canonical tokens last and a shared surface stylesheet.
- Shared table/card/form surfaces reference semantic tokens, including Reports and Campaign.
- 6.2.4 dropdown portal behavior preserved.

Migration note: legacy CSS rules and hardcoded non-theme semantic colors still exist. This is a compatibility-first consolidation, not a claim of total CSS deduplication. Test visual regressions (including light mode), table hover/selection, Campaign menus and all routes in browser before production rollout.
