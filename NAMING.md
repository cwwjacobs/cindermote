# Naming

## Active product identity

All active surfaces use **Cindermote**:

| Surface | Form |
|---------|------|
| Product name | Cindermote |
| CLI binary | `cindermote` |
| Python package | `cindermote` |
| Python module prefix | `cindermote.*` |
| Environment variable prefix | `CINDERMOTE_` |
| Runtime state directory | `.cindermote/` |
| Runtime root | `/run/cindermote` |
| Cgroup root | `/sys/fs/cgroup/cindermote` |
| VMM user/group | `cindermote-vmm` |
| Proxy user/group | `cindermote-proxy` |
| Policy version | `cindermote-hotcell-v1.3` |
| Protocol version prefix | `cindermote.*` |
| Receipts terminology | Cindermote Ash Receipts |

## Historical identity

The predecessor name **Motefield** is preserved only in:

- `PROVENANCE.md` — upstream attribution
- `MIGRATION_FROM_MOTEFIELD.md` — migration record
- This document (`NAMING.md`) — naming reference

## Capitalization rules

- Product name: **Cindermote** (title case)
- CLI/package/directory: **cindermote** (lowercase)
- Environment variables: **CINDERMOTE_** (uppercase, underscore-suffixed)
- Protocol versions: **cindermote.** (lowercase, dot-suffixed)

## No mixed branding

Code and configuration (`.py`, `.sh`, `.json`, `.js`, `.html`, `.css`, `.yml`, `.yaml`, `.toml`, `.cfg`, `.ini` files and Containerfiles) must not contain `Motefield`, `motefield`, or `MOTEFIELD_` in any case. Prose may use the name only in the three documents listed above, and in README, VALIDATION and CHANGELOG where they link to them. `tests/test_vertical_spine.py` (`test_12`) enforces the code and configuration rule.

Two short identifiers from the predecessor remain in runtime resource names: job ids `mf-run-<8 hex>` (legacy runner) and `mf-web-<8 hex>` (Firecracker runtime). They are matched by exact patterns in cleanup logic, so renaming them is a coordinated change, not a text replace.