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

The active codebase must not contain `Motefield`, `motefield`, or `MOTEFIELD_` except in the three provenance/migration documents listed above.