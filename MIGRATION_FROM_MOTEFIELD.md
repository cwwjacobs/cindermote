# Migration from Motefield

## What changed

Cindermote is the renamed successor to Motefield. All active product surfaces use the new name:

| Old | New |
|-----|-----|
| `motefield` CLI | `cindermote` CLI |
| `motefield` Python package | `cindermote` Python package |
| `MOTEFIELD_*` environment variables | `CINDERMOTE_*` |
| `.motefield/` runtime state | `.cindermote/` |
| `Motefield` product name | `Cindermote` |
| `motefield-vmm` user/group | `cindermote-vmm` |
| `motefield-proxy` user/group | `cindermote-proxy` |
| `/run/motefield` runtime root | `/run/cindermote` |
| `motefield-hotcell-v1.3` policy | `cindermote-hotcell-v1.3` |
| `motefield.*` protocol versions | `cindermote.*` |

## What was preserved

The old name remains only in:

- `PROVENANCE.md` — upstream attribution
- `MIGRATION_FROM_MOTEFIELD.md` — this document
- `NAMING.md` — naming convention reference
- Legacy compatibility shims (none currently required)

## Intentional remaining occurrences

The following `motefield` references are intentionally preserved in the active codebase:

1. **`guest/motefield-init`** → renamed to `guest/cindermote-init`, but the reference in the guest rootfs build receipt sources table is updated to match.
2. **`mote/namespace_setup.sh`** — kept as `mote/namespace_setup.sh` (no rename needed).
3. **`mote/seccomp_filter.bpf`** — kept as `mote/seccomp_filter.bpf` (no rename needed).

All other occurrences are active product renames.