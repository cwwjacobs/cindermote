# Provenance

Cindermote is the successor product and repository identity to **Motefield**.

## Upstream

Motefield was an earlier private project by the same author. Its source is not
public. Cindermote was forked from Motefield commit
`584ab11ea054efb233d057b64c342846ed201592`, which is the value recorded in
Ash Receipt `provenance` fields.

## Lineage

Motefield was the original sandbox/detonation system providing:

- Firecracker microVM admission with fail-closed launch behavior
- Read-only runtime assets
- Cleanup proof and receipt authentication
- Explicit gate decisions
- Host-supported KVM verification
- agent-probe v0 (LLM agent execution inside Firecracker)
- browser-probe (passive Chromium/CDP inspection)
- Cinder Incident Gate (attack chain containment probes)
- Privilege-separated host egress proxy
- Legacy namespace isolation (chroot + seccomp + ptrace + cgroups)

Cindermote inherits and hardens this foundation under the Ultra Kernel-Spine-Ledger (U-KSL) framework.

## Rename scope

The Phase 0 rename covers:

- Product name: Motefield → Cindermote
- CLI binary: `motefield` → `cindermote`
- Python package: `motefield` → `cindermote`
- Environment variables: `MOTEFIELD_*` → `CINDERMOTE_*`
- Runtime state directory: `.motefield` → `.cindermote`
- Receipts terminology: Motefield receipts → Cindermote Ash Receipts
- Browser-probe naming: profile-specific Cindermote naming

The old name is preserved only in this provenance document, migration notes, and upstream attribution.