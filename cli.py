#!/usr/bin/env python3
"""Cindermote Command Line Interface (CLI) Entrypoint."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from cindermote import __version__  # noqa: E402

LEGACY_DEPRECATION_NOTICE = (
    "DEPRECATED: the legacy namespace profile shares the host kernel and is not a "
    "microVM boundary. Use 'cindermote detonate <skill.md> agent-probe' for "
    "Firecracker isolation. See docs/legacy-deprecation.md."
)


def main(args: list[str] | None = None) -> int:
    if args is None:
        args = sys.argv[1:]

    if not args:
        print(f"Cindermote {__version__}")
        print("Usage:")
        print("  cindermote incident-gate run [--case CASE] [--receipt-dir PATH]")
        print("  cindermote incident-gate doctor [--strict]")
        print("  cindermote detonate <artifact> agent-probe        (Firecracker)")
        print("  cindermote detonate <artifact> <legacy-type>      (deprecated)")
        print("  cindermote kernel-laws")
        print("  cindermote --version")
        return 1

    if args[0] in {"--version", "-V", "version"}:
        print(f"Cindermote {__version__}")
        return 0

    cmd = args[0]
    if cmd == "incident-gate":
        from cindermote.incident_gate import main as incident_gate_main
        return incident_gate_main(args[1:])
    elif cmd == "detonate":
        if len(args) < 3:
            print("Usage: cindermote detonate <artifact-path> <artifact-type>")
            return 1
        if args[2] == "agent-probe":
            from cindermote.agent_probe.contract import ModelConfig
            from cindermote.agent_probe.runner import run_agent_probe

            fd_text = os.environ.get("CINDERMOTE_AGENT_PROBE_API_KEY_FD", "")
            endpoint = os.environ.get("CINDERMOTE_AGENT_PROBE_ENDPOINT", "")
            model_id = os.environ.get("CINDERMOTE_AGENT_PROBE_MODEL", "")
            if not fd_text.isdigit() or not endpoint or not model_id:
                print(
                    "agent-probe requires CINDERMOTE_AGENT_PROBE_API_KEY_FD, "
                    "CINDERMOTE_AGENT_PROBE_ENDPOINT, and CINDERMOTE_AGENT_PROBE_MODEL",
                    file=sys.stderr,
                )
                return 3
            descriptor = int(fd_text)
            try:
                credential = bytearray(os.read(descriptor, 4097))
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if len(credential) > 4096:
                for index in range(len(credential)):
                    credential[index] = 0
                print("agent-probe API credential exceeds 4096 bytes", file=sys.stderr)
                return 3
            result = run_agent_probe(
                args[1],
                model=ModelConfig("openai-compatible", model_id, endpoint),
                api_key=credential,
            )
            print(json.dumps(result.envelope, indent=2, sort_keys=True))
            return result.exit_code

        from cindermote.mote.detonate import detonate

        if args[2] != "browser-probe":
            print(LEGACY_DEPRECATION_NOTICE, file=sys.stderr)
        receipt = detonate(args[1], args[2])
        print(json.dumps(receipt, indent=2, sort_keys=True))
        gate = receipt.get("gate", {}) if isinstance(receipt, dict) else {}
        purge = receipt.get("purge", {}) if isinstance(receipt, dict) else {}
        if purge.get("verified_externally") is not True:
            return 6
        return 0 if gate.get("final_decision") == "ALLOW" else 2
    elif cmd == "kernel-laws":
        from kernel_laws import run_kernel_law_checks
        laws = run_kernel_law_checks()
        if laws.valid:
            checked = ", ".join(f"{count} {name}" for name, count in laws.summary.items())
            print(f"Kernel Laws Verification: PASS (0 errors; checked {checked})")
            return 0
        else:
            print(f"Kernel Laws Verification: FAIL ({len(laws.errors)} errors)")
            for err in laws.errors:
                print(f"  - {err}")
            return 1
    elif cmd == "spine":
        from cindermote_api import CindermoteService
        service = CindermoteService()
        subcmd = args[1] if len(args) > 1 else ""
        if subcmd == "detonation":
            payload = {"target": {"id": "cli-target"}, "raw_manifest": {}}
            res = service.create_detonation(payload)
            print(json.dumps(res, indent=2))
            return 3
        else:
            print("Usage: cindermote spine detonation")
            return 1
    else:
        print(f"Unknown subcommand: {cmd}")
        print("Available subcommands: incident-gate, detonate, kernel-laws, spine")
        return 1



if __name__ == "__main__":
    sys.exit(main())
