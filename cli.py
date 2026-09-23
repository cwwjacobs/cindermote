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


def main(args: list[str] | None = None) -> int:
    if args is None:
        args = sys.argv[1:]

    if not args:
        print("Cindermote CLI v2.0")
        print("Usage:")
        print("  cindermote incident-gate run [--case CASE] [--receipt-dir PATH]")
        print("  cindermote incident-gate doctor")
        print("  cindermote detonate <artifact> <type>")
        return 1

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
        receipt = detonate(args[1], args[2])
        print(json.dumps(receipt, indent=2, sort_keys=True))
        gate = receipt.get("gate", {}) if isinstance(receipt, dict) else {}
        purge = receipt.get("purge", {}) if isinstance(receipt, dict) else {}
        if purge.get("verified_externally") is not True:
            return 6
        return 0 if gate.get("final_decision") == "ALLOW" else 2
    elif cmd == "kernel-laws":
        from kernel_laws import run_kernel_law_checks
        res = run_kernel_law_checks()
        if res.valid:
            print("Kernel Laws Verification: PASS (0 errors)")
            return 0
        else:
            print(f"Kernel Laws Verification: FAIL ({len(res.errors)} errors)")
            for err in res.errors:
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
