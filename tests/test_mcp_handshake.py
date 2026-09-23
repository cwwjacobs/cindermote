from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from cindermote.mote.detonate import detonate


SERVER = r'''import json
import sys

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "minimal-test", "version": "1.0"},
        }
    elif method == "tools/list":
        result = {
            "tools": [
                {
                    "name": "echo",
                    "description": "Return a bounded value.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"arg1": {"type": "string"}, "path": {"type": "string"}},
                    },
                }
            ]
        }
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "ok"}], "isError": False}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": request.get("id"), "result": result}), flush=True)
'''


def run() -> dict:
    with TemporaryDirectory(prefix="cindermote-test-") as directory:
        artifact = Path(directory) / "server.py"
        artifact.write_text(SERVER, encoding="utf-8")
        receipt = detonate(artifact, "mcp-server", submitted_by="self-test")
    protocol = receipt["mcp_protocol"]
    assert receipt["identity"]["artifact_type"] == "mcp-server"
    assert protocol["initialize_completed"] is True
    assert protocol["tools_list_completed"] is True
    assert protocol["tools_called"] == ["echo"]
    assert protocol["errors"] == []
    return receipt
