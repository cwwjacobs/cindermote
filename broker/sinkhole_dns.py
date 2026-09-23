"""Minimal loopback-only DNS sinkhole used by a Cindermote namespace."""

from __future__ import annotations

import socket
import sys


def _sinkhole_response(query: bytes) -> bytes:
    if len(query) < 12:
        return b""
    # Preserve the transaction ID and question. Return NOERROR with no answers.
    flags = b"\x81\x80"
    counts = query[4:6] + b"\x00\x00\x00\x00\x00\x00"
    return query[:2] + flags + counts + query[12:]


def serve_forever(host: str = "127.0.0.1", port: int = 5353) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((host, port))
        while True:
            payload, address = server.recvfrom(4096)
            response = _sinkhole_response(payload)
            if response:
                server.sendto(response, address)


if __name__ == "__main__":
    try:
        serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
