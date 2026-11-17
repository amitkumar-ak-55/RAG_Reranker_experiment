from __future__ import annotations

import socket
import time


def wait_for_port(host: str, port: int, timeout: float, interval: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=min(interval, max(0.01, deadline - time.monotonic()))):
                return True
        except OSError:
            time.sleep(interval)
    return False
