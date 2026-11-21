"""Render docs/demo.svg from a real run. Needs `pip install rich` and network access.

Three real public MCP servers (pinned first), plus a local mock server that simulates an
MCP server impersonating another authorization server's issuer.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.text import Text

from mcp_issuer_check import lock
from mcp_issuer_check.cli import _render
from mcp_issuer_check.probe import probe

ROOT = Path(__file__).resolve().parents[1]
REAL = ["https://mcp.notion.com/mcp", "https://api.githubcopilot.com/mcp/", "https://mcp.stripe.com"]
MOCK = "http://127.0.0.1:8799/mcp"

mock = subprocess.Popen(
    [sys.executable, str(ROOT / "tests/mock_mcp.py"), "8799", "https://login.example.com"], stdout=subprocess.DEVNULL
)
try:
    time.sleep(1.5)
    pins = {"version": 1, "servers": {}}
    lock.pin([probe(u.split("/")[2], u, "--url") for u in REAL], pins)
    results = [probe(u.split("/")[2], u, "--url") for u in REAL + [MOCK]]
    lock.compare(results, pins)
finally:
    mock.terminate()

console = Console(record=True, width=118, file=open(os.devnull, "w"))
console.print("$ mcp-issuer-check   # 3 real servers (pinned) + a local mock impersonating an issuer", style="bold green")
console.print(Text.from_ansi(_render(results, color=True)))
console.save_svg(str(ROOT / "docs/demo.svg"), title="mcp-issuer-check")
print("wrote docs/demo.svg")
