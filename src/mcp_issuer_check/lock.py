"""Pin file: the authorization servers you have approved for each MCP server (trust on first use)."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from .probe import Result, norm

PIN_BLOCKERS = {"ISSUER-MISMATCH", "INSECURE-TRANSPORT", "AS-PRIVATE-ADDRESS", "RESOURCE-MISMATCH", "PRM-CROSS-ORIGIN"}


def default_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "mcp-issuer-check" / "pins.json"


def load(path: Path) -> dict:
    if not path.is_file():
        return {"version": 1, "servers": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("servers", {})
    return data


def save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def compare(results: list[Result], pins: dict) -> None:
    """Add findings for servers whose authorization servers differ from the pinned ones."""
    servers = pins.get("servers", {})
    for r in results:
        pinned = servers.get(norm(r.url))
        if pinned is None:
            if r.authorization_servers:
                r.add("NOT-PINNED", "low", "not in pin file yet; review the login servers above, then run `pin`")
            continue
        if any(f.code == "UNREACHABLE" for f in r.findings):
            r.add("PIN-UNVERIFIED", "low", "server unreachable; pinned login servers could not be re-checked")
            continue
        want = sorted(pinned.get("authorization_servers", []))
        got = sorted(r.authorization_servers)
        if got != want:
            r.add(
                "PIN-CHANGED",
                "high",
                f"authorization servers changed: pinned {want or 'none'}, now {got or 'none'}. "
                "Do not sign in until you confirm the change with the provider.",
            )
        want_iss = sorted(pinned.get("issuers", []))
        got_iss = sorted(i.issuer for i in r.as_info if i.issuer)
        if want_iss and got_iss and got_iss != want_iss:
            r.add("ISSUER-CHANGED", "high", f"issuer changed: pinned {want_iss}, now {got_iss}")


def pin(results: list[Result], pins: dict) -> tuple[list[str], list[str]]:
    """Record current observations. Returns (pinned_urls, refused_urls)."""
    done, refused = [], []
    now = datetime.now(UTC).isoformat(timespec="seconds")
    for r in results:
        if not r.authorization_servers:
            continue
        if any(f.code in PIN_BLOCKERS for f in r.findings):
            refused.append(r.url)
            continue
        pins["servers"][norm(r.url)] = {
            "name": r.name,
            "authorization_servers": sorted(r.authorization_servers),
            "issuers": sorted(i.issuer for i in r.as_info if i.issuer),
            "pinned_at": now,
        }
        done.append(r.url)
    return done, refused
