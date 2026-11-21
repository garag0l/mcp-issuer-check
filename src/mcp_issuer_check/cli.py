"""mcp-issuer-check command line."""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__, lock
from .configs import Server, discover
from .probe import Result, probe, set_ca_bundle

SEV = {"high": 3, "medium": 2, "low": 1, "info": 0}


def _servers(a) -> list[Server]:
    servers = [Server(urlsplit(u).hostname or u, u, "--url") for u in a.url or []]
    if not a.url or a.project or a.user:
        servers += discover(Path(a.project).resolve() if a.project else Path.cwd(), include_user=not a.no_user)
    seen, out = set(), []
    for s in servers:
        if s.url not in seen:
            seen.add(s.url)
            out.append(s)
    return out


def _render(results: list[Result], color: bool) -> str:
    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    col = {"high": "31", "medium": "33", "low": "36", "info": "2"}
    lines = [c("1", f"mcp-issuer-check {__version__}"), ""]
    for r in results:
        lines.append(c("1", f"{r.name}") + f"  {r.url}")
        lines.append(c("2", f"  from {r.source}"))
        if r.authorization_servers:
            for i in r.as_info:
                iss = i.issuer or "?"
                lines.append(f"  login via {i.identifier}" + (c("2", f"  (issuer {iss})") if iss != i.identifier else ""))
        for f in sorted(r.findings, key=lambda f: -SEV[f.severity]):
            lines.append("  " + c(col[f.severity], f"[{f.severity.upper()}] {f.code}") + f"  {f.message}")
        if not r.findings and r.authorization_servers:
            lines.append("  " + c("32", "ok"))
        lines.append("")
    counts = {s: sum(1 for r in results for f in r.findings if f.severity == s) for s in SEV}
    lines.append(
        c(
            "1",
            f"{len(results)} remote server(s): {counts['high']} high, {counts['medium']} medium, "
            f"{counts['low']} low, {counts['info']} info",
        )
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="mcp-issuer-check",
        description="See which OAuth authorization servers your MCP servers send your login to, check their metadata, "
        "and pin them so a silent change gets caught.",
    )
    p.add_argument(
        "command",
        nargs="?",
        choices=["scan", "pin", "list"],
        default="scan",
        help="scan (default): probe and report; pin: approve current login servers; list: show discovered servers",
    )
    p.add_argument(
        "--url",
        action="append",
        metavar="URL",
        help="check this MCP server URL (repeatable); skips config discovery unless --user/--project",
    )
    p.add_argument(
        "--project", metavar="DIR", help="also read project configs (.mcp.json, .cursor/, .vscode/) in DIR (default: cwd)"
    )
    p.add_argument("--user", action="store_true", help="with --url, also read user-level client configs")
    p.add_argument("--no-user", action="store_true", help="skip user-level client configs")
    p.add_argument("--pins", metavar="FILE", help=f"pin file (default: {lock.default_path()})")
    p.add_argument("-f", "--format", choices=["text", "json"], default="text")
    p.add_argument("--fail-on", choices=["high", "medium", "low", "none"], default="medium")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument(
        "--ca-bundle", metavar="FILE", help="verify TLS with this CA bundle (default: system store; SSL_CERT_FILE is honored)"
    )
    p.add_argument("--allow-private", action="store_true", help="allow fetching authorization servers on private addresses")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    a = p.parse_args(argv)

    if a.ca_bundle:
        set_ca_bundle(a.ca_bundle)
    servers = _servers(a)
    if a.command == "list":
        for s in servers:
            print(f"{s.name}\t{s.url}\t{s.source}")
        return 0
    if not servers:
        print("No remote MCP servers found. Use --url, or --project DIR.", file=sys.stderr)
        return 0

    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(
            ex.map(lambda s: probe(s.name, s.url, s.source, timeout=a.timeout, allow_private=a.allow_private), servers)
        )

    pins_path = Path(a.pins) if a.pins else lock.default_path()
    pins = lock.load(pins_path)
    if a.command == "pin":
        done, refused = lock.pin(results, pins)
        lock.save(pins_path, pins)
        for u in done:
            print(f"pinned   {u}")
        for u in refused:
            print(f"REFUSED  {u}  (fix the high/medium metadata findings first)")
        print(f"pin file: {pins_path}")
        return 1 if refused else 0

    lock.compare(results, pins)
    if a.format == "json":
        print(json.dumps({"version": __version__, "pins": str(pins_path), "results": [asdict(r) for r in results]}, indent=2))
    else:
        color = not a.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        print(_render(results, color))
    threshold = {"none": 99, **SEV}[a.fail_on]
    worst = max((SEV[f.severity] for r in results for f in r.findings), default=-1)
    return 1 if worst >= threshold and threshold != 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
