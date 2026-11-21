"""Find remote (HTTP/SSE) MCP servers in the config files of common MCP clients.

Only the server name, URL and source file are extracted. Headers, env vars and other
values (which often hold API keys) are never read into the results or sent anywhere.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

URL_KEYS = ("url", "serverUrl", "httpUrl", "server_url")
CONTAINER_KEYS = ("mcpServers", "servers", "mcp_servers")


@dataclass(frozen=True)
class Server:
    name: str
    url: str
    source: str


def _home() -> Path:
    return Path(os.environ.get("MCP_ISSUER_CHECK_HOME") or Path.home())


def user_config_paths() -> list[tuple[str, Path]]:
    """(client, path) pairs for user-level configs on this OS."""
    h = _home()
    appdata = Path(os.environ.get("APPDATA") or h / "AppData" / "Roaming")
    mac_support = h / "Library" / "Application Support"
    xdg = Path(os.environ.get("XDG_CONFIG_HOME") or h / ".config")
    if sys.platform == "win32":
        claude_desktop = appdata / "Claude" / "claude_desktop_config.json"
        vscode_user = appdata / "Code" / "User"
    elif sys.platform == "darwin":
        claude_desktop = mac_support / "Claude" / "claude_desktop_config.json"
        vscode_user = mac_support / "Code" / "User"
    else:
        claude_desktop = xdg / "Claude" / "claude_desktop_config.json"
        vscode_user = xdg / "Code" / "User"
    return [
        ("claude-code", h / ".claude.json"),
        ("claude-code", h / ".claude" / "settings.json"),
        ("claude-desktop", claude_desktop),
        ("cursor", h / ".cursor" / "mcp.json"),
        ("windsurf", h / ".codeium" / "windsurf" / "mcp_config.json"),
        ("gemini-cli", h / ".gemini" / "settings.json"),
        ("vscode", vscode_user / "mcp.json"),
        ("vscode", vscode_user / "settings.json"),
        ("codex", h / ".codex" / "config.toml"),
    ]


def project_config_paths(root: Path) -> list[tuple[str, Path]]:
    return [
        ("claude-code", root / ".mcp.json"),
        ("cursor", root / ".cursor" / "mcp.json"),
        ("vscode", root / ".vscode" / "mcp.json"),
        ("gemini-cli", root / ".gemini" / "settings.json"),
    ]


_JSONC_COMMENT = re.compile(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*.*?\*/', re.S)
_TRAILING_COMMA = re.compile(r'("(?:\\.|[^"\\])*")|,(\s*[}\]])')


def load_jsonc(text: str):
    """Parse JSON with // and /* */ comments and trailing commas (VS Code settings)."""
    text = _JSONC_COMMENT.sub(lambda m: m.group(1) or "", text)
    text = _TRAILING_COMMA.sub(lambda m: m.group(1) or m.group(2), text)
    return json.loads(text)


def _servers_in(obj, source: str, out: list[Server]) -> None:
    """Walk a parsed config and collect every remote server entry under a known container key."""
    if isinstance(obj, dict):
        for key, val in obj.items():
            if key in CONTAINER_KEYS and isinstance(val, dict):
                for name, entry in val.items():
                    if not isinstance(entry, dict):
                        continue
                    for k in URL_KEYS:
                        u = entry.get(k)
                        if isinstance(u, str) and u.lower().startswith(("http://", "https://")):
                            out.append(Server(str(name), u.strip(), source))
                            break
            elif key == "mcp" and isinstance(val, dict):  # VS Code settings.json: "mcp": {"servers": {...}}
                _servers_in(val, source, out)
            elif isinstance(val, (dict, list)) and key not in ("env", "headers"):
                _servers_in(val, source, out)
    elif isinstance(obj, list):
        for v in obj:
            _servers_in(v, source, out)


def parse_file(path: Path, label: str | None = None) -> list[Server]:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return []
    source = label or str(path)
    try:
        data = tomllib.loads(text) if path.suffix == ".toml" else load_jsonc(text)
    except (ValueError, tomllib.TOMLDecodeError):
        return []
    out: list[Server] = []
    _servers_in(data, source, out)
    return out


def discover(project: Path | None = None, include_user: bool = True) -> list[Server]:
    paths: list[tuple[str, Path]] = []
    if include_user:
        paths += user_config_paths()
    if project:
        paths += project_config_paths(project)
    seen, out = set(), []
    for client, p in paths:
        if not p.is_file():
            continue
        for s in parse_file(p, f"{client}:{p}"):
            key = (s.name, s.url)
            if key not in seen:
                seen.add(key)
                out.append(s)
    return out
