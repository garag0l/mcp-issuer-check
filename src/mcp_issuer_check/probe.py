"""Discover which authorization server(s) an MCP server sends clients to, and check the metadata.

Follows the MCP authorization spec discovery order:
  1. unauthenticated `initialize` POST -> 401 `WWW-Authenticate: Bearer resource_metadata="..."`
  2. RFC 9728 Protected Resource Metadata (path-inserted well-known, then root)
  3. RFC 8414 / OpenID Connect metadata for each listed authorization server
No credentials are ever sent.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from . import __version__

UA = f"mcp-issuer-check/{__version__} (+https://github.com/garag0l/mcp-issuer-check)"
MAX_BODY = 512 * 1024
INIT_BODY = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "mcp-issuer-check", "version": __version__},
        },
    }
).encode()


@dataclass
class Finding:
    code: str
    severity: str  # high | medium | low | info
    message: str


@dataclass
class ASInfo:
    identifier: str
    metadata_url: str | None = None
    issuer: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    registration_endpoint: str | None = None


@dataclass
class Result:
    name: str
    url: str
    source: str
    status: int | None = None
    prm_url: str | None = None
    resource: str | None = None
    authorization_servers: list[str] = field(default_factory=list)
    as_info: list[ASInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def add(self, code: str, severity: str, message: str) -> None:
        self.findings.append(Finding(code, severity, message))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # surface redirects instead of following them blindly
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def set_ca_bundle(path: str | None) -> None:
    """Verify TLS against this CA file instead of the system store. Verification is never disabled."""
    global _opener
    ctx = ssl.create_default_context(cafile=path) if path else ssl.create_default_context()
    _opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))


def is_loopback_host(host: str) -> bool:
    if host in ("localhost",) or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def private_target(host: str) -> bool:
    """True if host is, or resolves to, a private/link-local/loopback address."""
    host = host.strip("[]")
    try:
        addrs = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addrs = {ipaddress.ip_address(ai[4][0].split("%")[0]) for ai in socket.getaddrinfo(host, None)}
        except (socket.gaierror, UnicodeError, OSError):
            return False
    return any(a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast for a in addrs)


def fetch(url: str, *, method: str = "GET", body: bytes | None = None, timeout: float = 10.0):
    """Return (status, headers, body_bytes). Never raises on HTTP errors."""
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json, text/event-stream"
        headers["MCP-Protocol-Version"] = "2025-11-25"
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with _opener.open(req, timeout=timeout) as r:  # noqa: S310 - scheme checked by callers
            return r.status, r.headers, r.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read(MAX_BODY) if e.fp else b""


def get_json(url: str, timeout: float):
    status, _, raw = fetch(url, timeout=timeout)
    if status != 200:
        return None
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


_RM = re.compile(r'resource_metadata\s*=\s*"([^"]+)"', re.I)


def well_known(base: str, suffix: str, *, insert: bool) -> str:
    """RFC 8414/9728 well-known URL. insert=True puts the path after the well-known segment."""
    p = urlsplit(base)
    path = p.path.rstrip("/") if p.path not in ("", "/") else ""
    if p.path.endswith("/") and path:
        path += "/"
    wk = f"/.well-known/{suffix}" + (path if insert else "")
    return urlunsplit((p.scheme, p.netloc, wk, "", ""))


def origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme.lower()}://{(p.hostname or '').lower()}" + (f":{p.port}" if p.port else "")


def norm(url: str) -> str:
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    port = (
        f":{p.port}" if p.port and not ((p.scheme == "https" and p.port == 443) or (p.scheme == "http" and p.port == 80)) else ""
    )
    return urlunsplit((p.scheme.lower(), host + port, p.path or "/", p.query, ""))


def same_resource(a: str, b: str) -> bool:
    return norm(a).rstrip("/") == norm(b).rstrip("/")


def _transport_ok(url: str, res: Result, what: str, allow_loopback_http: bool) -> bool:
    p = urlsplit(url)
    if p.scheme == "https":
        return True
    if p.scheme == "http" and allow_loopback_http and is_loopback_host(p.hostname or ""):
        return True
    res.add("INSECURE-TRANSPORT", "high", f"{what} uses {p.scheme}:// ({url}); tokens and codes would travel unencrypted")
    return False


def probe(name: str, url: str, source: str, *, timeout: float = 10.0, allow_private: bool = False) -> Result:
    res = Result(name, url, source)
    server_host = urlsplit(url).hostname or ""
    local_server = is_loopback_host(server_host)
    if not _transport_ok(url, res, "MCP server", allow_loopback_http=True):
        return res

    # 1. unauthenticated initialize
    rm_url = None
    try:
        status, headers, _ = fetch(url, method="POST", body=INIT_BODY, timeout=timeout)
        res.status = status
        www = ", ".join(headers.get_all("WWW-Authenticate") or []) if headers else ""
        m = _RM.search(www)
        rm_url = m.group(1) if m else None
    except (urllib.error.URLError, OSError, ValueError) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, ssl.SSLCertVerificationError):
            res.add(
                "UNREACHABLE",
                "low",
                f"TLS verification failed ({reason.verify_message}). If the site works in a browser, your Python "
                "CA store is likely missing a root: rerun with --ca-bundle (e.g. certifi's) or set SSL_CERT_FILE.",
            )
        else:
            res.add("UNREACHABLE", "low", f"could not reach server: {reason}")

    # 2. protected resource metadata
    candidates = []
    if rm_url:
        if origin(rm_url) != origin(url):
            res.add(
                "PRM-CROSS-ORIGIN",
                "medium",
                f"401 points resource metadata to another origin ({rm_url}); verify it belongs to this server",
            )
        candidates.append(rm_url)
    candidates += [
        well_known(url, "oauth-protected-resource", insert=True),
        well_known(url, "oauth-protected-resource", insert=False),
    ]
    prm = None
    for c in dict.fromkeys(candidates):
        if not _transport_ok(c, res, "resource metadata", allow_loopback_http=local_server):
            continue
        try:
            prm = get_json(c, timeout)
        except (urllib.error.URLError, OSError, ValueError):
            prm = None
        if prm and isinstance(prm.get("authorization_servers"), list):
            res.prm_url = c
            break
        prm = None

    if res.status in (404, 410):
        res.add("ENDPOINT-GONE", "medium", f"server URL returns HTTP {res.status}; update the URL in your client config")
    if not prm:
        if res.status in (401, 403):
            res.add(
                "NO-METADATA",
                "medium",
                "server requires auth but publishes no RFC 9728 metadata; clients fall back to legacy discovery "
                "(the path abused in GHSA-qx49-fqc8-xw99)",
            )
        elif not any(f.code == "UNREACHABLE" for f in res.findings):
            res.add("NO-OAUTH", "info", f"no OAuth advertised (HTTP {res.status}); server is public or uses another auth method")
        return res

    res.resource = prm.get("resource")
    res.authorization_servers = [a for a in prm["authorization_servers"] if isinstance(a, str)]
    if res.resource and not same_resource(res.resource, url):
        res.add(
            "RESOURCE-MISMATCH",
            "medium",
            f"metadata is for resource {res.resource}, not the configured URL {url}; RFC 9728 says clients must not use it",
        )
    if not res.authorization_servers:
        res.add("NO-AS", "medium", "resource metadata lists no authorization servers")

    # 3. authorization server metadata
    for as_id in res.authorization_servers:
        info = ASInfo(as_id)
        res.as_info.append(info)
        if not _transport_ok(as_id, res, f"authorization server {as_id}", allow_loopback_http=local_server):
            continue
        host = urlsplit(as_id).hostname or ""
        if not allow_private and not local_server and private_target(host):
            res.add(
                "AS-PRIVATE-ADDRESS",
                "high",
                f"authorization server {as_id} is on a private/internal address; not fetched (SSRF guard)",
            )
            continue
        md = None
        for mu in dict.fromkeys(
            [
                well_known(as_id, "oauth-authorization-server", insert=True),
                well_known(as_id, "openid-configuration", insert=True),
                as_id.rstrip("/") + "/.well-known/openid-configuration",
            ]
        ):
            try:
                md = get_json(mu, timeout)
            except (urllib.error.URLError, OSError, ValueError):
                md = None
            if md and md.get("issuer"):
                info.metadata_url = mu
                break
            md = None
        if not md:
            res.add("AS-NO-METADATA", "medium", f"no RFC 8414 / OIDC metadata found for {as_id}")
            continue
        info.issuer = md.get("issuer")
        info.authorization_endpoint = md.get("authorization_endpoint")
        info.token_endpoint = md.get("token_endpoint")
        info.registration_endpoint = md.get("registration_endpoint")
        if info.issuer.rstrip("/") != as_id.rstrip("/"):
            res.add(
                "ISSUER-MISMATCH",
                "high",
                f"metadata for {as_id} claims issuer {info.issuer}; RFC 8414 requires them to match. "
                "This is how a server impersonates your real authorization server.",
            )
        for label, ep in (
            ("token", info.token_endpoint),
            ("authorization", info.authorization_endpoint),
            ("registration", info.registration_endpoint),
        ):
            if not ep:
                continue
            _transport_ok(ep, res, f"{label} endpoint", allow_loopback_http=local_server)
            if (urlsplit(ep).hostname or "").lower() != host.lower():
                res.add(
                    "ENDPOINT-OTHER-HOST",
                    "low",
                    f"{label} endpoint {ep} is on a different host than issuer {info.issuer}; confirm it is expected",
                )
        if (urlsplit(as_id).hostname or "").lower() != server_host.lower():
            res.add("AS-OTHER-HOST", "info", f"login goes to {as_id} (different host than the MCP server)")
    return res
