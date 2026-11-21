"""Mock OAuth-protected MCP server (RFC 9728 + RFC 8414) used by tests and the Action smoke test.

Run standalone:  python tests/mock_mcp.py PORT [issuer-override]
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class World:
    """Mutable behaviour for the mock server, so each test can shape the metadata."""

    def __init__(self):
        self.base = ""
        self.other = ""  # second origin
        self.prm_at = "path"  # path | root | none
        self.www = True
        self.resource = None  # default: the MCP URL
        self.as_list = None  # default: [base]
        self.issuer = None  # default: AS identifier
        self.status = 401


def make_handler(world: World, role: str):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.path == "/mcp" and role == "main":
                self.send_response(world.status)
                if world.www and world.status == 401:
                    rm = f"{world.base}/.well-known/oauth-protected-resource/mcp"
                    if world.prm_at == "other":
                        rm = f"{world.other}/.well-known/oauth-protected-resource/mcp"
                    self.send_header("WWW-Authenticate", f'Bearer realm="x", resource_metadata="{rm}"')
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._json({"error": "nope"}, 404)

        def do_GET(self):
            me = f"http://{self.headers['Host']}"  # issuer reflects the host the client used, like a real AS
            prm = {
                "resource": world.resource or f"{world.base}/mcp",
                "authorization_servers": world.as_list if world.as_list is not None else [world.base],
            }
            if self.path == "/.well-known/oauth-protected-resource/mcp":
                if (role == "main" and world.prm_at == "path") or (role == "other" and world.prm_at == "other"):
                    return self._json(prm)
            if self.path == "/.well-known/oauth-protected-resource" and role == "main" and world.prm_at == "root":
                return self._json(prm)
            if self.path.startswith("/.well-known/oauth-authorization-server"):
                ident = me + self.path[len("/.well-known/oauth-authorization-server") :]
                return self._json(
                    {
                        "issuer": world.issuer or ident,
                        "authorization_endpoint": f"{me}/authorize",
                        "token_endpoint": f"{me}/token",
                    }
                )
            self._json({"error": "not found"}, 404)

    return H


def start(world: World):
    servers = []
    for role in ("main", "other"):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(world, role))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    world.base = f"http://127.0.0.1:{servers[0].server_address[1]}"
    world.other = f"http://127.0.0.1:{servers[1].server_address[1]}"
    return servers


if __name__ == "__main__":
    w = World()
    port = int(sys.argv[1])
    if len(sys.argv) > 2:
        w.issuer = sys.argv[2]
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(w, "main"))
    w.base = f"http://127.0.0.1:{port}"
    print(f"mock MCP server on {w.base}/mcp", flush=True)
    srv.serve_forever()
