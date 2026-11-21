import json
from pathlib import Path

import pytest

from mcp_issuer_check import lock
from mcp_issuer_check.cli import main
from mcp_issuer_check.configs import discover, load_jsonc, parse_file
from mcp_issuer_check.probe import private_target, probe, same_resource, well_known

from .mock_mcp import World, start

# ---------------------------------------------------------------- mock OAuth-protected MCP server


@pytest.fixture
def world():
    w = World()
    servers = start(w)
    yield w
    for s in servers:
        s.shutdown()


def codes(res):
    return {f.code for f in res.findings}


# ---------------------------------------------------------------- probe scenarios


def test_happy_path(world):
    r = probe("t", f"{world.base}/mcp", "test")
    assert r.status == 401
    assert r.prm_url == f"{world.base}/.well-known/oauth-protected-resource/mcp"
    assert r.authorization_servers == [world.base]
    assert r.as_info[0].issuer == world.base
    assert r.as_info[0].token_endpoint == f"{world.base}/token"
    assert codes(r) == set()


def test_root_prm_fallback_without_www_authenticate(world):
    world.www = False
    world.prm_at = "root"
    r = probe("t", f"{world.base}/mcp", "test")
    assert r.prm_url == f"{world.base}/.well-known/oauth-protected-resource"
    assert codes(r) == set()


def test_issuer_mismatch_is_high(world):
    world.issuer = "https://login.microsoftonline.com/common/v2.0"
    r = probe("t", f"{world.base}/mcp", "test")
    assert "ISSUER-MISMATCH" in codes(r)
    assert [f.severity for f in r.findings if f.code == "ISSUER-MISMATCH"] == ["high"]


def test_resource_mismatch(world):
    world.resource = "https://elsewhere.example/mcp"
    assert "RESOURCE-MISMATCH" in codes(probe("t", f"{world.base}/mcp", "test"))


def test_no_metadata_on_401(world):
    world.prm_at = "none"
    world.www = False
    r = probe("t", f"{world.base}/mcp", "test")
    assert codes(r) == {"NO-METADATA"}


def test_public_server_is_info(world):
    world.prm_at = "none"
    world.status = 200
    assert codes(probe("t", f"{world.base}/mcp", "test")) == {"NO-OAUTH"}


def test_gone_endpoint(world):
    world.prm_at = "none"
    world.status = 410
    assert "ENDPOINT-GONE" in codes(probe("t", f"{world.base}/mcp", "test"))


def test_prm_cross_origin(world):
    world.prm_at = "other"
    r = probe("t", f"{world.base}/mcp", "test")
    assert "PRM-CROSS-ORIGIN" in codes(r)
    assert r.prm_url.startswith(world.other)


def test_as_on_other_host_is_info_only(world):
    world.as_list = [world.other.replace("127.0.0.1", "localhost")]
    r = probe("t", f"{world.base}/mcp", "test")
    assert r.as_info[0].issuer == world.as_list[0]
    assert {f.severity for f in r.findings} <= {"info", "low"}


def test_plain_http_remote_server_rejected_without_network():
    r = probe("t", "http://mcp.example.com/mcp", "test")
    assert codes(r) == {"INSECURE-TRANSPORT"}


def test_http_as_for_remote_server_flagged(monkeypatch, world):
    # Simulate a remote https server advertising an http:// AS by probing the AS check directly
    world.as_list = ["http://auth.example.com"]
    r = probe("t", f"{world.base}/mcp", "test")  # loopback server: loopback http allowed, remote http AS is not
    assert "INSECURE-TRANSPORT" in codes(r)


def test_private_address_guard():
    assert private_target("10.0.0.5")
    assert private_target("169.254.169.254")
    assert private_target("127.0.0.1")
    assert not private_target("93.184.215.14")


# ---------------------------------------------------------------- url helpers


@pytest.mark.parametrize(
    "base,suffix,insert,expected",
    [
        (
            "https://mcp.notion.com/mcp",
            "oauth-protected-resource",
            True,
            "https://mcp.notion.com/.well-known/oauth-protected-resource/mcp",
        ),
        (
            "https://api.githubcopilot.com/mcp/",
            "oauth-protected-resource",
            True,
            "https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/",
        ),
        (
            "https://mcp.stripe.com",
            "oauth-protected-resource",
            True,
            "https://mcp.stripe.com/.well-known/oauth-protected-resource",
        ),
        (
            "https://github.com/login/oauth",
            "oauth-authorization-server",
            True,
            "https://github.com/.well-known/oauth-authorization-server/login/oauth",
        ),
        ("https://x.example/a/b", "oauth-protected-resource", False, "https://x.example/.well-known/oauth-protected-resource"),
    ],
)
def test_well_known(base, suffix, insert, expected):
    assert well_known(base, suffix, insert=insert) == expected


def test_same_resource():
    assert same_resource("https://MCP.example.com:443/mcp/", "https://mcp.example.com/mcp")
    assert not same_resource("https://mcp.example.com/v2/mcp", "https://mcp.example.com/sse")


# ---------------------------------------------------------------- pins


def test_pin_then_detect_change(world, tmp_path):
    url = f"{world.base}/mcp"
    pins = {"version": 1, "servers": {}}
    done, refused = lock.pin([probe("t", url, "test")], pins)
    assert done == [url] and not refused
    lock.save(tmp_path / "p.json", pins)

    world.as_list = [world.other]  # provider silently switched login server
    r = probe("t", url, "test")
    lock.compare([r], lock.load(tmp_path / "p.json"))
    assert "PIN-CHANGED" in codes(r)


def test_pin_refuses_bad_metadata(world):
    world.issuer = "https://evil.example"
    pins = {"version": 1, "servers": {}}
    done, refused = lock.pin([probe("t", f"{world.base}/mcp", "test")], pins)
    assert not done and refused
    assert pins["servers"] == {}


def test_unpinned_is_low(world):
    r = probe("t", f"{world.base}/mcp", "test")
    lock.compare([r], {"servers": {}})
    assert codes(r) == {"NOT-PINNED"}


# ---------------------------------------------------------------- configs

CLAUDE_CODE = {
    "mcpServers": {
        "notion": {"type": "http", "url": "https://mcp.notion.com/mcp", "headers": {"Authorization": "Bearer SECRET"}}
    },
    "projects": {
        "/p": {
            "mcpServers": {
                "linear": {"type": "sse", "url": "https://mcp.linear.app/sse"},
                "local": {"command": "npx", "args": ["x"], "env": {"KEY": "SECRET"}},
            }
        }
    },
}


def _write(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_claude_code_config(tmp_path):
    servers = parse_file(_write(tmp_path / ".claude.json", json.dumps(CLAUDE_CODE)))
    assert {(s.name, s.url) for s in servers} == {
        ("notion", "https://mcp.notion.com/mcp"),
        ("linear", "https://mcp.linear.app/sse"),
    }
    assert "SECRET" not in repr(servers)


def test_vscode_jsonc_and_settings(tmp_path):
    jsonc = '{\n // comment\n "servers": {"gh": {"type": "http", "url": "https://api.githubcopilot.com/mcp/",},},\n}'
    assert [s.url for s in parse_file(_write(tmp_path / "mcp.json", jsonc))] == ["https://api.githubcopilot.com/mcp/"]
    settings = '{"editor.fontSize": 14, /* x */ "mcp": {"servers": {"s": {"url": "https://mcp.sentry.dev/mcp"}}}}'
    assert [s.url for s in parse_file(_write(tmp_path / "settings.json", settings))] == ["https://mcp.sentry.dev/mcp"]


def test_windsurf_gemini_codex(tmp_path):
    ws = _write(tmp_path / "w.json", '{"mcpServers": {"a": {"serverUrl": "https://a.example/mcp"}}}')
    gm = _write(tmp_path / "g.json", '{"mcpServers": {"b": {"httpUrl": "https://b.example/mcp"}}}')
    cx = _write(tmp_path / "config.toml", '[mcp_servers.c]\nurl = "https://c.example/mcp"\n[mcp_servers.d]\ncommand = "x"\n')
    assert [s.url for s in parse_file(ws)] == ["https://a.example/mcp"]
    assert [s.url for s in parse_file(gm)] == ["https://b.example/mcp"]
    assert [s.url for s in parse_file(cx)] == ["https://c.example/mcp"]


def test_jsonc_keeps_urls_with_slashes():
    assert load_jsonc('{"u": "https://x//y", /* c */ "v": 1,}') == {"u": "https://x//y", "v": 1}


def test_discover_user_and_project(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("MCP_ISSUER_CHECK_HOME", str(home))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    _write(home / ".cursor" / "mcp.json", '{"mcpServers": {"c": {"url": "https://c.example/mcp"}}}')
    proj = tmp_path / "proj"
    _write(proj / ".mcp.json", '{"mcpServers": {"p": {"type": "http", "url": "https://p.example/mcp"}}}')
    found = {s.url for s in discover(proj)}
    assert found == {"https://c.example/mcp", "https://p.example/mcp"}
    assert {s.url for s in discover(proj, include_user=False)} == {"https://p.example/mcp"}


def test_broken_config_ignored(tmp_path):
    assert parse_file(_write(tmp_path / "bad.json", "{not json")) == []


# ---------------------------------------------------------------- cli


def test_cli_scan_and_pin(world, tmp_path, capsys):
    url = f"{world.base}/mcp"
    pins = str(tmp_path / "pins.json")
    assert main(["--url", url, "--pins", pins, "--no-color"]) == 0  # only NOT-PINNED (low)
    assert main(["pin", "--url", url, "--pins", pins]) == 0
    assert main(["--url", url, "--pins", pins, "-f", "json"]) == 0
    out = capsys.readouterr().out
    data = json.loads(out[out.index("{") :])
    assert data["results"][0]["authorization_servers"] == [world.base]
    world.as_list = [world.other]
    assert main(["--url", url, "--pins", pins, "--no-color"]) == 1
    assert "PIN-CHANGED" in capsys.readouterr().out


def test_cli_fail_on(world, tmp_path):
    world.resource = "https://elsewhere.example/mcp"
    url = f"{world.base}/mcp"
    pins = str(tmp_path / "p.json")
    assert main(["--url", url, "--pins", pins]) == 1
    assert main(["--url", url, "--pins", pins, "--fail-on", "high"]) == 0
    assert main(["--url", url, "--pins", pins, "--fail-on", "none"]) == 0


def test_cli_list(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("MCP_ISSUER_CHECK_HOME", str(tmp_path))
    _write(tmp_path / "proj" / ".mcp.json", '{"mcpServers": {"p": {"url": "https://p.example/mcp"}}}')
    assert main(["list", "--project", str(tmp_path / "proj"), "--no-user"]) == 0
    assert "https://p.example/mcp" in capsys.readouterr().out


def test_unreachable_pinned_server_is_not_a_change(tmp_path):
    url = "https://127.0.0.1:1/mcp"  # nothing listens on port 1
    pins = {"version": 1, "servers": {"https://127.0.0.1:1/mcp": {"authorization_servers": ["https://a.example"]}}}
    r = probe("t", url, "test", timeout=2)
    lock.compare([r], pins)
    assert "PIN-CHANGED" not in codes(r)
    assert "PIN-UNVERIFIED" in codes(r)
