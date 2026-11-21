# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-11-21

### Added
- Published to PyPI.

## [0.1.0] - 2026-11-21

### Added
- Discovery of remote MCP servers in Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI and Codex configs (names and URLs only; headers and env values are never read into results).
- MCP-spec OAuth discovery: `WWW-Authenticate` resource metadata, RFC 9728 protected resource metadata, RFC 8414 / OpenID Connect authorization server metadata.
- Checks: issuer mismatch, resource mismatch, insecure transport, cross-origin resource metadata, missing metadata, gone endpoints, endpoints on other hosts, private-address SSRF guard.
- `pin` / pin file with change detection (`PIN-CHANGED`, `ISSUER-CHANGED`); pinning refused for servers with bad metadata.
- Text and JSON output, `--fail-on`, `--ca-bundle`, composite GitHub Action.
