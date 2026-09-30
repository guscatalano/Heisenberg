# Heisenberg

A Windows-only [MCP](https://modelcontextprotocol.io) server that makes native
debugging easy for an agent — capture dumps, configure gflags, run Procmon, open
dumps, drive TTD, launch from session 0 into a user session — wrapping only free,
Microsoft-published tools and citing public docs.

Full design plan: <https://claude.ai/code/artifact/00a8d7df-6da0-4f1b-a9f9-2cb877dbffc2>

## Status

**Phase 1 (foundation) — implemented.** The static single-binary `rmcp` server,
the `env.check` capability probe, the box-class safety spine, and the
`heisenberg://` / `docs://` resources. Later phases (dump capture/analysis,
gflags, procmon, kernel, TTD, logs, session-0) are planned; see the doc.

Tools today:

| Tool | What it does |
|------|--------------|
| `env.check` | Probe OS build/edition, architecture (incl. WOW64), integrity level, privileges (SeDebug/SeTcb), session id, derived capabilities. Read-only. |
| `policy.show` | Effective box class, its source/trust, per-tool overrides, and the full gate matrix. |
| `gate.check` | What gate a proposed `tool` + effect tier would face on this box (allow / confirm-token / human-approval / deny), without running anything. |

Resources: `heisenberg://env`, `heisenberg://policy`, `docs://<tool>`.

## Build

Requires Rust 1.88+ with the MSVC toolchain. The CRT is linked statically (see
`.cargo/config.toml`) so the binary runs on a bare box.

```powershell
cargo build --release        # -> target\release\heisenberg.exe
cargo test                   # policy + envelope unit tests
```

## Register with an MCP client

```powershell
claude mcp add heisenberg -- C:\path\to\heisenberg.exe
```

Or in a client config:

```json
{
  "mcpServers": {
    "heisenberg": { "command": "C:\\path\\to\\heisenberg.exe" }
  }
}
```

The server speaks MCP over stdio; logs go to stderr (`RUST_LOG=debug` for detail).

## Safety policy

The box's **risk class** is set by an operator-deployed policy, never by the
agent. It is read once at startup from an admin-only location and, if
absent/malformed/unverified, fails safe to `Critical`.

- **Location:** `%ProgramData%\Heisenberg\policy.json`, or the path in
  `HEISENBERG_POLICY`.
- **Format:** `{ "class": "sandbox" | "development" | "production" | "critical",
  "overrides": { "<tool>": "allow" | "confirm-token" | "human-approval" | "deny" } }`
- **Trust:** signature verification is a later phase. Until then a policy is
  `Unverified` (clamped to `Critical`) unless the operator sets
  `HEISENBERG_TRUST_UNSIGNED=1` — a dev/test escape hatch, not for production.

Gate matrix (box class × effect tier):

| class \ tier | read-only | state-changing | machine-disrupting |
|--------------|-----------|----------------|--------------------|
| sandbox      | allow     | allow          | allow              |
| development  | allow     | allow          | confirm-token      |
| production   | allow     | confirm-token  | human-approval     |
| critical     | allow     | human-approval | human-approval     |

## Layout

```
src/
  main.rs        stdio server bootstrap
  server.rs      MCP surface: tools + resources
  env_probe.rs   env.check: Win32 OS/token/session interrogation
  policy.rs      box class, effect tiers, gate matrix (unit-tested)
  config.rs      policy loading + fail-safe trust
  envelope.rs    uniform result/error envelope
  docs.rs        docs:// registry of Microsoft doc links
```
