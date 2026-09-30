# Heisenberg

A Windows-only [MCP](https://modelcontextprotocol.io) server that makes native
debugging easy for an agent — capture dumps, configure gflags, run Procmon, open
dumps, drive TTD, launch from session 0 into a user session — wrapping only free,
Microsoft-published tools and citing public docs.

Full design plan: <https://claude.ai/code/artifact/00a8d7df-6da0-4f1b-a9f9-2cb877dbffc2>

## Status

**Phases 1–3 — implemented.** The static single-binary `rmcp` server, the
`env.check` probe, the box-class safety spine with *enforcement*, the reversible
change ledger + audit journal, and the first capture-then-inspect loop. Later
phases (gflags, procmon, kernel, TTD, logs, session-0) are planned; see the doc.

Tools today:

| Tool | What it does |
|------|--------------|
| `env.check` | Probe OS build/edition, architecture (incl. WOW64), integrity level, privileges (SeDebug/SeTcb), session id, derived capabilities. Read-only. |
| `policy.show` / `gate.check` | Show the box class + gate matrix; test what gate a proposed tool+tier would face, without running anything. |
| `tools.list` | Inventory the external tools Heisenberg drives — found (with path) vs missing — each with its doc link. |
| `system.triage` | First-response gather on a broken box: systeminfo, services, tasklist, boot config, drivers, hypervisor, log locations. |
| `inspect.processTree` / `inspect.network` / `inspect.verify` | Process tree (pid/ppid), active connections (netstat), and Authenticode signature checks. |
| `dump.capture` | Capture a user-mode dump (full/mini) by pid or name. ProcDump if staged, else comsvcs. Disk pre-checked; full dumps marked high-sensitivity. |
| `dump.onCrashInstall` | Configure WER LocalDumps so future crashes of an image (or all) auto-dump (reversible; needs elevation). |
| `postmortem.aeDebug` | Set the AeDebug JIT debugger so any unhandled crash drops to a scripted dump (reversible; needs elevation). |
| `dump.analyze` | Open a dump in cdb (`!analyze -v`, stacks, modules) and return parsed + raw. Needs the Debugging Tools for Windows. |
| `analyze.deadlock` / `analyze.highCpu` / `analyze.handles` / `analyze.async` / `analyze.verifierStop` | Targeted cdb analyses of a dump (lock contention, CPU by thread, handle leaks, .NET async, verifier stops). |
| `gflags.get` / `gflags.set` | Show / enable full page heap for an image via IFEO (reversible via the ledger; `dry_run` + confirm token; needs elevation). Disable by reverting the change. |
| `appverifier.enable` | Enable Application Verifier for an image via IFEO (reversible; needs elevation). |
| `ttd.record` / `ttd.stop` / `ttd.replay` | Record a process to a Time Travel Debugging `.run` trace (a `job.*` capture) and replay it in cdb. |
| `dotnet.dump` / `dotnet.gcHeap` / `dotnet.analyze` | Managed (.NET) dumps, GC-heap snapshots, and SOS analysis via the dotnet diagnostics tools. |
| `symbols.show` / `symbols.configure` | Read / set `_NT_SYMBOL_PATH` (reversible via the ledger; `dry_run` + confirm token). |
| `procmon.start` / `procmon.stop` | Start/stop a background Process Monitor capture to a `.pml` (needs Procmon staged + elevation). |
| `job.list` / `job.status` / `job.stop` / `job.cancel` | Unified control for every background capture job. |
| `kernel.status` | Crash-dump mode, detected hypervisor (Hyper-V / Proxmox / VMware / physical), and bcdedit debug settings. |
| `kernel.setCrashDump` | Set the crash-dump mode via CrashControl (reversible; needs elevation). |
| `kernel.serialDebugSetup` / `kernel.netDebugSetup` | Configure guest kernel debugging (serial or KDNET) + emit host-side wiring for the hypervisor (reversible; needs elevation + reboot). |
| `logs.eventQuery` / `logs.eventExport` | Query recent event-log entries (wevtutil) or export a channel to `.evtx`. |
| `logs.etwStart` / `logs.etwStop` | Start/stop a background WPR ETW trace to `.etl` (a `job.*` capture; needs elevation). |
| `session.list` | Windows sessions (id/station/state) + the active console session. |
| `session.launchInUser` | Launch a process from session 0 / SYSTEM into the active user session (needs SeTcbPrivilege). |
| `changes.list` / `changes.revert` | The reversible-change ledger and one-call undo. |
| `collect.package` | Bundle a portable case (env + policy + ledger + jobs + dumps + audit) into a zipped manifest. |
| `report.generate` | Human-readable Markdown incident report from the current state. |
| `artifacts.purge` | Reclaim disk by deleting captured artifacts (dry-run by default; optional age filter). |

Resources: `heisenberg://env`, `heisenberg://policy`, `heisenberg://changes`,
`heisenberg://audit`, `heisenberg://dumps` (+ `/<id>`), `heisenberg://captures`
(+ `/<id>`), `heisenberg://tools`, `docs://<tool>`.

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
