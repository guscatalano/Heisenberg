# Heisenberg

A Windows-only [MCP](https://modelcontextprotocol.io) server that makes native
debugging easy for an agent — capture dumps, configure gflags, run Procmon, open
dumps, drive TTD, launch from session 0 into a user session — wrapping free
debugging tools (Microsoft-published by default, plus opt-in third-party helpers
like cv2pdb and the REA reverse-engineering MCP) and citing public docs.

## Why it's useful

Native Windows debugging normally means a human at a WinDbg prompt who already
knows which SDK tool to reach for, what registry key arms it, and how to read the
output. Heisenberg hands that whole loop to an agent — safely, reversibly, and
with every step citing the public doc it came from. Some concrete situations:

- **"It crashes in the field and I can't repro it."** The agent arms
  `dump.onCrashInstall` (WER LocalDumps) or `dump.onTrigger` so the *next* crash
  auto-captures a dump, then runs `symbols.download` + `dump.analyze` /
  `analyze.highCpu` / `analyze.handles` to get a symbolized root-cause stack — no
  live repro, no human watching the box.

- **"It's hung and nothing's obviously wrong."** `analyze.waitChain` asks the OS
  (Wait Chain Traversal) what every thread is blocked on and who holds it —
  *across processes* — and flags deadlock cycles that a single process's `!locks`
  can't see. `inspect.stacks` grabs all thread stacks live, without a full dump.

- **"Memory's getting corrupted somewhere."** `gflags.set` turns on full page
  heap so the bad write faults at the *exact* instruction instead of crashing
  later in innocent code; `appverifier.enable` adds handle/lock checks. Both are
  reversible — one `changes.revert` undoes them.

- **"This is a production box — don't break it."** Every mutation runs through the
  box-class safety spine: gated by a confirm token or out-of-band human approval
  on Critical boxes, recorded with its inverse in the ledger *before* it's applied,
  and full dumps flagged sensitive before anything leaves the machine. The agent
  can act on a live server without being a liability.

- **"A driver is bugchecking the machine."** `kernel.analyze` reads the crash dump
  (`!analyze -v`), `kernel.poolAnalyze` localizes pool-tag leaks, and
  `kernel.verifier` turns on Driver Verifier to force a latent driver bug into an
  immediate, debuggable bugcheck (reversible, applies on reboot).

- **"Make it reproducible / hand it off."** `repro.record` captures the arming
  conditions + the manual trigger steps + the resulting dump as a replayable
  recipe; `repro.replay` re-arms them on any box; `collect.package` bundles a
  portable case and `report.generate` writes the human-readable incident report.

## Status

**Phases 1–3 — implemented.** The static single-binary `rmcp` server, the
`env.check` probe, the box-class safety spine with *enforcement*, the reversible
change ledger + audit journal, and the first capture-then-inspect loop. Later
phases (gflags, procmon, kernel, TTD, logs, session-0) are planned.

Tools today:

| Tool | What it does |
|------|--------------|
| `env.check` | Probe OS build/edition, architecture (incl. WOW64), integrity level, privileges (SeDebug/SeTcb), session id, derived capabilities. Read-only. |
| `policy.show` / `gate.check` | Show the box class + gate matrix; test what gate a proposed tool+tier would face, without running anything. |
| `tools.list` | Inventory the external tools Heisenberg drives — found (with path) vs missing — each with its doc link. |
| `tools.install` | Install a known tool via direct download / winget / dotnet CLI (procdump, procmon, sysinternals, windbg, windows-sdk, dotnet-dump…); gated, uninstallable via `changes.revert`. |
| `env.provision` | Provision the whole toolchain in one step via [Groundhog](https://github.com/guscatalano/Groundhog) if installed (default profile: windows-internals — Sysinternals, WinDbg, WPT, symbols, crash dumps). Falls back to `tools.install` when absent. |
| `tools.addFolder` / `tools.removeFolder` | Add/remove a folder in the tool search path (searched first, persisted across restarts). |
| `system.triage` | First-response gather on a broken box: systeminfo, services, tasklist, boot config, drivers, hypervisor, log locations. |
| `triage.auto` | One-call auto-triage: pick the right cdb commands for a symptom (crash/hang/deadlock/high-cpu/leak) against a live pid or a dump, and return the analysis. |
| `inspect.processTree` / `inspect.network` / `inspect.verify` / `inspect.access` | Process tree (pid/ppid), active connections (netstat), Authenticode checks, and effective-ACL checks (AccessChk). |
| `inspect.stacks` | Every thread's call stack + loaded modules of a LIVE process (noninvasive `cdb -pv`) — a fast first look without a full, sensitive dump. Read-only. |
| `inspect.addressSpace` | Virtual-address-space summary + regions of a dump (`!address`) to spot reservation/commit growth and leaks. |
| `inspect.drivers` | Loaded kernel drivers with versions/paths/signing (driverquery /v). |
| `inspect.mitigations` | Exploit-mitigation policy of a process (DEP/ASLR/CFG/CET…) via `Get-ProcessMitigation`. |
| `analyze.waitChain` | Ask the OS (Wait Chain Traversal) what each live thread is blocked on and who holds it — ACROSS processes; flags deadlock cycles. Native Win32, no cdb. |
| `memory.read` | Read a span of a live process's memory at an address (or module+offset) and return hex + ASCII. Read-only. |
| `perf.counters` | Sample a process's CPU/working-set/handles/threads and GDI+USER object counts over a short window. |
| `dump.capture` | Capture a user-mode dump (full/mini) by pid or name. ProcDump if staged, else comsvcs. Disk pre-checked; full dumps marked high-sensitivity. |
| `dump.onCrashInstall` | Configure WER LocalDumps so future crashes of an image (or all) auto-dump (reversible; needs elevation). |
| `wer.list` | Recent Windows Error Reporting crash history (app/kernel events + WER report folders), optionally filtered by image. |
| `dump.compare` | Diff two dumps — modules present in one but not the other, and thread-count delta — to localize what changed between a good and bad capture. |
| `dump.redact` | Write a redacted COPY of a dump with common secrets (passwords, keys, tokens, Bearer/AWS/PEM) overwritten, for safer off-box sharing. |
| `dump.onTrigger` | Arm ProcDump to dump on a trigger (exception / CPU / hang) as a background `job.*` capture. |
| `service.startupDebug` | Attach a debugger to an image at process start (IFEO Debugger) for startup crashes/hangs (reversible; needs elevation). |
| `postmortem.aeDebug` | Set the AeDebug JIT debugger so any unhandled crash drops to a scripted dump (reversible; needs elevation). |
| `dump.analyze` | Open a dump in cdb (`!analyze -v`, stacks, modules) and return parsed + raw. Needs the Debugging Tools for Windows. |
| `dump.open` / `dump.command` / `dump.close` | Interactive cdb session on a dump: run arbitrary commands across calls, then close. |
| `debug.windbgMcp` | Hand off to the official **WinDbg MCP** (WinDbg ≥ 1.2610.1001.0) for live/interactive debugging: locate `DbgX.Mcp.Proxy.exe`, emit the stdio connect recipe (`list_sessions`/`connect_session`) + GUI-enable steps, optionally open a pid/dump. Read-only; complements the headless cdb analyses. |
| `re.reverseEngineer` | Hand off to **REA** (Reverse Engineer Anything) — a third-party MCP (Ghidra/IDA/Hopper) for deep binary RE across PE/ELF/Mach-O/.NET/Electron/APK; emits the `npx rea-agents setup` recipe. Gated by `allow_third_party_tools`. |
| `analyze.deadlock` / `analyze.highCpu` / `analyze.handles` / `analyze.async` / `analyze.verifierStop` / `analyze.foreignDump` | Targeted cdb analyses of a dump (lock contention, CPU by thread, handle leaks, .NET async, verifier stops, off-box dumps with matched symbols). |
| `gflags.get` / `gflags.set` | Show / enable full page heap for an image via IFEO (reversible via the ledger; `dry_run` + confirm token; needs elevation). Disable by reverting the change. |
| `appverifier.enable` | Enable Application Verifier for an image via IFEO (reversible; needs elevation). |
| `memory.patch` / `binary.patch` | Patch bytes in a live process (`WriteProcessMemory`, ASLR-aware module+RVA) or in a PE file on disk (RVA→file offset). Reversible via the ledger; `dry_run` + confirm. |
| `binary.replace` | Replace a whole binary file with another (rebuilt / instrumented / fixed build). Pristine original pinned, each replace versioned, retention-capped (`HEISENBERG_BACKUP_KEEP`); handles loaded images (renames aside) and TrustedInstaller/System32 (takes ownership, restored on revert). Reversible; needs elevation; `dry_run` + confirm. |
| `ttd.record` / `ttd.stop` / `ttd.replay` | Record a process to a Time Travel Debugging `.run` trace (a `job.*` capture) and replay it in cdb. |
| `leak.heapTrackStart` / `leak.heapSnapshot` / `leak.heapDiff` | Enable the UMDH stack DB (IFEO), snapshot a heap, and diff snapshots to find leaks. |
| `boot.trace` | Configure a WPR boot trace (arm / collect / cancel) for pre-login and startup issues. |
| `gpu.tdrAnalyze` | Analyze a kernel dump for a GPU TDR (VIDEO_TDR_FAILURE 0x116/0x117). |
| `inspect.autoruns` | Enumerate autostart / persistence points (Autoruns) as CSV. |
| `remote.logCollect` / `remote.dumpCapture` | Query event logs (wevtutil /r) or capture a dump (PsExec + ProcDump) on a remote host. |
| `dotnet.dump` / `dotnet.gcHeap` / `dotnet.analyze` / `dotnet.trace` / `dotnet.counters` | Managed (.NET) dumps, GC-heap snapshots, SOS analysis, timed CPU traces, and perf counters. |
| `symbols.show` / `symbols.configure` | Read / set `_NT_SYMBOL_PATH` (reversible via the ledger; `dry_run` + confirm token). |
| `symbols.download` | Pre-cache symbols for a dump (`.reload /f`) or an image (symchk) so later analyses resolve frames offline. |
| `procmon.start` / `procmon.stop` | Start/stop a background Process Monitor capture to a `.pml` (needs Procmon staged + elevation). |
| `job.list` / `job.status` / `job.stop` / `job.cancel` | Unified control for every background capture job. |
| `kernel.status` | Crash-dump mode, detected hypervisor (Hyper-V / Proxmox / VMware / physical), and bcdedit debug settings. |
| `kernel.setCrashDump` | Set the crash-dump mode via CrashControl (reversible; needs elevation). |
| `kernel.analyze` | Open a kernel/complete dump in cdb (`!analyze -v`, modules) and return the bugcheck analysis. |
| `kernel.poolAnalyze` | Kernel pool usage (`!vm`, `!poolused`) to localize pool-tag growth / pool exhaustion. |
| `kernel.verifier` | Enable Driver Verifier (standard flags) on named drivers or all third-party drivers; `/reset` to clear (reversible via the ledger; `dry_run` + confirm; needs elevation + reboot). |
| `kernel.serialDebugSetup` / `kernel.netDebugSetup` | Configure guest kernel debugging (serial or KDNET) + emit host-side wiring for the hypervisor (reversible; needs elevation + reboot). |
| `logs.eventQuery` / `logs.eventExport` | Query recent event-log entries (wevtutil) or export a channel to `.evtx`. |
| `logs.etwStart` / `logs.etwStop` | Start/stop a background WPR ETW trace to `.etl` (a `job.*` capture; needs elevation). |
| `trace.cpuSample` | Short system-wide CPU sampling trace to `.etl` (WPR CPU profile) for a quick "what's hot" without a full boot/ETW setup (needs elevation). |
| `session.list` | Windows sessions (id/station/state) + the active console session. |
| `session.launchInUser` | Launch a process from session 0 / SYSTEM into the active user session (needs SeTcbPrivilege). |
| `remote.debugServer` | Start a dbgsrv process server (a `job.*` capture) so a remote WinDbg can debug this box; returns the connect string. |
| `changes.list` / `changes.revert` | The reversible-change ledger and one-call undo. |
| `approvals.list` | Human-approval broker grants (for HumanApproval-gated actions on Critical boxes). |
| `audit.export` | Export the append-only audit journal (path, count, recent entries). |
| `repro.record` | Record (or update) a **repro recipe**: the re-appliable arming conditions (page heap / App Verifier / dump-on-trigger / symbol path), the manual trigger steps Heisenberg can't observe, and the evidence it produced. Pass `id` to attach a dump after you reproduce. |
| `repro.replay` | Replay a recipe — `mode=emit` (read-only) returns the ordered runnable recipe; `mode=apply` re-arms the conditions on this box by re-invoking each underlying tool (each re-passes its own gate + records a reversible ledger entry; `dry_run` + confirm token). |
| `collect.package` | Bundle a portable case (env + policy + ledger + jobs + dumps + repros + audit) into a zipped manifest. |
| `report.generate` | Human-readable Markdown incident report from the current state. |
| `artifacts.purge` | Reclaim disk by deleting captured artifacts (dry-run by default; optional age filter). |

Resources: `heisenberg://env`, `heisenberg://policy`, `heisenberg://changes`,
`heisenberg://audit`, `heisenberg://dumps` (+ `/<id>`), `heisenberg://repros`
(+ `/<id>`), `heisenberg://captures` (+ `/<id>`), `heisenberg://cases`,
`heisenberg://sessions`, `heisenberg://tools`, `docs://<tool>`. Plus 11 guided **prompts** (triage-broken-box, diagnose-crash/hang/
deadlock/high-cpu/leak, diagnose-service-start, app-wont-launch, analyze-existing-dump/
bugcheck, diagnose-verifier-stop).

## Build

Requires Rust 1.88+ with the MSVC toolchain. The CRT is linked statically (see
`.cargo/config.toml`) so the binary runs on a bare box.

```powershell
cargo build --release        # -> target\release\heisenberg.exe
cargo test                   # policy + envelope unit tests
```

## Transports: stdio (default) and HTTP + web portal

By default Heisenberg speaks MCP over **stdio** (an MCP client spawns the process).
It can also serve the full tool set over **HTTP**, with an interactive **web portal**:

```powershell
heisenberg serve-http                 # binds 127.0.0.1:8787
heisenberg serve-http 127.0.0.1:9000  # or a custom HOST:PORT (HEISENBERG_HTTP_ADDR)
```

On start it prints a bearer **token** and the URLs:

- **MCP endpoint** — `POST http://<addr>/mcp` with `Authorization: Bearer <token>`
  (streamable HTTP). Point any HTTP MCP client at it.
- **Web portal** — open `http://<addr>/?token=<token>` for a dashboard of the live
  state (env, policy + gate matrix, ledger, dumps, backups, captures, repros, audit)
  and a tool runner. The portal is itself an MCP client, so **every tool call goes
  through the same gate / confirm-token / ledger / audit as any other client** — the
  safety spine is not bypassed.

Security: HTTP is **opt-in**, **loopback-bound by default**, and **token-gated**
(set `HEISENBERG_HTTP_TOKEN`, else one is generated and persisted under
`HEISENBERG_HOME`). A non-loopback bind is allowed but warns loudly. On a Critical
box, mutations over HTTP still require out-of-band `heisenberg approve`.

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

## Deploy to a broken box

Heisenberg is a single static-CRT binary with no runtime dependencies, meant to
be dropped onto an already-broken or air-gapped machine. After copying
`heisenberg.exe` over, verify it offline before wiring it to a client:

```powershell
heisenberg version      # build identity
heisenberg selfcheck    # policy in force, elevation, state root, and which
                        # external tools (cdb/procdump/procmon/...) resolve here
```

`selfcheck` (alias `doctor`) starts no server and touches nothing — it just
reports what the agent would see. A `[ ]` next to a tool means it isn't on this
box; stage it with `tools.install` (needs network) or point `HEISENBERG_TOOLS`
at a folder of staged tools. Then register the binary with your MCP client as
below. If the box should be anything looser than `Critical`, drop a signed
`policy.json` first (see **Safety policy**).

## Safety policy

The box's **risk class** is set by an operator-deployed policy, never by the
agent. It is read once at startup from an admin-only location and, if
absent/malformed/unverified, fails safe to `Critical`.

- **Location:** `%ProgramData%\Heisenberg\policy.json`, or the path in
  `HEISENBERG_POLICY`.
- **Format:** `{ "class": "sandbox" | "development" | "production" | "critical",
  "overrides": { "<tool>": "allow" | "confirm-token" | "human-approval" | "deny" } }`
- **Trust:** a policy is trusted only when a detached ed25519 signature
  (`policy.json.sig`) verifies against a trusted public key — otherwise it is
  `Unverified` and clamped to `Critical`. The key comes from
  `HEISENBERG_TRUSTED_KEY`, a compile-time `HEISENBERG_TRUSTED_KEY_B64`, or
  `%ProgramData%\Heisenberg\trusted_key.pub`. `HEISENBERG_TRUST_UNSIGNED=1` is a
  dev/test escape hatch only.

  ```powershell
  heisenberg keygen                       # prints a public + private key
  heisenberg sign policy.json priv.key    # writes policy.json.sig
  heisenberg approve <tool>               # one-shot human approval (Critical boxes, 15 min)
  ```

Gate matrix (box class × effect tier):

| class \ tier | read-only | state-changing | machine-disrupting |
|--------------|-----------|----------------|--------------------|
| sandbox      | allow     | allow          | allow              |
| development  | allow     | allow          | confirm-token      |
| production   | allow     | confirm-token  | human-approval     |
| critical     | allow     | human-approval | human-approval     |

## Tool-call log

Every tool-call *result* is appended (one compact JSON object per line) to
`<state-root>\calls.jsonl` — `ts`, `tool`, `ok`, `summary`, `error`, `command`,
and any `artifacts`. Tail it to watch results stream in live:

```powershell
Get-Content "$env:ProgramData\Heisenberg\calls.jsonl" -Wait
```

The recent tail is also exposed over MCP as the `heisenberg://calls` resource.

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
