# Heisenberg — contributor & agent guide

Windows-only MCP server that makes native debugging easy for an agent, wrapping
free debugging tools (Microsoft-published by default, plus opt-in third-party
helpers like cv2pdb) and citing public docs. Rust + `rmcp` over stdio.

## Build / test / lint

```powershell
cargo build              # debug
cargo build --release    # single static-CRT binary -> target\release\heisenberg.exe
cargo test               # unit tests (policy, envelope, gate, jobs)
cargo clippy             # keep this clean
```

## Testing the live server

Run the smoke test: `python scripts/smoke.py` (after `cargo build`). It drives
the server the correct way — a **synchronous** stdio client (send a request, read
one response line, repeat). Piping all requests then closing stdin makes rmcp
cancel the last in-flight tool call, so a batch-and-EOF test drops responses.
The handshake is `initialize` → `notifications/initialized` → `tools/call`.

Useful env vars for testing:
- `HEISENBERG_HOME` — state root (ledger/audit/dumps/jobs/cases + artifacts).
- `HEISENBERG_POLICY` — path to the box policy JSON.
- `HEISENBERG_TRUST_UNSIGNED=1` — dev escape hatch to trust an unsigned policy
  (otherwise it clamps to Critical). Not for production.
- `HEISENBERG_TOOLS` — extra dirs to search for staged tools.
- `HEISENBERG_BACKUP_KEEP` — max retained *non-original* `binary.replace` backups
  (default 20; `0` = unlimited). The pristine original is always kept.
- `HEISENBERG_HTTP_ADDR` / `HEISENBERG_HTTP_TOKEN` — listen address (default
  `127.0.0.1:8787`) and bearer token for `heisenberg serve-http` (the HTTP MCP
  endpoint `/mcp` + web portal `/`). Token is generated + persisted if unset.
- `HEISENBERG_HTTP_ALLOW_REMOTE=1` — required to bind a **non-loopback** address
  (e.g. `0.0.0.0:8787`). Without it, `serve-http` refuses any non-loopback bind;
  with it, it binds and warns. Loopback is always allowed. A non-loopback bind also
  **drops the Host (anti-DNS-rebinding) allowlist** — the bearer token is the guard —
  so remote clients reaching the box by IP/DNS/proxy aren't 403'd.
- `HEISENBERG_HTTP_ALLOWED_HOSTS` — comma-separated Host/`host:port` allowlist to pin
  exactly which `Host` headers `/mcp` accepts (overrides the above). Loopback default
  is `localhost,127.0.0.1,::1`.

## Module map

- `server.rs` — the MCP surface: all tools + resources. `AppState` holds the
  policy, tool locator, and the ledger/dumps/jobs/audit stores.
- `policy.rs` — box class × effect tier → gate matrix; fail-safe to Critical.
- `gate.rs` — enforcement (`enforce`) that mutating tools call before acting.
- `ledger.rs` — reversible-change ledger; `RevertPlan` variants per change kind.
- `audit.rs`, `jobs.rs`, `dumps.rs`, `repro.rs`, `backup.rs`, `store.rs` — persisted
  state. `repro.rs` is the repro-recipe registry (`repro.record`/`repro.replay`);
  `backup.rs` is the versioned binary-replacement backup store + replace/restore
  mechanics (loaded-image rename, TrustedInstaller ownership) behind `binary.replace`.
- `env_probe.rs`, `proc.rs`, `regutil.rs`, `session.rs`, `kernel.rs`, `wct.rs` —
  the Win32 work (via the `windows` crate) and registry helpers. `wct.rs` wraps
  the Wait Chain Traversal API (live cross-process deadlock detection).
- `tools.rs` — external-tool locator; `docs.rs` — public-doc links; `envelope.rs`
  — the uniform result/error envelope.
- `controls.rs` — the "knob" catalog (stateful registry toggles) exposed at
  `heisenberg://controls` and flipped by the gated `control.set`. Built-in `KNOBS`
  (compiled) are merged with **user knobs** — an owned `UserKnobStore` persisted to
  `HEISENBERG_HOME\controls.json` that operators add/edit/import from the portal
  (`control.add` / `control.remove` / `control.import`). Those three only edit the
  catalog config, so they are **not** gated and **not** in the gate-lock test; the
  registry write still happens through `control.set` (elevation + gate + ledger), so
  a user knob is no more privileged than a built-in. `find_view`/`views` return an
  owned `KnobView` that unifies both sources; new built-ins are still added as data.
- `portal.rs` — opt-in HTTP surface (`heisenberg serve-http`): rmcp
  `StreamableHttpService` at `/mcp` + a bearer-gated, loopback-default web portal at
  `/` (an embedded SPA that drives `/mcp` as an MCP client — no separate dispatch, so
  the gate/ledger/audit still apply).

## Adding a tool (the pattern)

1. Define a `#[derive(Deserialize, schemars::JsonSchema)]` args struct.
2. Add an `async fn` with `#[tool(name = "group.verb", description = "...")]` on
   the `#[tool_router] impl Heisenberg` block; take `Parameters<Args>`.
3. Return `Ok(text(Outcome::new(...).data(...).command(...).docs(...).to_value()))`
   on success, or `text(error(tool, ErrorKind::..., msg, remedy, docs))` on
   failure. Never throw — always a typed envelope.
4. **Read-only** tools just run. **Mutating** tools must:
   - check `env_probe::is_elevated()` if they need admin (→ `RequiresElevation`),
   - call `gate::enforce(&self.state.policy, tool, tier, EFFECT_TOKEN, confirm)`
     and return its `Blocked` as an error,
   - record the inverse in the ledger via `ledger.begin(..., RevertPlan::...)`
     **before** applying, then `mark(Applied|Failed)`,
   - support a `dry_run` that previews `commands` + the decision,
   - `audit.record(...)` the outcome,
   - be added to the `mutating_tool_gate_set_is_locked` test (server.rs) — it
     locks the exact set of gated tools, so a new mutation won't compile-pass
     review until it's classified there.
5. Long-running captures register a `jobs` entry and stop via `do_stop` (add a
   `kind` arm); expose under `heisenberg://captures`.
6. A tool that writes a file via an external backend must treat the **produced
   file** as the source of truth, not the process exit code (ProcDump exits
   nonzero on success and renames the output). See `dump.capture`.

## Invariants

- Every wrapped tool carries a `docsUrl` and a vendor (`microsoft` | `third-party`,
  see `tools::vendor`). Microsoft tooling is always allowed; third-party tools
  (e.g. cv2pdb, groundhog) are allowed by default but can be locked out by a box
  whose policy sets `allow_third_party_tools: false` (enforced via
  `require_tool_allowed`).
- The agent can never change the box class through the protocol.
- Every machine mutation is reversible via the ledger, or clearly marked Manual.
- Full dumps/traces are tagged sensitive; warn before anything leaves the box.
