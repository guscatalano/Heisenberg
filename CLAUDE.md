# Heisenberg — contributor & agent guide

Windows-only MCP server that makes native debugging easy for an agent, wrapping
only free Microsoft-published tools and citing public docs. Rust + `rmcp` over
stdio. Full design plan: <https://claude.ai/code/artifact/00a8d7df-6da0-4f1b-a9f9-2cb877dbffc2>

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

## Module map

- `server.rs` — the MCP surface: all tools + resources. `AppState` holds the
  policy, tool locator, and the ledger/dumps/jobs/audit stores.
- `policy.rs` — box class × effect tier → gate matrix; fail-safe to Critical.
- `gate.rs` — enforcement (`enforce`) that mutating tools call before acting.
- `ledger.rs` — reversible-change ledger; `RevertPlan` variants per change kind.
- `audit.rs`, `jobs.rs`, `dumps.rs`, `store.rs` — persisted state.
- `env_probe.rs`, `proc.rs`, `regutil.rs`, `session.rs`, `kernel.rs` — the Win32
  work (via the `windows` crate) and registry helpers.
- `tools.rs` — external-tool locator; `docs.rs` — public-doc links; `envelope.rs`
  — the uniform result/error envelope.

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

- Public Microsoft tools only; every tool carries a `docsUrl`.
- The agent can never change the box class through the protocol.
- Every machine mutation is reversible via the ledger, or clearly marked Manual.
- Full dumps/traces are tagged sensitive; warn before anything leaves the box.
