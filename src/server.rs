//! The MCP server surface. Phase 1 gave the foundation (`env.check`, policy view,
//! `gate.check`, resources). Phase 2 adds the safety spine's teeth: the change
//! ledger, audit journal, gate *enforcement*, and a first reversible tool
//! (`symbols.configure`) that exercises the whole path.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler};
use serde::Deserialize;
use serde_json::json;
use tokio::process::Command;

use crate::audit::Audit;
use crate::dumps::DumpRegistry;
use crate::envelope::{error, Artifact, ErrorKind, Outcome};
use crate::ledger::{ChangeStatus, Ledger, RevertPlan};
use crate::policy::{base_gate, BoxClass, EffectTier, Policy};
use crate::store::Store;
use crate::tools::Locator;
use crate::{docs, env_probe, gate, proc, regutil};

const SYMBOLS_TOKEN: &str = "set-symbol-path";
const SYMBOL_PATH_DOCS: &str =
    "https://learn.microsoft.com/windows-hardware/drivers/debugger/symbol-path";

const GFLAGS_TOKEN: &str = "set-gflags";
const GFLAGS_DOCS: &str =
    "https://learn.microsoft.com/windows-hardware/drivers/debugger/gflags-and-pageheap";
/// FLG_HEAP_PAGE_ALLOCS ("hpa") in the IFEO GlobalFlag.
const FLG_HEAP_PAGE_ALLOCS: u32 = 0x0200_0000;
/// PageHeapFlags value for *full* page heap.
const PAGE_HEAP_FULL: u32 = 0x3;

/// Shared server state: the immutable policy plus the on-disk ledger and audit.
pub struct AppState {
    pub policy: Policy,
    pub store: Store,
    pub locator: Locator,
    pub ledger: Mutex<Ledger>,
    pub dumps: Mutex<DumpRegistry>,
    pub audit: Audit,
}

impl AppState {
    pub fn new(policy: Policy) -> Self {
        let store = Store::discover();
        let ledger = Ledger::load(store.ledger_path());
        let dumps = DumpRegistry::load(store.dumps_path());
        let audit = Audit::open(store.audit_path());
        AppState {
            policy,
            locator: Locator::discover(),
            ledger: Mutex::new(ledger),
            dumps: Mutex::new(dumps),
            audit,
            store,
        }
    }
}

#[derive(Clone)]
pub struct Heisenberg {
    state: Arc<AppState>,
    #[allow(dead_code)] // read by the generated ServerHandler (tool_handler macro).
    tool_router: ToolRouter<Heisenberg>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GateCheckArgs {
    /// The tool to test, e.g. "gflags.set" or "kernel.forceBugcheck".
    pub tool: String,
    /// Effect tier: "read-only", "state-changing", or "machine-disrupting".
    pub tier: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SymbolsConfigureArgs {
    /// New _NT_SYMBOL_PATH, e.g. "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols".
    pub path: String,
    /// Preview the commands and before/after without changing anything.
    #[serde(default)]
    pub dry_run: bool,
    /// Confirm token naming the effect ("set-symbol-path") when the box requires one.
    #[serde(default)]
    pub confirm: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ChangesRevertArgs {
    /// The change id to undo (from changes.list).
    pub id: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DumpCaptureArgs {
    /// Target process id (preferred — unambiguous).
    #[serde(default)]
    pub pid: Option<u32>,
    /// Target process name, e.g. "notepad.exe". Rejected if it matches many.
    #[serde(default)]
    pub name: Option<String>,
    /// Full-memory dump (default) vs a minidump.
    #[serde(default = "default_true")]
    pub full: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DumpAnalyzeArgs {
    /// A dump id from dump.capture (or heisenberg://dumps/<id>), or a file path.
    pub dump: String,
    /// Optional cdb command string (default: "!analyze -v; ~*k; lm t; q").
    #[serde(default)]
    pub commands: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GflagsGetArgs {
    /// Image name, e.g. "myapp.exe".
    pub image: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GflagsSetArgs {
    /// Image name, e.g. "myapp.exe".
    pub image: String,
    /// Preview the change without writing anything.
    #[serde(default)]
    pub dry_run: bool,
    /// Confirm token ("set-gflags") when the box requires one.
    #[serde(default)]
    pub confirm: Option<String>,
}

fn comsvcs_path() -> std::path::PathBuf {
    let sr = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    std::path::PathBuf::from(sr).join("System32").join("comsvcs.dll")
}

/// Pull a handful of well-known fields out of cdb's `!analyze -v` text.
fn parse_analysis(raw: &str) -> serde_json::Value {
    let grab = |key: &str| -> Option<String> {
        raw.lines().find_map(|l| {
            l.trim()
                .strip_prefix(key)
                .map(|rest| rest.trim().to_string())
                .filter(|s| !s.is_empty())
        })
    };
    json!({
        "exceptionCode": grab("ExceptionCode:"),
        "faultingModule": grab("MODULE_NAME:").or_else(|| grab("FAULTING_MODULE:")),
        "faultingIp": grab("FAULTING_IP:"),
        "processName": grab("PROCESS_NAME:"),
        "failureBucket": grab("FAILURE_BUCKET_ID:"),
        "bugcheck": grab("BUGCHECK_CODE:"),
    })
}

fn last_chars(s: &str, n: usize) -> String {
    let v: Vec<char> = s.chars().collect();
    if v.len() <= n {
        s.to_string()
    } else {
        v[v.len() - n..].iter().collect()
    }
}

fn parse_tier(s: &str) -> Option<EffectTier> {
    match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "read-only" | "readonly" | "ro" => Some(EffectTier::ReadOnly),
        "state-changing" | "statechanging" | "sc" => Some(EffectTier::StateChanging),
        "machine-disrupting" | "machinedisrupting" | "md" => Some(EffectTier::MachineDisrupting),
        _ => None,
    }
}

fn text(v: serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(&v).unwrap_or_default(),
    )])
}

fn gate_matrix() -> serde_json::Value {
    let classes = [
        BoxClass::Sandbox,
        BoxClass::Development,
        BoxClass::Production,
        BoxClass::Critical,
    ];
    let tiers = [
        EffectTier::ReadOnly,
        EffectTier::StateChanging,
        EffectTier::MachineDisrupting,
    ];
    let mut rows = serde_json::Map::new();
    for c in classes {
        let mut row = serde_json::Map::new();
        for t in tiers {
            let tkey = serde_json::to_value(t).unwrap();
            row.insert(
                tkey.as_str().unwrap_or("?").to_string(),
                serde_json::to_value(base_gate(c, t)).unwrap(),
            );
        }
        let ckey = serde_json::to_value(c).unwrap();
        rows.insert(ckey.as_str().unwrap_or("?").to_string(), row.into());
    }
    rows.into()
}

#[tool_router]
impl Heisenberg {
    pub fn new(policy: Policy) -> Self {
        Self {
            state: Arc::new(AppState::new(policy)),
            tool_router: Self::tool_router(),
        }
    }

    fn env_report_json(&self) -> serde_json::Value {
        let report = env_probe::probe();
        let summary = format!(
            "{} build {}, {}, session {}{}",
            report.os.name,
            report.os.build,
            report.arch.native_arch,
            report.session_id,
            if report.is_system {
                ", SYSTEM"
            } else if report.is_admin {
                ", elevated"
            } else {
                ""
            }
        );
        let data = serde_json::to_value(&report).unwrap_or_else(|_| json!({}));
        Outcome::new("env.check", summary)
            .data(data)
            .docs("https://learn.microsoft.com/sysinternals/")
            .to_value()
    }

    fn policy_json(&self) -> serde_json::Value {
        let policy = &self.state.policy;
        let class = policy.effective_class();
        let data = json!({
            "declaredClass": policy.class,
            "effectiveClass": class,
            "source": policy.source,
            "overrides": policy.overrides,
            "gateMatrix": gate_matrix(),
        });
        Outcome::new(
            "policy.show",
            format!(
                "effective class: {:?} (source: {}, {:?})",
                class, policy.source.origin, policy.source.trust
            ),
        )
        .data(data)
        .to_value()
    }

    fn changes_json(&self) -> serde_json::Value {
        let l = self.state.ledger.lock().unwrap();
        json!({ "changes": l.list() })
    }

    #[tool(
        name = "env.check",
        description = "Probe the machine: OS build/edition, architecture (incl. WOW64), integrity level, privileges (SeDebug/SeTcb), session id, and derived capabilities. Read-only."
    )]
    async fn env_check(&self) -> Result<CallToolResult, McpError> {
        Ok(text(self.env_report_json()))
    }

    #[tool(
        name = "policy.show",
        description = "Show the effective box class, its source and trust, per-tool overrides, and the full gate matrix (box class x effect tier). Read-only."
    )]
    async fn policy_show(&self) -> Result<CallToolResult, McpError> {
        Ok(text(self.policy_json()))
    }

    #[tool(
        name = "gate.check",
        description = "Ask the policy what gate a given tool + effect tier would face on this box (allow / confirm-token / human-approval / deny), without running anything."
    )]
    async fn gate_check(
        &self,
        Parameters(args): Parameters<GateCheckArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = match parse_tier(&args.tier) {
            Some(tier) => {
                let decision = self.state.policy.decide(&args.tool, tier);
                Outcome::new(
                    "gate.check",
                    format!("{} [{:?}] -> {:?}", decision.tool, decision.tier, decision.gate),
                )
                .data(serde_json::to_value(&decision).unwrap_or_else(|_| json!({})))
                .to_value()
            }
            None => error(
                "gate.check",
                ErrorKind::InvalidArgument,
                format!("unknown effect tier '{}'", args.tier),
                "use one of: read-only, state-changing, machine-disrupting",
                None,
            ),
        };
        Ok(text(v))
    }

    #[tool(
        name = "symbols.show",
        description = "Show the current _NT_SYMBOL_PATH (from the user environment). Read-only."
    )]
    async fn symbols_show(&self) -> Result<CallToolResult, McpError> {
        let cur = regutil::get_hkcu_env("_NT_SYMBOL_PATH");
        let summary = match &cur {
            Some(p) => format!("_NT_SYMBOL_PATH = {p}"),
            None => "_NT_SYMBOL_PATH is unset".to_string(),
        };
        let v = Outcome::new("symbols.show", summary)
            .data(json!({ "path": cur }))
            .docs(SYMBOL_PATH_DOCS)
            .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "symbols.configure",
        description = "Set _NT_SYMBOL_PATH in the user environment (state-changing, reversible via the ledger). Supports dry_run; needs a confirm token on Production, human approval on Critical."
    )]
    async fn symbols_configure(
        &self,
        Parameters(a): Parameters<SymbolsConfigureArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "symbols.configure";
        let prior = regutil::get_hkcu_env("_NT_SYMBOL_PATH");
        let cmd = format!("setx _NT_SYMBOL_PATH \"{}\"", a.path);

        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            self.state
                .audit
                .record(tool, "dry-run", Some(&format!("{:?}", decision.gate)), "dry-run", None);
            let v = Outcome::new(
                tool,
                format!("[dry-run] would set _NT_SYMBOL_PATH (gate: {:?})", decision.gate),
            )
            .data(json!({ "path": a.path, "prior": prior, "gate": decision }))
            .command(cmd)
            .docs(SYMBOL_PATH_DOCS)
            .warn("dry-run: no change made")
            .to_value();
            return Ok(text(v));
        }

        let decision = match gate::enforce(
            &self.state.policy,
            tool,
            EffectTier::StateChanging,
            SYMBOLS_TOKEN,
            a.confirm.as_deref(),
        ) {
            Ok(d) => d,
            Err(b) => {
                self.state
                    .audit
                    .record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None);
                return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(SYMBOL_PATH_DOCS))));
            }
        };

        // Record the inverse *before* applying.
        let id = {
            let mut l = self.state.ledger.lock().unwrap();
            l.begin(
                tool,
                &format!("set _NT_SYMBOL_PATH to {}", a.path),
                RevertPlan::HkcuEnv {
                    name: "_NT_SYMBOL_PATH".to_string(),
                    prior: prior.clone(),
                },
            )
        };

        match regutil::set_hkcu_env("_NT_SYMBOL_PATH", &a.path) {
            Ok(()) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
                self.state.audit.record(
                    tool,
                    &format!("set _NT_SYMBOL_PATH to {}", a.path),
                    Some(&format!("{:?}", decision.gate)),
                    "applied",
                    Some(&id),
                );
                let v = Outcome::new(
                    tool,
                    format!(
                        "set _NT_SYMBOL_PATH (was {}); change {}",
                        prior.as_deref().unwrap_or("<unset>"),
                        id
                    ),
                )
                .data(json!({ "path": a.path, "prior": prior, "changeId": id }))
                .command(cmd)
                .docs(SYMBOL_PATH_DOCS)
                .warn("new/restarted processes pick this up; already-running processes keep the old value")
                .to_value();
                Ok(text(v))
            }
            Err(e) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
                self.state.audit.record(
                    tool,
                    &format!("apply failed: {e}"),
                    Some(&format!("{:?}", decision.gate)),
                    "failed",
                    Some(&id),
                );
                Ok(text(error(
                    tool,
                    ErrorKind::Internal,
                    format!("failed to set registry value: {e}"),
                    "check HKCU\\Environment permissions",
                    Some(SYMBOL_PATH_DOCS),
                )))
            }
        }
    }

    #[tool(
        name = "changes.list",
        description = "List the reversible-change ledger: every state mutation this server made, its status, and how to undo it. Read-only."
    )]
    async fn changes_list(&self) -> Result<CallToolResult, McpError> {
        let (count, data) = {
            let l = self.state.ledger.lock().unwrap();
            (l.list().len(), json!({ "changes": l.list() }))
        };
        let v = Outcome::new("changes.list", format!("{count} change(s) recorded"))
            .data(data)
            .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "changes.revert",
        description = "Undo a change by id (from changes.list) using its recorded inverse. Reverting is always allowed."
    )]
    async fn changes_revert(
        &self,
        Parameters(a): Parameters<ChangesRevertArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "changes.revert";
        let result = {
            let mut l = self.state.ledger.lock().unwrap();
            l.revert(&a.id)
        };
        let v = match result {
            Ok(c) => {
                self.state
                    .audit
                    .record(tool, &format!("reverted {}", a.id), Some("Allow"), "reverted", Some(&a.id));
                Outcome::new(tool, format!("reverted change {} ({})", c.id, c.summary))
                    .data(json!({ "change": c }))
                    .to_value()
            }
            Err(e) => {
                self.state
                    .audit
                    .record(tool, &format!("revert failed: {e}"), Some("Allow"), "failed", Some(&a.id));
                error(
                    tool,
                    ErrorKind::InvalidArgument,
                    format!("{e}"),
                    "check the id via changes.list",
                    None,
                )
            }
        };
        Ok(text(v))
    }

    #[tool(
        name = "tools.list",
        description = "Inventory the external tools Heisenberg drives: which are found (with path) and which are missing, each with its doc link. Read-only."
    )]
    async fn tools_list(&self) -> Result<CallToolResult, McpError> {
        let inv = self.state.locator.inventory();
        let found = inv.iter().filter(|t| t["found"] == json!(true)).count();
        let v = Outcome::new("tools.list", format!("{}/{} known tools found", found, inv.len()))
            .data(json!({ "tools": inv }))
            .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "dump.capture",
        description = "Capture a user-mode process dump (full by default, or mini) by pid or name. Auto-selects ProcDump if staged, else comsvcs MiniDump. Read-only; disk pre-checked. Full dumps are marked high-sensitivity."
    )]
    async fn dump_capture(
        &self,
        Parameters(a): Parameters<DumpCaptureArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "dump.capture";
        let docs = "https://learn.microsoft.com/sysinternals/downloads/procdump";

        let pid = match proc::resolve(a.pid, a.name.as_deref()) {
            Ok(p) => p,
            Err(proc::TargetError::NotFound(m)) => {
                self.state.audit.record(tool, &format!("target not found: {m}"), None, "error", None);
                return Ok(text(error(
                    tool,
                    ErrorKind::TargetNotFound,
                    format!("no process matched {m}"),
                    "pass a valid pid or an exact process name",
                    Some(docs),
                )));
            }
            Err(proc::TargetError::Ambiguous { name, pids }) => {
                self.state.audit.record(tool, &format!("ambiguous target {name}"), None, "error", None);
                let mut v = error(
                    tool,
                    ErrorKind::AmbiguousTarget,
                    format!("'{name}' matches {} processes", pids.len()),
                    "re-call with a specific pid",
                    Some(docs),
                );
                v["error"]["candidates"] = json!(pids);
                return Ok(text(v));
            }
        };

        // Disk pre-check: estimate from the target's working set.
        let dir = self.state.store.artifacts_dir();
        let est = proc::working_set(pid).unwrap_or(64 * 1024 * 1024);
        let need = if a.full {
            est + est / 2 + 16 * 1024 * 1024
        } else {
            32 * 1024 * 1024
        };
        if let Some(free) = proc::free_bytes(&dir) {
            if free < need {
                return Ok(text(error(
                    tool,
                    ErrorKind::InsufficientDiskSpace,
                    format!("need ~{} MB, only {} MB free", need / 1048576, free / 1048576),
                    "free space or point HEISENBERG_HOME at another drive",
                    Some(docs),
                )));
            }
        }

        let kind = if a.full { "full" } else { "mini" };
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let outpath = dir.join(format!("pid{pid}_{ts}.dmp"));

        let mut warnings: Vec<String> = Vec::new();
        let (backend, cmd_str, mut cmd) = if let Some(pd) = self.state.locator.find("procdump.exe") {
            let mode = if a.full { "-ma" } else { "-mp" };
            let s = format!("{} -accepteula {} {} \"{}\"", pd.display(), mode, pid, outpath.display());
            let mut c = Command::new(&pd);
            c.args(["-accepteula", mode]).arg(pid.to_string()).arg(&outpath);
            ("procdump", s, c)
        } else {
            let comsvcs = comsvcs_path();
            if !a.full {
                warnings.push("comsvcs MiniDump writes a full dump; 'mini' was upgraded to full".to_string());
            }
            let s = format!("rundll32.exe {},MiniDump {} \"{}\" full", comsvcs.display(), pid, outpath.display());
            let mut c = Command::new("rundll32.exe");
            c.arg(format!("{},MiniDump", comsvcs.display()))
                .arg(pid.to_string())
                .arg(&outpath)
                .arg("full");
            ("comsvcs", s, c)
        };

        let output = match tokio::time::timeout(Duration::from_secs(180), cmd.output()).await {
            Err(_) => {
                self.state.audit.record(tool, "capture timed out", None, "timeout", None);
                return Ok(text(error(
                    tool,
                    ErrorKind::Timeout,
                    "dump capture timed out after 180s",
                    "retry, or capture a mini dump",
                    Some(docs),
                )));
            }
            Ok(Err(e)) => {
                return Ok(text(error(
                    tool,
                    ErrorKind::Internal,
                    format!("failed to launch {backend}: {e}"),
                    "check the backend tool is present",
                    Some(docs),
                )));
            }
            Ok(Ok(o)) => o,
        };

        if !output.status.success() || !outpath.is_file() {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let denied = combined.to_ascii_lowercase().contains("access is denied");
            let (kinderr, remedy) = if denied {
                (
                    ErrorKind::AccessDenied,
                    "run elevated (SeDebugPrivilege) to dump another user/session or protected process",
                )
            } else {
                (ErrorKind::AnalysisFailed, "check the target pid and that the backend can dump it")
            };
            self.state.audit.record(tool, &format!("capture failed via {backend}"), None, "failed", None);
            let mut v = error(tool, kinderr, format!("{backend} failed to capture pid {pid}"), remedy, Some(docs));
            v["error"]["output"] = json!(combined.trim());
            return Ok(text(v));
        }

        let bytes = std::fs::metadata(&outpath).map(|m| m.len()).unwrap_or(0);
        let rec = {
            let mut reg = self.state.dumps.lock().unwrap();
            reg.add(outpath.display().to_string(), pid, kind, backend, bytes)
        };
        self.state.audit.record(
            tool,
            &format!("captured {kind} dump of pid {pid} ({bytes} bytes)"),
            None,
            "captured",
            Some(&rec.id),
        );

        let mut out = Outcome::new(
            tool,
            format!(
                "captured {kind} dump of pid {pid} via {backend} ({:.1} MB)",
                bytes as f64 / 1048576.0
            ),
        )
        .data(json!({
            "pid": pid, "kind": kind, "backend": backend,
            "bytes": bytes, "path": outpath.display().to_string(), "dumpId": rec.id
        }))
        .artifact(Artifact {
            kind: "dump".to_string(),
            path: outpath.display().to_string(),
            bytes,
            resource: format!("heisenberg://dumps/{}", rec.id),
            sensitivity: Some(rec.sensitivity.clone()),
        })
        .command(cmd_str)
        .docs(docs);
        if rec.sensitivity == "high" {
            out = out.warn(
                "full dump may contain passwords/keys/PII; treat as high-sensitivity and do not transfer off-box unreviewed",
            );
        }
        for w in warnings {
            out = out.warn(w);
        }
        Ok(text(out.to_value()))
    }

    #[tool(
        name = "dump.analyze",
        description = "Open a user-mode dump in cdb and run analysis (default: !analyze -v, all-thread stacks, modules). Accepts a dump id from dump.capture or a file path. Read-only; needs cdb from the Debugging Tools for Windows."
    )]
    async fn dump_analyze(
        &self,
        Parameters(a): Parameters<DumpAnalyzeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "dump.analyze";
        let docs = "https://learn.microsoft.com/windows-hardware/drivers/debugger/";

        let path = {
            let reg = self.state.dumps.lock().unwrap();
            let id = a.dump.trim_start_matches("heisenberg://dumps/");
            reg.get(id).map(|r| r.path.clone()).unwrap_or_else(|| a.dump.clone())
        };
        if !std::path::Path::new(&path).is_file() {
            return Ok(text(error(
                tool,
                ErrorKind::TargetNotFound,
                format!("no dump at {path}"),
                "capture one with dump.capture, or pass a valid file path",
                Some(docs),
            )));
        }

        let cdb = match self.state.locator.find("cdb.exe") {
            Some(p) => p,
            None => {
                let mut v = error(
                    tool,
                    ErrorKind::ToolNotInstalled,
                    "cdb.exe not found",
                    "install the Debugging Tools for Windows (winget install Microsoft.WinDbg) or stage it in --tools-dir",
                    Some(docs),
                );
                v["error"]["wingetId"] = json!("Microsoft.WinDbg");
                return Ok(text(v));
            }
        };

        let sympath = regutil::get_hkcu_env("_NT_SYMBOL_PATH").unwrap_or_else(|| {
            format!(
                "srv*{}*https://msdl.microsoft.com/download/symbols",
                self.state.store.root.join("symbols").display()
            )
        });
        let cmds = a
            .commands
            .clone()
            .unwrap_or_else(|| "!analyze -v; ~*k; lm t; q".to_string());
        let cmd_str = format!(
            "{} -z \"{}\" -y \"{}\" -c \"{}\"",
            cdb.display(),
            path,
            sympath,
            cmds
        );

        let mut c = Command::new(&cdb);
        c.arg("-z").arg(&path).arg("-y").arg(&sympath).arg("-c").arg(&cmds);
        let output = match tokio::time::timeout(Duration::from_secs(300), c.output()).await {
            Err(_) => {
                return Ok(text(error(
                    tool,
                    ErrorKind::Timeout,
                    "cdb analysis timed out after 300s (symbol download can be slow)",
                    "retry once symbols are cached, or pass a narrower command set",
                    Some(docs),
                )))
            }
            Ok(Err(e)) => {
                return Ok(text(error(
                    tool,
                    ErrorKind::Internal,
                    format!("failed to launch cdb: {e}"),
                    "check the cdb path",
                    Some(docs),
                )))
            }
            Ok(Ok(o)) => o,
        };

        let raw = String::from_utf8_lossy(&output.stdout).to_string();
        let parsed = parse_analysis(&raw);
        let sym_missing = raw.contains("symbols could not be loaded")
            || raw.contains("Symbol file could not be found");
        let mut out = Outcome::new(tool, format!("analyzed {path}"))
            .data(json!({ "path": path, "parsed": parsed, "raw": last_chars(&raw, 8000) }))
            .command(cmd_str)
            .docs(docs);
        if sym_missing {
            out = out.warn("some symbols could not be loaded; stacks may be incomplete");
        }
        self.state.audit.record(tool, &format!("analyzed {path}"), None, "analyzed", None);
        Ok(text(out.to_value()))
    }

    #[tool(
        name = "gflags.get",
        description = "Show the IFEO GlobalFlag / PageHeapFlags for an image (e.g. \"myapp.exe\") — i.e. whether full page heap is enabled. Read-only."
    )]
    async fn gflags_get(
        &self,
        Parameters(a): Parameters<GflagsGetArgs>,
    ) -> Result<CallToolResult, McpError> {
        let (gf, ph, exists) = regutil::ifeo_read(&a.image);
        let full = ph == Some(PAGE_HEAP_FULL)
            && gf.map(|g| g & FLG_HEAP_PAGE_ALLOCS != 0).unwrap_or(false);
        let state = if full {
            "FULL"
        } else if exists {
            "partial/other"
        } else {
            "off"
        };
        let v = Outcome::new("gflags.get", format!("{}: page heap {state}", a.image))
            .data(json!({
                "image": a.image, "keyExists": exists,
                "globalFlag": gf, "pageHeapFlags": ph, "fullPageHeap": full
            }))
            .docs(GFLAGS_DOCS)
            .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "gflags.set",
        description = "Enable full page heap for an image via IFEO (state-changing, reversible via the ledger; needs elevation). Supports dry_run; confirm token on Production, human approval on Critical. Disable by reverting the change."
    )]
    async fn gflags_set(
        &self,
        Parameters(a): Parameters<GflagsSetArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "gflags.set";
        let image = a.image.clone();
        let (prior_gf, prior_ph, exists) = regutil::ifeo_read(&image);
        let cmd = format!("gflags /p /enable {image} /full");

        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            self.state.audit.record(tool, "dry-run", Some(&format!("{:?}", decision.gate)), "dry-run", None);
            let v = Outcome::new(
                tool,
                format!("[dry-run] would enable full page heap for {image} (gate: {:?})", decision.gate),
            )
            .data(json!({
                "image": image,
                "prior": { "globalFlag": prior_gf, "pageHeapFlags": prior_ph },
                "wouldSet": { "globalFlag": FLG_HEAP_PAGE_ALLOCS, "pageHeapFlags": PAGE_HEAP_FULL },
                "gate": decision
            }))
            .command(cmd)
            .docs(GFLAGS_DOCS)
            .warn("dry-run: no change made")
            .to_value();
            return Ok(text(v));
        }

        if !env_probe::is_elevated() {
            self.state.audit.record(tool, "not elevated", None, "blocked", None);
            return Ok(text(error(
                tool,
                ErrorKind::RequiresElevation,
                "writing IFEO page-heap flags needs an elevated (admin) token",
                "re-run Heisenberg elevated, or via the elevated broker",
                Some(GFLAGS_DOCS),
            )));
        }

        let decision = match gate::enforce(
            &self.state.policy,
            tool,
            EffectTier::StateChanging,
            GFLAGS_TOKEN,
            a.confirm.as_deref(),
        ) {
            Ok(d) => d,
            Err(b) => {
                self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None);
                return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(GFLAGS_DOCS))));
            }
        };

        let id = {
            let mut l = self.state.ledger.lock().unwrap();
            l.begin(
                tool,
                &format!("enable full page heap for {image}"),
                RevertPlan::IfeoFlags {
                    image: image.clone(),
                    prior_global_flag: prior_gf,
                    prior_page_heap: prior_ph,
                    created_key: !exists,
                },
            )
        };

        match regutil::ifeo_write(&image, FLG_HEAP_PAGE_ALLOCS, PAGE_HEAP_FULL) {
            Ok(_) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
                self.state.audit.record(
                    tool,
                    &format!("enabled full page heap for {image}"),
                    Some(&format!("{:?}", decision.gate)),
                    "applied",
                    Some(&id),
                );
                let v = Outcome::new(tool, format!("enabled full page heap for {image}; change {id}"))
                    .data(json!({
                        "image": image, "globalFlag": FLG_HEAP_PAGE_ALLOCS,
                        "pageHeapFlags": PAGE_HEAP_FULL, "changeId": id
                    }))
                    .command(cmd)
                    .docs(GFLAGS_DOCS)
                    .warn("full page heap sharply increases the target's memory use and can stop it starting; revert with changes.revert when done")
                    .to_value();
                Ok(text(v))
            }
            Err(e) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
                let (kind, remedy) = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    (ErrorKind::RequiresElevation, "re-run elevated to write IFEO")
                } else {
                    (ErrorKind::Internal, "check the image name and HKLM IFEO permissions")
                };
                self.state.audit.record(tool, &format!("apply failed: {e}"), None, "failed", Some(&id));
                Ok(text(error(
                    tool,
                    kind,
                    format!("failed to write IFEO for {image}: {e}"),
                    remedy,
                    Some(GFLAGS_DOCS),
                )))
            }
        }
    }
}

#[tool_handler]
impl ServerHandler for Heisenberg {
    fn get_info(&self) -> ServerConfig {
        let mut info = Implementation::from_build_env();
        info.name = "heisenberg".to_string();
        info.version = env!("CARGO_PKG_VERSION").to_string();
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .build(),
        )
        .with_server_info(info)
        .with_instructions(
            "Heisenberg makes Windows native debugging easy for an agent, wrapping only free \
             Microsoft-published tools. Start with env.check to learn what the box supports, and \
             gate.check to see what a proposed action would require. Mutating tools (e.g. \
             symbols.configure) are recorded in the change ledger and reversible via changes.revert."
                .to_string(),
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let mut resources = vec![
            Resource::new("heisenberg://env", "Machine capability snapshot".to_string()),
            Resource::new("heisenberg://policy", "Effective safety policy".to_string()),
            Resource::new("heisenberg://changes", "Reversible-change ledger".to_string()),
            Resource::new("heisenberg://audit", "Audit journal (recent entries)".to_string()),
            Resource::new("heisenberg://dumps", "Captured dumps".to_string()),
            Resource::new("heisenberg://tools", "External tool inventory".to_string()),
        ];
        for (key, name, _, _) in docs::DOCS {
            resources.push(Resource::new(
                format!("docs://{key}"),
                format!("Docs: {name}"),
            ));
        }
        Ok(ListResourcesResult {
            resources,
            ..Default::default()
        })
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(ListResourceTemplatesResult {
            resource_templates: Vec::new(),
            ..Default::default()
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        let uri = request.uri.clone();
        let text_body = match uri.as_str() {
            "heisenberg://env" => serde_json::to_string_pretty(&self.env_report_json()).ok(),
            "heisenberg://policy" => serde_json::to_string_pretty(&self.policy_json()).ok(),
            "heisenberg://changes" => serde_json::to_string_pretty(&self.changes_json()).ok(),
            "heisenberg://audit" => {
                serde_json::to_string_pretty(&json!({ "entries": self.state.audit.tail(200) })).ok()
            }
            "heisenberg://dumps" => {
                let reg = self.state.dumps.lock().unwrap();
                serde_json::to_string_pretty(&json!({ "dumps": reg.list() })).ok()
            }
            "heisenberg://tools" => {
                serde_json::to_string_pretty(&json!({ "tools": self.state.locator.inventory() })).ok()
            }
            other if other.starts_with("heisenberg://dumps/") => {
                let id = &other["heisenberg://dumps/".len()..];
                let reg = self.state.dumps.lock().unwrap();
                reg.get(id).map(|r| serde_json::to_string_pretty(r).unwrap_or_default())
            }
            other if other.starts_with("docs://") => {
                let key = &other["docs://".len()..];
                docs::lookup(key).map(|(k, name, url, summary)| {
                    serde_json::to_string_pretty(&json!({
                        "key": k, "name": name, "url": url, "summary": summary
                    }))
                    .unwrap_or_default()
                })
            }
            _ => None,
        };

        match text_body {
            Some(t) => Ok(ReadResourceResult::new(vec![ResourceContents::text(t, uri)]).into()),
            None => Err(McpError::resource_not_found(
                "resource_not_found",
                Some(json!({ "uri": uri })),
            )),
        }
    }
}
