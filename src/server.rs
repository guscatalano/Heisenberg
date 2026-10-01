//! The MCP server surface. Phase 1 gave the foundation (`env.check`, policy view,
//! `gate.check`, resources). Phase 2 adds the safety spine's teeth: the change
//! ledger, audit journal, gate *enforcement*, and a first reversible tool
//! (`symbols.configure`) that exercises the whole path.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::handler::server::router::prompt::PromptRouter;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{
    prompt, prompt_handler, prompt_router, schemars, tool, tool_handler, tool_router,
    ErrorData as McpError, RoleServer, ServerHandler,
};
use serde::Deserialize;
use serde_json::json;
use tokio::process::Command;

use crate::approvals::Approvals;
use crate::audit::Audit;
use crate::dumps::DumpRegistry;
use crate::envelope::{error, Artifact, ErrorKind, Outcome};
use crate::jobs::{JobRegistry, JobState};
use crate::ledger::{ChangeStatus, Ledger, RevertPlan};
use crate::policy::{base_gate, BoxClass, EffectTier, Policy};
use crate::store::Store;
use crate::tools::Locator;
use crate::{docs, env_probe, gate, kernel, proc, regutil, session};

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

const PROCMON_DOCS: &str = "https://learn.microsoft.com/sysinternals/downloads/procmon";
const GROUNDHOG_DOCS: &str = "https://github.com/guscatalano/Groundhog";

const KERNEL_TOKEN: &str = "kernel-debug-setup";
const CRASHDUMP_TOKEN: &str = "set-crash-dump";
const KERNEL_DOCS: &str =
    "https://learn.microsoft.com/windows-hardware/drivers/debugger/setting-up-kernel-mode-debugging-in-windbg--cdb--or-ntsd";
const CRASHDUMP_DOCS: &str =
    "https://learn.microsoft.com/windows-hardware/drivers/debugger/enabling-a-kernel-mode-dump-file";

const WEVTUTIL_DOCS: &str =
    "https://learn.microsoft.com/windows-server/administration/windows-commands/wevtutil";
const WPR_DOCS: &str =
    "https://learn.microsoft.com/windows-hardware/test/wpt/windows-performance-recorder";

const SESSION_TOKEN: &str = "launch-in-user-session";
const SESSION_DOCS: &str =
    "https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw";

const TTD_DOCS: &str =
    "https://learn.microsoft.com/windows-hardware/drivers/debugger/time-travel-debugging-overview";
const DOTNET_DOCS: &str = "https://learn.microsoft.com/dotnet/core/diagnostics/dotnet-dump";

const AEDEBUG_TOKEN: &str = "set-postmortem-debugger";
const WER_TOKEN: &str = "set-wer-localdumps";
const AEDEBUG_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug";
const WER_LOCALDUMPS: &str = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps";
const POSTMORTEM_DOCS: &str =
    "https://learn.microsoft.com/windows/win32/wer/collecting-user-mode-dumps";

const APPVERIF_TOKEN: &str = "enable-appverifier";
const APPVERIF_DOCS: &str =
    "https://learn.microsoft.com/windows-hardware/drivers/devtest/application-verifier";
/// FLG_APPLICATION_VERIFIER in the IFEO GlobalFlag.
const FLG_APPLICATION_VERIFIER: u32 = 0x100;
/// FLG_USER_STACK_TRACE_DB ("ust") in the IFEO GlobalFlag — needed for UMDH.
const FLG_USER_STACK_TRACE_DB: u32 = 0x1000;

/// Shared server state: the immutable policy plus the on-disk ledger and audit.
pub struct AppState {
    pub policy: Policy,
    pub store: Store,
    pub locator: Locator,
    pub ledger: Mutex<Ledger>,
    pub dumps: Mutex<DumpRegistry>,
    pub jobs: Mutex<JobRegistry>,
    pub audit: Audit,
    /// Operator-added tool search folders (persisted); shared with the locator.
    pub extra_folders: Arc<Mutex<Vec<PathBuf>>>,
    pub folders_path: PathBuf,
    /// Out-of-band human-approval broker.
    pub approvals: Approvals,
    /// Live interactive cdb debug sessions (dump.open/command/close).
    pub sessions: crate::sessions::DebugSessions,
}

impl AppState {
    pub fn new(policy: Policy) -> Self {
        let store = Store::discover();
        let ledger = Ledger::load(store.ledger_path());
        let dumps = DumpRegistry::load(store.dumps_path());
        let jobs = JobRegistry::load(store.jobs_path());
        let audit = Audit::open(store.audit_path());
        let folders_path = store.folders_path();
        let folders: Vec<PathBuf> = std::fs::read(&folders_path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok())
            .unwrap_or_default()
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let extra_folders = Arc::new(Mutex::new(folders));
        AppState {
            policy,
            locator: Locator::discover(extra_folders.clone()),
            ledger: Mutex::new(ledger),
            dumps: Mutex::new(dumps),
            jobs: Mutex::new(jobs),
            audit,
            approvals: Approvals::load(store.approvals_path()),
            sessions: crate::sessions::DebugSessions::new(),
            extra_folders,
            folders_path,
            store,
        }
    }
}

fn save_folders(path: &std::path::Path, folders: &[PathBuf]) {
    let v: Vec<String> = folders.iter().map(|p| p.display().to_string()).collect();
    if let Err(e) = std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap_or_default()) {
        tracing::warn!("folders save failed: {e}");
    }
}

#[derive(Clone)]
pub struct Heisenberg {
    state: Arc<AppState>,
    #[allow(dead_code)] // read by the generated ServerHandler (tool_handler macro).
    tool_router: ToolRouter<Heisenberg>,
    #[allow(dead_code)] // read by the generated ServerHandler (prompt_handler macro).
    prompt_router: PromptRouter<Heisenberg>,
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

fn default_dbgsrv_port() -> u32 {
    5005
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PromptTargetArgs {
    /// Target for the playbook: a pid, process name, image name, or dump id/path
    /// (whichever the scenario needs).
    #[serde(default)]
    pub target: Option<String>,
}

fn default_dur() -> u64 {
    10
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DumpOpenArgs {
    /// Dump id (from dump.capture) or a file path to open interactively.
    pub dump: String,
    /// Symbol path (default: current _NT_SYMBOL_PATH, else the public server).
    #[serde(default)]
    pub sympath: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionCommandArgs {
    /// Session id from dump.open.
    pub session: String,
    /// A cdb command to run in the session (e.g. "k", "!analyze -v", "lm").
    pub command: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionIdArg {
    /// Session id from dump.open.
    pub session: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DotnetTimedArgs {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub name: Option<String>,
    /// Collection duration in seconds (default 10).
    #[serde(default = "default_dur")]
    pub duration_sec: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ForeignDumpArgs {
    /// Dump id (from dump.capture) or a file path — typically captured off-box.
    pub dump: String,
    /// Path to the matching image(s) for `.exepath+`.
    #[serde(default)]
    pub image_path: Option<String>,
    /// Symbol path for `.sympath` (e.g. a pre-seeded cache for that build).
    #[serde(default)]
    pub sym_path: Option<String>,
    /// cdb commands (default: "!analyze -v; lm; q").
    #[serde(default)]
    pub commands: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProvisionArgs {
    /// Groundhog profile or Groundhogfile path/URL (default: the windows-internals
    /// library — Sysinternals, WinDbg, WPT, symbols, crash dumps).
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirm: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ToolsInstallArgs {
    /// What to install: procdump, procmon, autoruns, psexec, sysinternals,
    /// windbg, windows-sdk, dotnet-dump, dotnet-gcdump, dotnet-trace.
    pub tool: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirm: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LeakDiffArgs {
    /// Baseline UMDH snapshot path (from leak.heapSnapshot).
    pub baseline: String,
    /// Later UMDH snapshot path to diff against the baseline.
    pub current: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BootTraceArgs {
    /// "arm" (configure a boot trace; needs reboot), "collect" (finalize after
    /// reboot), or "cancel".
    pub action: String,
    /// WPR profile for "arm" (default "GeneralProfile").
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub confirm: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RemoteLogArgs {
    /// Remote host name or IP.
    pub host: String,
    #[serde(default = "default_channel")]
    pub channel: String,
    #[serde(default = "default_count")]
    pub count: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RemoteDumpArgs {
    /// Remote host name or IP.
    pub host: String,
    /// Target pid on the remote host.
    #[serde(default)]
    pub pid: Option<u32>,
    /// Or target process name on the remote host.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub confirm: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RemoteServerArgs {
    /// TCP port for the process server (default 5005).
    #[serde(default = "default_dbgsrv_port")]
    pub port: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DumpOnTriggerArgs {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub name: Option<String>,
    /// Trigger: "unhandled" (default), "firstchance", "cpu", or "hang".
    #[serde(default)]
    pub on: Option<String>,
    /// CPU percent threshold for on="cpu" (default 80).
    #[serde(default)]
    pub threshold: Option<u32>,
    /// Full dump (default) vs mini.
    #[serde(default = "default_true")]
    pub full: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ServiceDebugArgs {
    /// Service executable image name, e.g. "myservice.exe".
    pub image: String,
    /// Debugger command line (default: cdb, if staged).
    #[serde(default)]
    pub debugger: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirm: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AppVerifierArgs {
    /// Image name, e.g. "myapp.exe".
    pub image: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirm: Option<String>,
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

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct ProcmonStartArgs {
    /// Optional process-name filter (not yet applied — recorded for now).
    #[serde(default)]
    pub process: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JobIdArgs {
    /// Job id from job.list / heisenberg://captures.
    pub id: String,
}

fn default_com() -> u32 {
    1
}
fn default_baud() -> u32 {
    115200
}
fn default_kdport() -> u32 {
    50000
}
fn default_channel() -> String {
    "System".to_string()
}
fn default_count() -> u32 {
    20
}
fn default_wpr_profile() -> String {
    "GeneralProfile".to_string()
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LogsEventQueryArgs {
    /// Event log channel, e.g. "System", "Application", "Microsoft-Windows-Kernel-Power/Analytic".
    #[serde(default = "default_channel")]
    pub channel: String,
    /// Number of most-recent events to return.
    #[serde(default = "default_count")]
    pub count: u32,
    /// Return raw event XML instead of text.
    #[serde(default)]
    pub xml: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LogsEventExportArgs {
    /// Event log channel to export to a .evtx file.
    pub channel: String,
}

#[derive(Debug, Default, Deserialize, schemars::JsonSchema)]
pub struct LogsEtwStartArgs {
    /// WPR profile (default "GeneralProfile"; e.g. "CPU", "DiskIO", "FileIO").
    #[serde(default = "default_wpr_profile")]
    pub profile: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SessionLaunchArgs {
    /// Command line to launch, e.g. "C:\\Windows\\System32\\notepad.exe".
    pub command: String,
    /// Target session id; defaults to the active console session.
    #[serde(default)]
    pub session_id: Option<u32>,
    /// Confirm token ("launch-in-user-session") when the box requires one.
    #[serde(default)]
    pub confirm: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TtdRecordArgs {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub name: Option<String>,
    /// Ring-buffer mode (bounded trace size).
    #[serde(default)]
    pub ring: bool,
    /// With ring mode, the max trace size in MB.
    #[serde(default)]
    pub max_file_mb: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DotnetTargetArgs {
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DotnetAnalyzeArgs {
    /// Managed dump id (from dotnet.dump / dump.capture) or a file path.
    pub dump: String,
    /// dotnet-dump SOS commands (default: clrthreads, clrstack -all).
    #[serde(default)]
    pub commands: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CollectPackageArgs {
    /// Optional note recorded in the case manifest.
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PathArg {
    /// Absolute path to the file.
    pub path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AeDebugArgs {
    /// Debugger command line (default: cdb scripted dump, if cdb is staged).
    #[serde(default)]
    pub debugger: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirm: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct OnCrashInstallArgs {
    /// Image name (e.g. "myapp.exe") for a per-image rule; omitted = global.
    #[serde(default)]
    pub image: Option<String>,
    /// Full dump (default) vs mini.
    #[serde(default = "default_true")]
    pub full: bool,
    /// Folder for the dumps (default "%LOCALAPPDATA%\\CrashDumps").
    #[serde(default)]
    pub dump_folder: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirm: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ArtifactsPurgeArgs {
    /// Only purge artifacts older than this many days (default: all candidates).
    #[serde(default)]
    pub older_than_days: Option<u64>,
    /// Preview what would be deleted without deleting (default true).
    #[serde(default = "default_true")]
    pub dry_run: bool,
}

impl Default for LogsEventQueryArgs {
    fn default() -> Self {
        LogsEventQueryArgs {
            channel: default_channel(),
            count: default_count(),
            xml: false,
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct KernelCrashDumpArgs {
    /// none | small | kernel | complete | automatic.
    pub mode: String,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirm: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct KernelSerialArgs {
    /// Guest COM port number (1 = COM1).
    #[serde(default = "default_com")]
    pub port: u32,
    #[serde(default = "default_baud")]
    pub baudrate: u32,
    /// Host/hypervisor hint: hyperv | proxmox | vmware | physical | auto.
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirm: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct KernelNetArgs {
    /// The debugger host's IP the target will send KDNET packets to.
    pub hostip: String,
    #[serde(default = "default_kdport")]
    pub port: u32,
    /// Optional KDNET key; omitted → bcdedit generates one (returned).
    #[serde(default)]
    pub key: Option<String>,
    /// Host/hypervisor hint: hyperv | proxmox | vmware | physical | auto.
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub confirm: Option<String>,
}

fn build_proc_node(
    pid: u32,
    info: &std::collections::HashMap<u32, String>,
    children: &std::collections::HashMap<u32, Vec<u32>>,
    depth: u32,
) -> serde_json::Value {
    let kids: Vec<serde_json::Value> = if depth > 30 {
        Vec::new()
    } else {
        children
            .get(&pid)
            .map(|v| {
                v.iter()
                    .filter(|c| **c != pid)
                    .map(|c| build_proc_node(*c, info, children, depth + 1))
                    .collect()
            })
            .unwrap_or_default()
    };
    json!({ "pid": pid, "name": info.get(&pid).cloned().unwrap_or_default(), "children": kids })
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

async fn kill_pid(pid: u32) -> Result<(), String> {
    let out = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F", "/T"])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
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
            prompt_router: Self::prompt_router(),
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
        name = "approvals.list",
        description = "List the human-approval broker's grants (granted/used) for HumanApproval-gated actions. Read-only. Operators grant with the CLI: heisenberg approve <tool>."
    )]
    async fn approvals_list(&self) -> Result<CallToolResult, McpError> {
        let items = self.state.approvals.list();
        Ok(text(
            Outcome::new("approvals.list", format!("{} approval record(s)", items.len()))
                .data(json!({ "approvals": items }))
                .to_value(),
        ))
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
            &self.state.approvals,
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
        let extra: Vec<String> = self
            .state
            .extra_folders
            .lock()
            .unwrap()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let v = Outcome::new("tools.list", format!("{}/{} known tools found", found, inv.len()))
            .data(json!({ "tools": inv, "extraFolders": extra }))
            .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "tools.addFolder",
        description = "Add a folder to Heisenberg's tool search path (searched first, persisted across restarts). Affects only tool discovery, not the machine."
    )]
    async fn tools_add_folder(
        &self,
        Parameters(a): Parameters<PathArg>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "tools.addFolder";
        let (list, added) = {
            let mut g = self.state.extra_folders.lock().unwrap();
            let exists = g
                .iter()
                .any(|d| d.display().to_string().eq_ignore_ascii_case(&a.path));
            if !exists {
                g.push(PathBuf::from(&a.path));
            }
            (g.clone(), !exists)
        };
        save_folders(&self.state.folders_path, &list);
        self.state.audit.record(tool, &format!("add folder {}", a.path), None, if added { "added" } else { "noop" }, None);
        let display: Vec<String> = list.iter().map(|p| p.display().to_string()).collect();
        let mut out = Outcome::new(tool, format!("{} search folder(s)", display.len()))
            .data(json!({ "added": added, "folders": display }));
        if !std::path::Path::new(&a.path).exists() {
            out = out.warn("that folder doesn't exist yet; tools there will resolve once it does");
        }
        Ok(text(out.to_value()))
    }

    #[tool(
        name = "tools.removeFolder",
        description = "Remove a folder from Heisenberg's tool search path (persisted)."
    )]
    async fn tools_remove_folder(
        &self,
        Parameters(a): Parameters<PathArg>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "tools.removeFolder";
        let (list, removed) = {
            let mut g = self.state.extra_folders.lock().unwrap();
            let before = g.len();
            g.retain(|d| !d.display().to_string().eq_ignore_ascii_case(&a.path));
            let removed = g.len() != before;
            (g.clone(), removed)
        };
        save_folders(&self.state.folders_path, &list);
        self.state.audit.record(tool, &format!("remove folder {}", a.path), None, if removed { "removed" } else { "noop" }, None);
        let display: Vec<String> = list.iter().map(|p| p.display().to_string()).collect();
        Ok(text(
            Outcome::new(tool, format!("{} search folder(s)", display.len()))
                .data(json!({ "removed": removed, "folders": display }))
                .to_value(),
        ))
    }

    #[tool(
        name = "tools.install",
        description = "Install a known tool via winget or the dotnet CLI (procdump, procmon, autoruns, psexec, sysinternals, windbg, windows-sdk, dotnet-dump/-gcdump/-trace). State-changing, gated; accepts EULAs non-interactively; recorded in the ledger so it can be uninstalled via changes.revert. Needs network — on air-gapped boxes stage a --tools-dir bundle instead. dry_run + confirm."
    )]
    async fn tools_install(
        &self,
        Parameters(a): Parameters<ToolsInstallArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "tools.install";
        let docs = "https://learn.microsoft.com/windows/package-manager/winget/install";
        let method = match crate::tools::install_method(&a.tool) {
            Some(m) => m,
            None => {
                return Ok(text(error(
                    tool,
                    ErrorKind::InvalidArgument,
                    format!("don't know how to install '{}'", a.tool),
                    "known: procdump, procmon, autoruns, psexec, sysinternals, windbg, windows-sdk, dotnet-dump, dotnet-gcdump, dotnet-trace",
                    Some(docs),
                )))
            }
        };
        let (program, args_vec, revert, label): (&str, Vec<String>, RevertPlan, String) = match &method {
            crate::tools::InstallMethod::Winget(id) => (
                "winget",
                vec![
                    "install".into(), "--id".into(), id.to_string(), "-e".into(),
                    "--accept-source-agreements".into(), "--accept-package-agreements".into(),
                    "--disable-interactivity".into(),
                ],
                RevertPlan::Command {
                    program: "winget".into(),
                    args: vec!["uninstall".into(), "--id".into(), id.to_string(), "-e".into(), "--disable-interactivity".into()],
                    describe: format!("winget uninstall {id}"),
                },
                format!("winget id {id}"),
            ),
            crate::tools::InstallMethod::DotnetTool(pkg) => (
                "dotnet",
                vec!["tool".into(), "install".into(), "-g".into(), pkg.to_string()],
                RevertPlan::Command {
                    program: "dotnet".into(),
                    args: vec!["tool".into(), "uninstall".into(), "-g".into(), pkg.to_string()],
                    describe: format!("dotnet tool uninstall -g {pkg}"),
                },
                format!("dotnet tool {pkg}"),
            ),
            crate::tools::InstallMethod::DirectZip { url, exe } => {
                let dir = crate::tools::MANAGED_TOOLS_DIR;
                let script = format!(
                    "$d='{dir}'; New-Item -ItemType Directory -Force $d | Out-Null; \
                     $z=Join-Path $env:TEMP ('hb_'+[guid]::NewGuid().ToString('N')+'.zip'); \
                     Invoke-WebRequest -UseBasicParsing -Uri '{url}' -OutFile $z; \
                     Expand-Archive -LiteralPath $z -DestinationPath $d -Force; \
                     Remove-Item $z -Force; (Get-Item (Join-Path $d '{exe}')).FullName"
                );
                (
                    "powershell",
                    vec!["-NoProfile".into(), "-NonInteractive".into(), "-Command".into(), script],
                    RevertPlan::Command {
                        program: "powershell".into(),
                        args: vec![
                            "-NoProfile".into(),
                            "-Command".into(),
                            format!("Remove-Item -Force -ErrorAction SilentlyContinue '{dir}\\{exe}'"),
                        ],
                        describe: format!("remove {exe} from the managed tools dir"),
                    },
                    format!("direct download {url}"),
                )
            }
        };
        let cmd_str = format!("{program} {}", args_vec.join(" "));

        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            return Ok(text(
                Outcome::new(tool, format!("[dry-run] would install {} via {label} (gate: {:?})", a.tool, decision.gate))
                    .data(json!({ "tool": a.tool, "method": label, "gate": decision }))
                    .command(cmd_str)
                    .docs(docs)
                    .warn("dry-run: no change made; needs network. On air-gapped boxes stage a --tools-dir bundle instead.")
                    .to_value(),
            ));
        }
        let decision = match gate::enforce(&self.state.policy, tool, EffectTier::StateChanging, "install-tool", a.confirm.as_deref(), &self.state.approvals) {
            Ok(d) => d,
            Err(b) => { self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None); return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(docs)))); }
        };
        let id = { let mut l = self.state.ledger.lock().unwrap(); l.begin(tool, &format!("install {} ({label})", a.tool), revert) };
        let argrefs: Vec<&str> = args_vec.iter().map(|s| s.as_str()).collect();
        let (ok, out) = self.run_capture(program, &argrefs, 600).await;
        if ok {
            self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
            self.state.audit.record(tool, &format!("installed {}", a.tool), Some(&format!("{:?}", decision.gate)), "installed", Some(&id));
            Ok(text(
                Outcome::new(tool, format!("installed {} via {label}; change {id}", a.tool))
                    .data(json!({ "tool": a.tool, "method": label, "changeId": id, "output": last_chars(&out, 3000) }))
                    .command(cmd_str)
                    .docs(docs)
                    .warn("re-run tools.list / env.check to confirm the tool resolves; a new shell may be needed for PATH. Uninstall via changes.revert.")
                    .to_value(),
            ))
        } else {
            self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
            let low = out.to_lowercase();
            let k = if low.contains("admin") || low.contains("elevat") {
                ErrorKind::RequiresElevation
            } else if low.contains("launch error") || low.contains("not found") {
                ErrorKind::ToolNotInstalled
            } else {
                ErrorKind::ToolInstallFailed
            };
            let mut v = error(tool, k, format!("install of {} failed", a.tool), "check network/winget availability; on air-gapped boxes stage a --tools-dir bundle", Some(docs));
            v["error"]["output"] = json!(last_chars(&out, 3000));
            Ok(text(v))
        }
    }

    #[tool(
        name = "env.provision",
        description = "Provision the whole debugging environment in one step via Groundhog (if installed): applies a Groundhogfile profile (default the windows-internals library: Sysinternals, WinDbg, WPT, _NT_SYMBOL_PATH, WER crash dumps). State-changing, gated; needs elevation. ToolNotInstalled if groundhog-agent isn't present. dry_run + confirm."
    )]
    async fn env_provision(
        &self,
        Parameters(a): Parameters<ProvisionArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "env.provision";
        let agent = self
            .state
            .locator
            .find("groundhog-agent.exe")
            .or_else(|| self.state.locator.find("groundhog.exe"));
        let agent = match agent {
            Some(p) => p,
            None => {
                return Ok(text(error(
                    tool,
                    ErrorKind::ToolNotInstalled,
                    "groundhog-agent not found",
                    "install Groundhog (https://github.com/guscatalano/Groundhog); or use tools.install for individual tools",
                    Some(GROUNDHOG_DOCS),
                )))
            }
        };
        let profile = a.profile.clone().unwrap_or_else(|| "groundhog:windows-internals".to_string());
        let cmd = format!("{} apply {}", agent.display(), profile);

        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            return Ok(text(
                Outcome::new(tool, format!("[dry-run] would apply Groundhog profile '{profile}' (gate: {:?})", decision.gate))
                    .data(json!({ "agent": agent.display().to_string(), "profile": profile, "gate": decision }))
                    .command(cmd)
                    .docs(GROUNDHOG_DOCS)
                    .warn("dry-run: no change made")
                    .to_value(),
            ));
        }
        if !env_probe::is_elevated() {
            return Ok(text(error(tool, ErrorKind::RequiresElevation, "the windows-internals profile writes HKLM (crash dumps); needs an elevated token", "re-run Heisenberg elevated", Some(GROUNDHOG_DOCS))));
        }
        let decision = match gate::enforce(&self.state.policy, tool, EffectTier::StateChanging, "provision-environment", a.confirm.as_deref(), &self.state.approvals) {
            Ok(d) => d,
            Err(b) => { self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None); return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(GROUNDHOG_DOCS)))); }
        };
        let id = {
            let mut l = self.state.ledger.lock().unwrap();
            l.begin(
                tool,
                &format!("Groundhog apply {profile}"),
                RevertPlan::Manual {
                    instructions: "Groundhog applies are declarative/idempotent; to undo, apply a prior profile or remove the installed items (C:\\Tools\\Sysinternals, _NT_SYMBOL_PATH, WER LocalDumps, CrashControl).".to_string(),
                },
            )
        };
        let (ok, out) = self.run_capture(&agent.display().to_string(), &["apply", &profile], 900).await;
        if ok {
            self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
            self.state.audit.record(tool, &format!("provisioned via Groundhog ({profile})"), Some(&format!("{:?}", decision.gate)), "provisioned", Some(&id));
            Ok(text(
                Outcome::new(tool, format!("provisioned the environment via Groundhog profile '{profile}'; change {id}"))
                    .data(json!({ "profile": profile, "changeId": id, "output": last_chars(&out, 3000) }))
                    .command(cmd)
                    .docs(GROUNDHOG_DOCS)
                    .warn("Heisenberg reads the registry PATH live, so tools.list should resolve the newly provisioned tools (C:\\Tools\\Sysinternals, etc.) without a restart")
                    .to_value(),
            ))
        } else {
            self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
            let mut v = error(tool, ErrorKind::ToolInstallFailed, format!("Groundhog apply of '{profile}' failed"), "check the profile name/URL and network; see the Groundhog output", Some(GROUNDHOG_DOCS));
            v["error"]["output"] = json!(last_chars(&out, 3000));
            Ok(text(v))
        }
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
        // comsvcs MiniDump ACLs the dump to SYSTEM+Administrators only; grant the
        // capturing user read so cdb (and dump.analyze) can open it without elevation.
        if backend == "comsvcs" {
            if let Ok(user) = std::env::var("USERNAME") {
                let _ = tokio::time::timeout(
                    Duration::from_secs(20),
                    Command::new("icacls").arg(&outpath).arg("/grant").arg(format!("{user}:(R)")).output(),
                )
                .await;
            }
        }
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

    /// Resolve a dump ref (id or path), locate cdb, run a command set, return raw.
    async fn run_cdb_on(
        &self,
        tool: &str,
        dump_ref: &str,
        cmds: &str,
    ) -> Result<(String, String, String), CallToolResult> {
        let docs = "https://learn.microsoft.com/windows-hardware/drivers/debugger/";
        let path = {
            let reg = self.state.dumps.lock().unwrap();
            let id = dump_ref.trim_start_matches("heisenberg://dumps/");
            reg.get(id).map(|r| r.path.clone()).unwrap_or_else(|| dump_ref.to_string())
        };
        if !std::path::Path::new(&path).is_file() {
            return Err(text(error(tool, ErrorKind::TargetNotFound, format!("no dump at {path}"), "capture one with dump.capture, or pass a valid path", Some(docs))));
        }
        let cdb = match self.state.locator.find("cdb.exe") {
            Some(p) => p,
            None => {
                let mut v = error(tool, ErrorKind::ToolNotInstalled, "cdb.exe not found", "install the Debugging Tools for Windows (winget install Microsoft.WinDbg)", Some(docs));
                v["error"]["wingetId"] = json!("Microsoft.WinDbg");
                return Err(text(v));
            }
        };
        let sympath = regutil::get_hkcu_env("_NT_SYMBOL_PATH").unwrap_or_else(|| {
            format!("srv*{}*https://msdl.microsoft.com/download/symbols", self.state.store.root.join("symbols").display())
        });
        let cmd_str = format!("{} -z \"{}\" -y \"{}\" -c \"{}\"", cdb.display(), path, sympath, cmds);
        let output = match tokio::time::timeout(
            Duration::from_secs(300),
            Command::new(&cdb).arg("-z").arg(&path).arg("-y").arg(&sympath).arg("-c").arg(cmds).output(),
        )
        .await
        {
            Err(_) => return Err(text(error(tool, ErrorKind::Timeout, "cdb timed out after 300s", "retry once symbols are cached", Some(docs)))),
            Ok(Err(e)) => return Err(text(error(tool, ErrorKind::Internal, format!("failed to launch cdb: {e}"), "check the cdb path", Some(docs)))),
            Ok(Ok(o)) => o,
        };
        Ok((path, String::from_utf8_lossy(&output.stdout).to_string(), cmd_str))
    }

    /// Shared body for the analyze.* family: run a fixed command set and return the raw tail.
    async fn simple_analyze(
        &self,
        tool: &str,
        dump: &str,
        override_cmds: Option<&str>,
        default_cmds: &str,
    ) -> Result<CallToolResult, McpError> {
        let cmds = override_cmds.unwrap_or(default_cmds);
        match self.run_cdb_on(tool, dump, cmds).await {
            Ok((path, raw, cmd_str)) => {
                let sym_missing = raw.contains("symbols could not be loaded")
                    || raw.contains("Symbol file could not be found");
                let mut out = Outcome::new(tool, format!("ran {tool} on {path}"))
                    .data(json!({ "path": path, "commands": cmds, "raw": last_chars(&raw, 8000) }))
                    .command(cmd_str)
                    .docs("https://learn.microsoft.com/windows-hardware/drivers/debugger/");
                if sym_missing {
                    out = out.warn("some symbols could not be loaded; results may be incomplete");
                }
                self.state.audit.record(tool, &format!("analyzed {path}"), None, "analyzed", None);
                Ok(text(out.to_value()))
            }
            Err(ct) => Ok(ct),
        }
    }

    #[tool(
        name = "analyze.deadlock",
        description = "Analyze a dump for lock / critical-section / .NET monitor contention (!locks, !cs, !syncblk, all-thread stacks). Read-only; needs cdb."
    )]
    async fn analyze_deadlock(
        &self,
        Parameters(a): Parameters<DumpAnalyzeArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.simple_analyze("analyze.deadlock", &a.dump, a.commands.as_deref(), "!locks; !cs -l; !syncblk; ~*kb; q")
            .await
    }

    #[tool(
        name = "analyze.highCpu",
        description = "Attribute CPU in a dump to threads (!runaway) with their stacks. Read-only; needs cdb."
    )]
    async fn analyze_high_cpu(
        &self,
        Parameters(a): Parameters<DumpAnalyzeArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.simple_analyze("analyze.highCpu", &a.dump, a.commands.as_deref(), "!runaway 7; ~*kb; q")
            .await
    }

    #[tool(
        name = "analyze.handles",
        description = "Summarize handle usage in a dump (!handle) — for handle-leak hunting. Read-only; needs cdb."
    )]
    async fn analyze_handles(
        &self,
        Parameters(a): Parameters<DumpAnalyzeArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.simple_analyze("analyze.handles", &a.dump, a.commands.as_deref(), "!handle 0 2; q")
            .await
    }

    #[tool(
        name = "analyze.async",
        description = "Analyze a managed (.NET) dump for async/threadpool state (!dumpasync, !threadpool). Read-only; needs cdb with SOS."
    )]
    async fn analyze_async(
        &self,
        Parameters(a): Parameters<DumpAnalyzeArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.simple_analyze("analyze.async", &a.dump, a.commands.as_deref(), "!dumpasync; !threadpool; q")
            .await
    }

    #[tool(
        name = "analyze.verifierStop",
        description = "Decode a Driver/Application Verifier stop in a dump (!analyze -v, !verifier) to the exact rule violated. Read-only; needs cdb."
    )]
    async fn analyze_verifier_stop(
        &self,
        Parameters(a): Parameters<DumpAnalyzeArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.simple_analyze("analyze.verifierStop", &a.dump, a.commands.as_deref(), "!analyze -v; !verifier 3; q")
            .await
    }

    #[tool(
        name = "appverifier.enable",
        description = "Enable Application Verifier for an image (sets the FLG_APPLICATION_VERIFIER bit in IFEO GlobalFlag). State-changing, reversible via the ledger; needs elevation. Configure specific checks with appverif.exe. dry_run + confirm."
    )]
    async fn appverifier_enable(
        &self,
        Parameters(a): Parameters<AppVerifierArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "appverifier.enable";
        let subkey = format!(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
            a.image
        );
        let prior_gf = regutil::hklm_read_dword(&subkey, "GlobalFlag");
        let exists = regutil::hklm_key_exists(&subkey);
        let new_gf = prior_gf.unwrap_or(0) | FLG_APPLICATION_VERIFIER;
        let cmd = format!("reg add \"HKLM\\{subkey}\" /v GlobalFlag /t REG_DWORD /d {new_gf} /f");

        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            return Ok(text(
                Outcome::new(tool, format!("[dry-run] would enable App Verifier for {} (gate: {:?})", a.image, decision.gate))
                    .data(json!({ "image": a.image, "priorGlobalFlag": prior_gf, "wouldSet": new_gf, "gate": decision }))
                    .command(cmd)
                    .docs(APPVERIF_DOCS)
                    .warn("dry-run: no change made")
                    .to_value(),
            ));
        }
        if !env_probe::is_elevated() {
            return Ok(text(error(tool, ErrorKind::RequiresElevation, "writing IFEO needs an elevated token", "re-run Heisenberg elevated", Some(APPVERIF_DOCS))));
        }
        let decision = match gate::enforce(&self.state.policy, tool, EffectTier::StateChanging, APPVERIF_TOKEN, a.confirm.as_deref(), &self.state.approvals) {
            Ok(d) => d,
            Err(b) => {
                self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None);
                return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(APPVERIF_DOCS))));
            }
        };
        let id = {
            let mut l = self.state.ledger.lock().unwrap();
            l.begin(
                tool,
                &format!("enable App Verifier for {}", a.image),
                RevertPlan::RegRestore {
                    subkey: subkey.clone(),
                    strings: vec![],
                    dwords: vec![("GlobalFlag".to_string(), prior_gf)],
                    created_key: !exists,
                },
            )
        };
        match regutil::hklm_set_dword(&subkey, "GlobalFlag", new_gf) {
            Ok(_) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
                self.state.audit.record(tool, &format!("App Verifier enabled for {}", a.image), Some(&format!("{:?}", decision.gate)), "applied", Some(&id));
                Ok(text(
                    Outcome::new(tool, format!("enabled App Verifier for {}; change {id}", a.image))
                        .data(json!({ "image": a.image, "globalFlag": new_gf, "changeId": id }))
                        .command(cmd)
                        .docs(APPVERIF_DOCS)
                        .warn("App Verifier adds heavy runtime checks and can surface stops; configure layers with appverif.exe; revert with changes.revert when done")
                        .to_value(),
                ))
            }
            Err(e) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
                let (k, remedy) = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    (ErrorKind::RequiresElevation, "re-run elevated")
                } else {
                    (ErrorKind::Internal, "check IFEO permissions")
                };
                Ok(text(error(tool, k, format!("failed to write IFEO: {e}"), remedy, Some(APPVERIF_DOCS))))
            }
        }
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
            &self.state.approvals,
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

    /// Stop all TTD recordings (finalizes the `.run` trace).
    async fn stop_ttd(&self) -> Result<(), String> {
        let ttd = self
            .state
            .locator
            .find("TTD.exe")
            .ok_or_else(|| "TTD.exe not found".to_string())?;
        let out = tokio::time::timeout(
            Duration::from_secs(120),
            Command::new(&ttd).args(["-stop", "all"]).output(),
        )
        .await
        .map_err(|_| "TTD -stop timed out".to_string())?
        .map_err(|e| format!("failed to launch TTD: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    /// Stop a WPR ETW session and finalize its `.etl`.
    async fn stop_wpr(&self, etl: &str) -> Result<(), String> {
        let out = tokio::time::timeout(
            Duration::from_secs(180),
            Command::new("wpr").args(["-stop", etl]).output(),
        )
        .await
        .map_err(|_| "wpr -stop timed out".to_string())?
        .map_err(|e| format!("failed to launch wpr: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    /// Ask a running Procmon to flush and exit (its own `/Terminate` form).
    async fn terminate_procmon(&self) -> Result<(), String> {
        let pm = self
            .state
            .locator
            .find("Procmon.exe")
            .ok_or_else(|| "Procmon.exe not found".to_string())?;
        let out = tokio::time::timeout(
            Duration::from_secs(60),
            Command::new(&pm).args(["/Terminate", "/AcceptEula"]).output(),
        )
        .await
        .map_err(|_| "procmon /Terminate timed out".to_string())?
        .map_err(|e| format!("failed to launch procmon: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
    }

    /// Shared stop/cancel path for background jobs.
    async fn do_stop(&self, tool: &str, id: &str, cancel: bool) -> Result<CallToolResult, McpError> {
        let job = {
            self.state.jobs.lock().unwrap().get(id).cloned()
        };
        let job = match job {
            Some(j) => j,
            None => {
                return Ok(text(error(
                    tool,
                    ErrorKind::SessionNotFound,
                    format!("no job {id}"),
                    "list jobs with job.list",
                    None,
                )))
            }
        };
        if job.state != JobState::Running {
            return Ok(text(error(
                tool,
                ErrorKind::InvalidArgument,
                format!("job {id} is {:?}, not running", job.state),
                "only running jobs can be stopped",
                None,
            )));
        }

        let stop_result: Result<(), String> = match job.kind.as_str() {
            "procmon" => self.terminate_procmon().await,
            "wpr" => match &job.backing_file {
                Some(p) => self.stop_wpr(p).await,
                None => Err("wpr job has no backing file".to_string()),
            },
            "ttd" => self.stop_ttd().await,
            "procdump" | "dbgsrv" => {
                // Best-effort: procdump may already have exited after its trigger
                // fired; dbgsrv is a long-running server we terminate.
                if let Some(pid) = job.tool_pid {
                    let _ = kill_pid(pid).await;
                }
                Ok(())
            }
            _ => {
                if cancel {
                    match job.tool_pid {
                        Some(pid) => kill_pid(pid).await,
                        None => Ok(()),
                    }
                } else {
                    Ok(())
                }
            }
        };

        let final_state = if cancel {
            JobState::Cancelled
        } else {
            JobState::Stopped
        };
        let verb = if cancel { "cancelled" } else { "stopped" };

        match stop_result {
            Ok(()) => {
                let updated = self.state.jobs.lock().unwrap().set_state(id, final_state);
                self.state.audit.record(tool, &format!("{verb} job {id}"), None, verb, Some(id));
                let mut out = Outcome::new(tool, format!("{verb} job {id} ({})", job.kind))
                    .data(json!({ "job": updated }));
                if let Some(bf) = &job.backing_file {
                    if std::path::Path::new(bf).is_file() {
                        let bytes = std::fs::metadata(bf).map(|m| m.len()).unwrap_or(0);
                        out = out.artifact(Artifact {
                            kind: "trace".to_string(),
                            path: bf.clone(),
                            bytes,
                            resource: format!("heisenberg://captures/{id}"),
                            sensitivity: Some("medium".to_string()),
                        });
                    }
                }
                Ok(text(out.to_value()))
            }
            Err(e) => {
                self.state.jobs.lock().unwrap().set_state(id, JobState::Failed);
                Ok(text(error(
                    tool,
                    ErrorKind::Internal,
                    format!("failed to stop job {id}: {e}"),
                    "try job.cancel to force-kill the tool process",
                    None,
                )))
            }
        }
    }

    #[tool(
        name = "procmon.start",
        description = "Start a Process Monitor capture in the background to a .pml backing file; returns a jobId. Read-only capture, but needs elevation (Procmon loads a driver). Stop with procmon.stop or job.stop."
    )]
    async fn procmon_start(
        &self,
        Parameters(a): Parameters<ProcmonStartArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "procmon.start";
        let pm = match self.state.locator.find("Procmon.exe") {
            Some(p) => p,
            None => {
                let mut v = error(
                    tool,
                    ErrorKind::ToolNotInstalled,
                    "Procmon.exe not found",
                    "install Sysinternals Process Monitor or stage it in --tools-dir",
                    Some(PROCMON_DOCS),
                );
                v["error"]["wingetId"] = json!("Microsoft.Sysinternals.ProcessMonitor");
                return Ok(text(v));
            }
        };
        if !env_probe::is_elevated() {
            return Ok(text(error(
                tool,
                ErrorKind::RequiresElevation,
                "Procmon needs an elevated token to load its capture driver",
                "re-run Heisenberg elevated, or via the elevated broker",
                Some(PROCMON_DOCS),
            )));
        }

        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let backing = self.state.store.artifacts_dir().join(format!("procmon_{ts}.pml"));
        let cmd_str = format!(
            "{} /AcceptEula /Quiet /Minimized /BackingFile \"{}\"",
            pm.display(),
            backing.display()
        );
        let mut c = std::process::Command::new(&pm);
        c.args(["/AcceptEula", "/Quiet", "/Minimized", "/BackingFile"])
            .arg(&backing);
        match c.spawn() {
            Ok(child) => {
                let pid = child.id();
                let job = {
                    let mut j = self.state.jobs.lock().unwrap();
                    j.add(
                        "procmon",
                        Some(pid),
                        Some(backing.display().to_string()),
                        &format!("procmon capture -> {}", backing.display()),
                    )
                };
                self.state.audit.record(tool, &format!("started procmon job {}", job.id), None, "started", Some(&job.id));
                let mut out = Outcome::new(tool, format!("started procmon capture (job {})", job.id))
                    .data(json!({
                        "jobId": job.id, "pid": pid,
                        "backingFile": backing.display().to_string(),
                        "resource": format!("heisenberg://captures/{}", job.id)
                    }))
                    .command(cmd_str)
                    .docs(PROCMON_DOCS)
                    .warn("capture is running; stop it with procmon.stop or job.stop to flush the .pml");
                if a.process.is_some() {
                    out = out.warn("process filter not yet applied; the capture is unfiltered");
                }
                Ok(text(out.to_value()))
            }
            Err(e) => Ok(text(error(
                tool,
                ErrorKind::Internal,
                format!("failed to launch Procmon: {e}"),
                "check the Procmon path",
                Some(PROCMON_DOCS),
            ))),
        }
    }

    #[tool(
        name = "procmon.stop",
        description = "Stop a running Procmon capture job, flush its .pml, and return the backing file as an artifact."
    )]
    async fn procmon_stop(
        &self,
        Parameters(a): Parameters<JobIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.do_stop("procmon.stop", &a.id, false).await
    }

    #[tool(
        name = "job.list",
        description = "List background jobs (captures) — running and finished — with kind, state, and backing file. Read-only."
    )]
    async fn job_list(&self) -> Result<CallToolResult, McpError> {
        let (n, data) = {
            let j = self.state.jobs.lock().unwrap();
            (j.list().len(), json!({ "jobs": j.list() }))
        };
        Ok(text(Outcome::new("job.list", format!("{n} job(s)")).data(data).to_value()))
    }

    #[tool(
        name = "job.status",
        description = "Show one background job by id. Read-only."
    )]
    async fn job_status(
        &self,
        Parameters(a): Parameters<JobIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let job = {
            self.state.jobs.lock().unwrap().get(&a.id).cloned()
        };
        match job {
            Some(j) => Ok(text(
                Outcome::new("job.status", format!("job {} is {:?}", j.id, j.state))
                    .data(json!({ "job": j }))
                    .to_value(),
            )),
            None => Ok(text(error(
                "job.status",
                ErrorKind::SessionNotFound,
                format!("no job {}", a.id),
                "list jobs with job.list",
                None,
            ))),
        }
    }

    #[tool(
        name = "job.stop",
        description = "Gracefully stop a running background job by id (kind-aware; procmon flushes its .pml)."
    )]
    async fn job_stop(
        &self,
        Parameters(a): Parameters<JobIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.do_stop("job.stop", &a.id, false).await
    }

    #[tool(
        name = "job.cancel",
        description = "Force-stop a running background job by id (kills the tool process). Prefer job.stop for a clean flush."
    )]
    async fn job_cancel(
        &self,
        Parameters(a): Parameters<JobIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.do_stop("job.cancel", &a.id, true).await
    }

    /// Run bcdedit, mapping access-denied to RequiresElevation.
    async fn run_bcdedit(&self, args: &[&str]) -> Result<String, (ErrorKind, String)> {
        let out = Command::new("bcdedit")
            .args(args)
            .output()
            .await
            .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if out.status.success() {
            Ok(combined.trim().to_string())
        } else {
            let low = combined.to_lowercase();
            let kind = if low.contains("access is denied") || low.contains("elevat") {
                ErrorKind::RequiresElevation
            } else {
                ErrorKind::Internal
            };
            Err((kind, combined.trim().to_string()))
        }
    }

    #[tool(
        name = "kernel.status",
        description = "Show kernel-debug configuration: crash-dump mode (CrashControl), detected hypervisor (Hyper-V/Proxmox/VMware/physical), and — when elevated — bcdedit debug settings. Read-only."
    )]
    async fn kernel_status(&self) -> Result<CallToolResult, McpError> {
        let cc = regutil::crashcontrol_read();
        let hv = kernel::detect_hypervisor();
        let (dbg, dbg_note) = match self.run_bcdedit(&["/dbgsettings"]).await {
            Ok(s) => (Some(s), None),
            Err((k, e)) => (None, Some(format!("{k:?}: {e}"))),
        };
        let v = Outcome::new(
            "kernel.status",
            format!(
                "crash dump: {}, hypervisor: {hv}",
                cc.map(kernel::crash_dump_mode_name).unwrap_or("unknown")
            ),
        )
        .data(json!({
            "crashDumpEnabled": cc,
            "crashDumpMode": cc.map(kernel::crash_dump_mode_name),
            "hypervisor": hv,
            "dbgSettings": dbg,
            "dbgSettingsNote": dbg_note,
        }))
        .docs(KERNEL_DOCS)
        .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "kernel.setCrashDump",
        description = "Set the kernel crash-dump mode (none|small|kernel|complete|automatic) via CrashControl. State-changing, reversible via the ledger; needs elevation. dry_run + confirm."
    )]
    async fn kernel_set_crash_dump(
        &self,
        Parameters(a): Parameters<KernelCrashDumpArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "kernel.setCrashDump";
        let target = match kernel::crash_dump_mode_value(&a.mode) {
            Some(v) => v,
            None => {
                return Ok(text(error(
                    tool,
                    ErrorKind::InvalidArgument,
                    format!("unknown mode '{}'", a.mode),
                    "use none|small|kernel|complete|automatic",
                    Some(CRASHDUMP_DOCS),
                )))
            }
        };
        let prior = regutil::crashcontrol_read();
        let cmd = format!(
            "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl /v CrashDumpEnabled /t REG_DWORD /d {target} /f"
        );

        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            self.state.audit.record(tool, "dry-run", Some(&format!("{:?}", decision.gate)), "dry-run", None);
            return Ok(text(
                Outcome::new(
                    tool,
                    format!("[dry-run] would set crash dump to {}", kernel::crash_dump_mode_name(target)),
                )
                .data(json!({
                    "priorMode": prior.map(kernel::crash_dump_mode_name), "prior": prior,
                    "wouldSet": target, "mode": kernel::crash_dump_mode_name(target), "gate": decision
                }))
                .command(cmd)
                .docs(CRASHDUMP_DOCS)
                .warn("dry-run: no change made")
                .to_value(),
            ));
        }

        if !env_probe::is_elevated() {
            return Ok(text(error(
                tool,
                ErrorKind::RequiresElevation,
                "writing CrashControl needs an elevated token",
                "re-run Heisenberg elevated",
                Some(CRASHDUMP_DOCS),
            )));
        }
        let decision = match gate::enforce(
            &self.state.policy,
            tool,
            EffectTier::StateChanging,
            CRASHDUMP_TOKEN,
            a.confirm.as_deref(),
            &self.state.approvals,
        ) {
            Ok(d) => d,
            Err(b) => {
                self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None);
                return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(CRASHDUMP_DOCS))));
            }
        };
        let id = {
            let mut l = self.state.ledger.lock().unwrap();
            l.begin(
                tool,
                &format!("set crash dump to {}", kernel::crash_dump_mode_name(target)),
                RevertPlan::CrashControl { prior },
            )
        };
        match regutil::crashcontrol_write(target) {
            Ok(()) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
                self.state.audit.record(
                    tool,
                    &format!("crash dump -> {}", kernel::crash_dump_mode_name(target)),
                    Some(&format!("{:?}", decision.gate)),
                    "applied",
                    Some(&id),
                );
                Ok(text(
                    Outcome::new(
                        tool,
                        format!("set crash dump to {}; change {id}", kernel::crash_dump_mode_name(target)),
                    )
                    .data(json!({ "mode": kernel::crash_dump_mode_name(target), "value": target, "prior": prior, "changeId": id }))
                    .command(cmd)
                    .docs(CRASHDUMP_DOCS)
                    .warn("complete/kernel dumps need a page file sized appropriately on the system drive; takes effect on the next bugcheck")
                    .to_value(),
                ))
            }
            Err(e) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
                let (kind, remedy) = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    (ErrorKind::RequiresElevation, "re-run elevated")
                } else {
                    (ErrorKind::Internal, "check CrashControl permissions")
                };
                Ok(text(error(tool, kind, format!("failed to write CrashControl: {e}"), remedy, Some(CRASHDUMP_DOCS))))
            }
        }
    }

    #[tool(
        name = "kernel.serialDebugSetup",
        description = "Configure the guest for SERIAL kernel debugging (bcdedit dbgsettings + /debug on) and return host-side wiring for the hypervisor (Hyper-V exposes the COM port as a named pipe; Proxmox needs a socket bridge; VMware/physical too). State-changing, reversible; needs elevation + reboot. dry_run + confirm."
    )]
    async fn kernel_serial_setup(
        &self,
        Parameters(a): Parameters<KernelSerialArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "kernel.serialDebugSetup";
        let host = kernel::resolve_host(a.host.as_deref());
        let guidance = kernel::serial_guidance(&host, a.port, a.baudrate);
        let cmds = format!(
            "bcdedit /dbgsettings serial debugport:{} baudrate:{} ; bcdedit /debug on",
            a.port, a.baudrate
        );

        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            return Ok(text(
                Outcome::new(tool, format!("[dry-run] serial KD on COM{} @ {} for {host}", a.port, a.baudrate))
                    .data(json!({ "host": host, "guidance": guidance, "gate": decision }))
                    .command(cmds)
                    .docs(KERNEL_DOCS)
                    .warn("dry-run: no change made")
                    .to_value(),
            ));
        }
        if !env_probe::is_elevated() {
            return Ok(text(error(tool, ErrorKind::RequiresElevation, "bcdedit needs an elevated token", "re-run Heisenberg elevated", Some(KERNEL_DOCS))));
        }
        let decision = match gate::enforce(&self.state.policy, tool, EffectTier::StateChanging, KERNEL_TOKEN, a.confirm.as_deref(), &self.state.approvals) {
            Ok(d) => d,
            Err(b) => {
                self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None);
                return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(KERNEL_DOCS))));
            }
        };
        let prior = self.run_bcdedit(&["/dbgsettings"]).await.ok();
        let id = {
            let mut l = self.state.ledger.lock().unwrap();
            l.begin(
                tool,
                &format!("enable serial KD (COM{} @ {})", a.port, a.baudrate),
                RevertPlan::Command {
                    program: "bcdedit".to_string(),
                    args: vec!["/debug".to_string(), "off".to_string()],
                    describe: "disable kernel debugging (bcdedit /debug off)".to_string(),
                },
            )
        };
        if let Err((k, e)) = self
            .run_bcdedit(&["/dbgsettings", "serial", &format!("debugport:{}", a.port), &format!("baudrate:{}", a.baudrate)])
            .await
        {
            self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
            return Ok(text(error(tool, k, format!("bcdedit dbgsettings failed: {e}"), "run elevated; ensure BCD is writable", Some(KERNEL_DOCS))));
        }
        if let Err((k, e)) = self.run_bcdedit(&["/debug", "on"]).await {
            self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
            return Ok(text(error(tool, k, format!("bcdedit /debug on failed: {e}"), "run elevated", Some(KERNEL_DOCS))));
        }
        self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
        self.state.audit.record(tool, "serial KD configured", Some(&format!("{:?}", decision.gate)), "applied", Some(&id));
        Ok(text(
            Outcome::new(tool, format!("configured serial KD on COM{} @ {} (reboot required); change {id}", a.port, a.baudrate))
                .data(json!({ "host": host, "guidance": guidance, "priorDbgSettings": prior, "changeId": id }))
                .command(cmds)
                .docs(KERNEL_DOCS)
                .warn("reboot the target for kernel debugging to take effect; Secure Boot must be OFF")
                .to_value(),
        ))
    }

    #[tool(
        name = "kernel.netDebugSetup",
        description = "Configure the guest for NETWORK (KDNET) kernel debugging (bcdedit dbgsettings net + /debug on) and return host-side wiring + hypervisor caveats (Proxmox: e1000e + hv-vendor-id; Hyper-V Gen2 synthetic NIC). Returns the generated key. State-changing, reversible; needs elevation + reboot. dry_run + confirm."
    )]
    async fn kernel_net_setup(
        &self,
        Parameters(a): Parameters<KernelNetArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "kernel.netDebugSetup";
        let host = kernel::resolve_host(a.host.as_deref());
        let guidance = kernel::net_guidance(&host, &a.hostip, a.port, a.key.as_deref());
        let keypart = a.key.as_ref().map(|k| format!(" key:{k}")).unwrap_or_default();
        let cmds = format!("bcdedit /dbgsettings net hostip:{} port:{}{keypart} ; bcdedit /debug on", a.hostip, a.port);

        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            return Ok(text(
                Outcome::new(tool, format!("[dry-run] KDNET to {}:{} for {host}", a.hostip, a.port))
                    .data(json!({ "host": host, "guidance": guidance, "gate": decision }))
                    .command(cmds)
                    .docs(KERNEL_DOCS)
                    .warn("dry-run: no change made")
                    .to_value(),
            ));
        }
        if !env_probe::is_elevated() {
            return Ok(text(error(tool, ErrorKind::RequiresElevation, "bcdedit needs an elevated token", "re-run Heisenberg elevated", Some(KERNEL_DOCS))));
        }
        let decision = match gate::enforce(&self.state.policy, tool, EffectTier::StateChanging, KERNEL_TOKEN, a.confirm.as_deref(), &self.state.approvals) {
            Ok(d) => d,
            Err(b) => {
                self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None);
                return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(KERNEL_DOCS))));
            }
        };
        let prior = self.run_bcdedit(&["/dbgsettings"]).await.ok();
        let id = {
            let mut l = self.state.ledger.lock().unwrap();
            l.begin(
                tool,
                &format!("enable KDNET (hostip {} port {})", a.hostip, a.port),
                RevertPlan::Command {
                    program: "bcdedit".to_string(),
                    args: vec!["/debug".to_string(), "off".to_string()],
                    describe: "disable kernel debugging (bcdedit /debug off)".to_string(),
                },
            )
        };
        let mut args: Vec<String> = vec![
            "/dbgsettings".to_string(),
            "net".to_string(),
            format!("hostip:{}", a.hostip),
            format!("port:{}", a.port),
        ];
        if let Some(k) = &a.key {
            args.push(format!("key:{k}"));
        }
        let argrefs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let dbg_out = match self.run_bcdedit(&argrefs).await {
            Ok(o) => o,
            Err((k, e)) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
                return Ok(text(error(tool, k, format!("bcdedit dbgsettings net failed: {e}"), "run elevated; ensure BCD is writable", Some(KERNEL_DOCS))));
            }
        };
        if let Err((k, e)) = self.run_bcdedit(&["/debug", "on"]).await {
            self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
            return Ok(text(error(tool, k, format!("bcdedit /debug on failed: {e}"), "run elevated", Some(KERNEL_DOCS))));
        }
        // bcdedit prints the (generated) key.
        let generated_key = dbg_out
            .lines()
            .find(|l| l.to_lowercase().contains("key"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .or_else(|| a.key.clone());

        self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
        self.state.audit.record(tool, "KDNET configured", Some(&format!("{:?}", decision.gate)), "applied", Some(&id));
        Ok(text(
            Outcome::new(tool, format!("configured KDNET to {}:{} (reboot required); change {id}", a.hostip, a.port))
                .data(json!({ "host": host, "guidance": guidance, "key": generated_key, "priorDbgSettings": prior, "changeId": id }))
                .command(cmds)
                .docs(KERNEL_DOCS)
                .warn("reboot the target for KDNET to take effect; Secure Boot OFF; the NIC must be KDNET-supported (e1000e, not virtio)")
                .to_value(),
        ))
    }

    #[tool(
        name = "logs.eventQuery",
        description = "Query the most recent Windows event log entries from a channel (default System) via wevtutil. Read-only; Application/System work unprivileged, some channels (Security) need admin."
    )]
    async fn logs_event_query(
        &self,
        Parameters(a): Parameters<LogsEventQueryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "logs.eventQuery";
        let fmt = if a.xml { "xml" } else { "text" };
        let count_arg = format!("/c:{}", a.count);
        let fmt_arg = format!("/f:{fmt}");
        let args = ["qe", a.channel.as_str(), &count_arg, "/rd:true", &fmt_arg];
        let out = match tokio::time::timeout(
            Duration::from_secs(60),
            Command::new("wevtutil").args(args).output(),
        )
        .await
        {
            Err(_) => {
                return Ok(text(error(tool, ErrorKind::Timeout, "wevtutil timed out", "narrow the channel or count", Some(WEVTUTIL_DOCS))))
            }
            Ok(Err(e)) => {
                return Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch wevtutil: {e}"), "ensure wevtutil is on PATH", Some(WEVTUTIL_DOCS))))
            }
            Ok(Ok(o)) => o,
        };
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            let low = err.to_lowercase();
            let (k, remedy) = if low.contains("access is denied") {
                (ErrorKind::AccessDenied, "this channel needs elevation")
            } else if low.contains("channel") || low.contains("could not be found") {
                (ErrorKind::InvalidArgument, "check the channel name (list them with: wevtutil el)")
            } else {
                (ErrorKind::Internal, "check the channel and query")
            };
            return Ok(text(error(tool, k, format!("wevtutil failed: {}", err.trim()), remedy, Some(WEVTUTIL_DOCS))));
        }
        let raw = String::from_utf8_lossy(&out.stdout).to_string();
        let events = if a.xml {
            raw.matches("<Event").count()
        } else {
            raw.matches("Event[").count()
        };
        let v = Outcome::new(tool, format!("{events} event(s) from {}", a.channel))
            .data(json!({ "channel": a.channel, "count": events, "format": fmt, "raw": last_chars(&raw, 8000) }))
            .command(format!("wevtutil qe {} /c:{} /rd:true /f:{fmt}", a.channel, a.count))
            .docs(WEVTUTIL_DOCS)
            .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "logs.eventExport",
        description = "Export a Windows event log channel to a .evtx file (wevtutil epl). Read-only; produces an artifact to hand to findneedle. Some channels (Security) need admin."
    )]
    async fn logs_event_export(
        &self,
        Parameters(a): Parameters<LogsEventExportArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "logs.eventExport";
        let safe: String = a
            .channel
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect();
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let path = self.state.store.artifacts_dir().join(format!("evtx_{safe}_{ts}.evtx"));
        let cmd = format!("wevtutil epl \"{}\" \"{}\" /ow:true", a.channel, path.display());
        let out = match tokio::time::timeout(
            Duration::from_secs(120),
            Command::new("wevtutil")
                .arg("epl")
                .arg(&a.channel)
                .arg(&path)
                .arg("/ow:true")
                .output(),
        )
        .await
        {
            Err(_) => {
                return Ok(text(error(tool, ErrorKind::Timeout, "wevtutil epl timed out", "retry", Some(WEVTUTIL_DOCS))))
            }
            Ok(Err(e)) => {
                return Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch wevtutil: {e}"), "ensure wevtutil is on PATH", Some(WEVTUTIL_DOCS))))
            }
            Ok(Ok(o)) => o,
        };
        if !out.status.success() || !path.is_file() {
            let err = String::from_utf8_lossy(&out.stderr).to_string();
            let low = err.to_lowercase();
            let (k, remedy) = if low.contains("access is denied") {
                (ErrorKind::AccessDenied, "this channel needs elevation")
            } else {
                (ErrorKind::InvalidArgument, "check the channel name (wevtutil el)")
            };
            return Ok(text(error(tool, k, format!("wevtutil epl failed: {}", err.trim()), remedy, Some(WEVTUTIL_DOCS))));
        }
        let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        self.state.audit.record(tool, &format!("exported {} ({bytes} bytes)", a.channel), None, "exported", None);
        let v = Outcome::new(tool, format!("exported {} ({:.1} KB)", a.channel, bytes as f64 / 1024.0))
            .data(json!({ "channel": a.channel, "path": path.display().to_string(), "bytes": bytes }))
            .artifact(Artifact {
                kind: "evtx".to_string(),
                path: path.display().to_string(),
                bytes,
                resource: path.display().to_string(),
                sensitivity: Some("medium".to_string()),
            })
            .command(cmd)
            .docs(WEVTUTIL_DOCS)
            .warn("hand the .evtx to findneedle (add_log_location) for querying and cross-artifact correlation")
            .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "logs.etwStart",
        description = "Start a WPR ETW trace in the background (default GeneralProfile; e.g. CPU/DiskIO/FileIO) to a .etl; returns a jobId. Needs elevation. Stop with logs.etwStop or job.stop to finalize the .etl."
    )]
    async fn logs_etw_start(
        &self,
        Parameters(a): Parameters<LogsEtwStartArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "logs.etwStart";
        if !env_probe::is_elevated() {
            return Ok(text(error(tool, ErrorKind::RequiresElevation, "WPR needs an elevated token to start an ETW session", "re-run Heisenberg elevated", Some(WPR_DOCS))));
        }
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let etl = self.state.store.artifacts_dir().join(format!("wpr_{ts}.etl"));
        let profile = if a.profile.is_empty() {
            "GeneralProfile".to_string()
        } else {
            a.profile.clone()
        };
        let cmd = format!("wpr -start {profile} -filemode");
        let out = match tokio::time::timeout(
            Duration::from_secs(60),
            Command::new("wpr").args(["-start", &profile, "-filemode"]).output(),
        )
        .await
        {
            Err(_) => {
                return Ok(text(error(tool, ErrorKind::Timeout, "wpr -start timed out", "retry", Some(WPR_DOCS))))
            }
            Ok(Err(e)) => {
                return Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch wpr: {e}"), "ensure wpr.exe is available", Some(WPR_DOCS))))
            }
            Ok(Ok(o)) => o,
        };
        if !out.status.success() {
            let err = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let low = err.to_lowercase();
            let (k, remedy) = if low.contains("already") || low.contains("in progress") {
                (ErrorKind::CaptureInProgress, "stop the current WPR session first (logs.etwStop / wpr -cancel)")
            } else if low.contains("denied") || low.contains("elevat") {
                (ErrorKind::RequiresElevation, "re-run elevated")
            } else {
                (ErrorKind::Internal, "check the WPR profile name")
            };
            return Ok(text(error(tool, k, format!("wpr -start failed: {}", err.trim()), remedy, Some(WPR_DOCS))));
        }
        let job = {
            let mut j = self.state.jobs.lock().unwrap();
            j.add("wpr", None, Some(etl.display().to_string()), &format!("wpr {profile} -> {}", etl.display()))
        };
        self.state.audit.record(tool, &format!("started wpr job {}", job.id), None, "started", Some(&job.id));
        let v = Outcome::new(tool, format!("started WPR {profile} capture (job {})", job.id))
            .data(json!({
                "jobId": job.id, "profile": profile,
                "backingFile": etl.display().to_string(),
                "resource": format!("heisenberg://captures/{}", job.id)
            }))
            .command(cmd)
            .docs(WPR_DOCS)
            .warn("ETW session is running; stop with logs.etwStop or job.stop to write the .etl")
            .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "logs.etwStop",
        description = "Stop a running WPR ETW trace job, finalize the .etl, and return it as an artifact."
    )]
    async fn logs_etw_stop(
        &self,
        Parameters(a): Parameters<JobIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.do_stop("logs.etwStop", &a.id, false).await
    }

    #[tool(
        name = "session.list",
        description = "List Windows sessions (id, window station, state) and the active console session. Read-only."
    )]
    async fn session_list(&self) -> Result<CallToolResult, McpError> {
        let sessions = session::list_sessions();
        let active = session::active_console_session();
        let v = Outcome::new(
            "session.list",
            format!("{} session(s); active console: {active:?}", sessions.len()),
        )
        .data(json!({ "sessions": sessions, "activeConsole": active }))
        .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "session.launchInUser",
        description = "Launch a process from session 0 / SYSTEM into the active interactive user session (WTSQueryUserToken -> CreateProcessAsUser, full desktop + environment-block recipe). Needs SeTcbPrivilege (SYSTEM), not merely an elevated admin. State-changing; confirm token per box class."
    )]
    async fn session_launch(
        &self,
        Parameters(a): Parameters<SessionLaunchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "session.launchInUser";
        let env = env_probe::probe();
        if !env.privileges.se_tcb.held {
            self.state.audit.record(tool, "missing SeTcbPrivilege", None, "blocked", None);
            return Ok(text(error(
                tool,
                ErrorKind::RequiresPrivilege,
                "launching into a user session needs SeTcbPrivilege (run as LocalSystem/SYSTEM; an elevated admin is not enough)",
                "run Heisenberg as a SYSTEM service, or via an elevated broker running as SYSTEM",
                Some(SESSION_DOCS),
            )));
        }
        let decision = match gate::enforce(
            &self.state.policy,
            tool,
            EffectTier::StateChanging,
            SESSION_TOKEN,
            a.confirm.as_deref(),
            &self.state.approvals,
        ) {
            Ok(d) => d,
            Err(b) => {
                self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None);
                return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(SESSION_DOCS))));
            }
        };
        let sid = match a.session_id.or_else(session::active_console_session) {
            Some(s) => s,
            None => {
                return Ok(text(error(
                    tool,
                    ErrorKind::SessionNotFound,
                    "no active console session",
                    "pass session_id (see session.list)",
                    Some(SESSION_DOCS),
                )))
            }
        };
        match session::launch_in_session(sid, &a.command) {
            Ok(pid) => {
                self.state.audit.record(
                    tool,
                    &format!("launched '{}' in session {sid} (pid {pid})", a.command),
                    Some(&format!("{:?}", decision.gate)),
                    "launched",
                    None,
                );
                Ok(text(
                    Outcome::new(tool, format!("launched '{}' in session {sid} as pid {pid}", a.command))
                        .data(json!({ "command": a.command, "sessionId": sid, "pid": pid }))
                        .command(format!("CreateProcessAsUser(session {sid}): {}", a.command))
                        .docs(SESSION_DOCS)
                        .to_value(),
                ))
            }
            Err(e) => {
                self.state.audit.record(tool, &format!("launch failed: {e}"), None, "failed", None);
                let low = e.to_lowercase();
                let k = if low.contains("setcb") || low.contains("privilege") {
                    ErrorKind::RequiresPrivilege
                } else if low.contains("denied") {
                    ErrorKind::AccessDenied
                } else {
                    ErrorKind::Internal
                };
                Ok(text(error(tool, k, e, "ensure SYSTEM context and a valid interactive session", Some(SESSION_DOCS))))
            }
        }
    }

    #[tool(
        name = "ttd.record",
        description = "Record a process to a Time Travel Debugging .run trace in the background (TTD -attach); returns a jobId. Needs TTD (ships with WinDbg) + elevation. Stop with ttd.stop/job.stop; replay with ttd.replay."
    )]
    async fn ttd_record(
        &self,
        Parameters(a): Parameters<TtdRecordArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "ttd.record";
        let ttd = match self.state.locator.find("TTD.exe") {
            Some(p) => p,
            None => {
                let mut v = error(tool, ErrorKind::ToolNotInstalled, "TTD.exe not found", "install WinDbg (winget install Microsoft.WinDbg) which includes TTD, or stage it in --tools-dir", Some(TTD_DOCS));
                v["error"]["wingetId"] = json!("Microsoft.WinDbg");
                return Ok(text(v));
            }
        };
        if !env_probe::is_elevated() {
            return Ok(text(error(tool, ErrorKind::RequiresElevation, "TTD needs an elevated token to record", "re-run Heisenberg elevated", Some(TTD_DOCS))));
        }
        let pid = match proc::resolve(a.pid, a.name.as_deref()) {
            Ok(p) => p,
            Err(proc::TargetError::NotFound(m)) => {
                return Ok(text(error(tool, ErrorKind::TargetNotFound, format!("no process matched {m}"), "pass a pid or name", Some(TTD_DOCS))))
            }
            Err(proc::TargetError::Ambiguous { name, pids }) => {
                let mut v = error(tool, ErrorKind::AmbiguousTarget, format!("'{name}' matches {} processes", pids.len()), "pass a specific pid", Some(TTD_DOCS));
                v["error"]["candidates"] = json!(pids);
                return Ok(text(v));
            }
        };
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let run = self.state.store.artifacts_dir().join(format!("ttd_{pid}_{ts}.run"));
        let mut cmdargs: Vec<String> = vec!["-out".into(), run.display().to_string()];
        if a.ring {
            cmdargs.push("-ring".into());
            if let Some(mb) = a.max_file_mb {
                cmdargs.push("-maxFile".into());
                cmdargs.push(mb.to_string());
            }
        }
        cmdargs.push("-attach".into());
        cmdargs.push(pid.to_string());
        let cmd_str = format!("TTD.exe {}", cmdargs.join(" "));
        match std::process::Command::new(&ttd).args(&cmdargs).spawn() {
            Ok(child) => {
                let tpid = child.id();
                let job = {
                    let mut j = self.state.jobs.lock().unwrap();
                    j.add("ttd", Some(tpid), Some(run.display().to_string()), &format!("TTD recording pid {pid} -> {}", run.display()))
                };
                self.state.audit.record(tool, &format!("started ttd job {}", job.id), None, "started", Some(&job.id));
                Ok(text(
                    Outcome::new(tool, format!("recording pid {pid} (job {})", job.id))
                        .data(json!({ "jobId": job.id, "targetPid": pid, "backingFile": run.display().to_string(), "resource": format!("heisenberg://captures/{}", job.id) }))
                        .command(cmd_str)
                        .docs(TTD_DOCS)
                        .warn("recording; stop with ttd.stop or job.stop, then replay with ttd.replay")
                        .to_value(),
                ))
            }
            Err(e) => Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch TTD: {e}"), "check the TTD path", Some(TTD_DOCS)))),
        }
    }

    #[tool(name = "ttd.stop", description = "Stop a TTD recording job and finalize its .run trace.")]
    async fn ttd_stop(&self, Parameters(a): Parameters<JobIdArgs>) -> Result<CallToolResult, McpError> {
        self.do_stop("ttd.stop", &a.id, false).await
    }

    #[tool(
        name = "ttd.replay",
        description = "Open a TTD .run trace in cdb and run commands (default: stacks). Accepts a trace path. Read-only; needs cdb."
    )]
    async fn ttd_replay(&self, Parameters(a): Parameters<DumpAnalyzeArgs>) -> Result<CallToolResult, McpError> {
        self.simple_analyze("ttd.replay", &a.dump, a.commands.as_deref(), "k; q").await
    }

    #[tool(
        name = "dotnet.dump",
        description = "Capture a managed (.NET) process dump with dotnet-dump. Read-only; needs the dotnet-dump global tool. Full dump — high-sensitivity."
    )]
    async fn dotnet_dump(&self, Parameters(a): Parameters<DotnetTargetArgs>) -> Result<CallToolResult, McpError> {
        let tool = "dotnet.dump";
        let dd = match self.state.locator.find("dotnet-dump.exe") {
            Some(p) => p,
            None => {
                let mut v = error(tool, ErrorKind::ToolNotInstalled, "dotnet-dump not found", "install it: dotnet tool install -g dotnet-dump", Some(DOTNET_DOCS));
                v["error"]["install"] = json!("dotnet tool install -g dotnet-dump");
                return Ok(text(v));
            }
        };
        let pid = match proc::resolve(a.pid, a.name.as_deref()) {
            Ok(p) => p,
            Err(proc::TargetError::NotFound(m)) => return Ok(text(error(tool, ErrorKind::TargetNotFound, format!("no process matched {m}"), "pass a pid or name", Some(DOTNET_DOCS)))),
            Err(proc::TargetError::Ambiguous { name, pids }) => {
                let mut v = error(tool, ErrorKind::AmbiguousTarget, format!("'{name}' matches {} processes", pids.len()), "pass a specific pid", Some(DOTNET_DOCS));
                v["error"]["candidates"] = json!(pids);
                return Ok(text(v));
            }
        };
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let out = self.state.store.artifacts_dir().join(format!("dotnet_{pid}_{ts}.dmp"));
        let cmd_str = format!("dotnet-dump collect -p {pid} -o \"{}\"", out.display());
        let output = match tokio::time::timeout(
            Duration::from_secs(180),
            Command::new(&dd).arg("collect").arg("-p").arg(pid.to_string()).arg("-o").arg(&out).output(),
        )
        .await
        {
            Err(_) => return Ok(text(error(tool, ErrorKind::Timeout, "dotnet-dump timed out", "retry", Some(DOTNET_DOCS)))),
            Ok(Err(e)) => return Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch dotnet-dump: {e}"), "check the tool", Some(DOTNET_DOCS)))),
            Ok(Ok(o)) => o,
        };
        if !output.status.success() || !out.is_file() {
            let combined = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            let k = if combined.to_lowercase().contains("access") { ErrorKind::AccessDenied } else { ErrorKind::AnalysisFailed };
            let mut v = error(tool, k, format!("dotnet-dump failed for pid {pid}"), "ensure the target is a .NET process and you have access (elevation may be needed)", Some(DOTNET_DOCS));
            v["error"]["output"] = json!(combined.trim());
            return Ok(text(v));
        }
        let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
        let rec = {
            let mut reg = self.state.dumps.lock().unwrap();
            reg.add(out.display().to_string(), pid, "full", "dotnet-dump", bytes)
        };
        self.state.audit.record(tool, &format!("captured managed dump of pid {pid}"), None, "captured", Some(&rec.id));
        Ok(text(
            Outcome::new(tool, format!("captured managed dump of pid {pid} ({:.1} MB)", bytes as f64 / 1048576.0))
                .data(json!({ "pid": pid, "backend": "dotnet-dump", "bytes": bytes, "path": out.display().to_string(), "dumpId": rec.id }))
                .artifact(Artifact { kind: "dump".to_string(), path: out.display().to_string(), bytes, resource: format!("heisenberg://dumps/{}", rec.id), sensitivity: Some("high".to_string()) })
                .command(cmd_str)
                .docs(DOTNET_DOCS)
                .warn("managed full dump may contain secrets; treat as high-sensitivity")
                .to_value(),
        ))
    }

    #[tool(
        name = "dotnet.gcHeap",
        description = "Collect a .NET GC heap snapshot (.gcdump) with dotnet-gcdump — for managed memory/leak analysis. Read-only; needs the dotnet-gcdump global tool."
    )]
    async fn dotnet_gcheap(&self, Parameters(a): Parameters<DotnetTargetArgs>) -> Result<CallToolResult, McpError> {
        let tool = "dotnet.gcHeap";
        let dg = match self.state.locator.find("dotnet-gcdump.exe") {
            Some(p) => p,
            None => {
                let mut v = error(tool, ErrorKind::ToolNotInstalled, "dotnet-gcdump not found", "install it: dotnet tool install -g dotnet-gcdump", Some(DOTNET_DOCS));
                v["error"]["install"] = json!("dotnet tool install -g dotnet-gcdump");
                return Ok(text(v));
            }
        };
        let pid = match proc::resolve(a.pid, a.name.as_deref()) {
            Ok(p) => p,
            Err(proc::TargetError::NotFound(m)) => return Ok(text(error(tool, ErrorKind::TargetNotFound, format!("no process matched {m}"), "pass a pid or name", Some(DOTNET_DOCS)))),
            Err(proc::TargetError::Ambiguous { name, pids }) => {
                let mut v = error(tool, ErrorKind::AmbiguousTarget, format!("'{name}' matches {} processes", pids.len()), "pass a specific pid", Some(DOTNET_DOCS));
                v["error"]["candidates"] = json!(pids);
                return Ok(text(v));
            }
        };
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let out = self.state.store.artifacts_dir().join(format!("gcheap_{pid}_{ts}.gcdump"));
        let cmd_str = format!("dotnet-gcdump collect -p {pid} -o \"{}\"", out.display());
        let output = match tokio::time::timeout(
            Duration::from_secs(120),
            Command::new(&dg).arg("collect").arg("-p").arg(pid.to_string()).arg("-o").arg(&out).output(),
        )
        .await
        {
            Err(_) => return Ok(text(error(tool, ErrorKind::Timeout, "dotnet-gcdump timed out", "retry", Some(DOTNET_DOCS)))),
            Ok(Err(e)) => return Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch dotnet-gcdump: {e}"), "check the tool", Some(DOTNET_DOCS)))),
            Ok(Ok(o)) => o,
        };
        if !output.status.success() || !out.is_file() {
            let combined = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            let mut v = error(tool, ErrorKind::AnalysisFailed, format!("dotnet-gcdump failed for pid {pid}"), "ensure the target is a .NET process", Some(DOTNET_DOCS));
            v["error"]["output"] = json!(combined.trim());
            return Ok(text(v));
        }
        let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
        self.state.audit.record(tool, &format!("gc heap snapshot of pid {pid}"), None, "captured", None);
        Ok(text(
            Outcome::new(tool, format!("collected GC heap snapshot of pid {pid} ({:.1} MB)", bytes as f64 / 1048576.0))
                .data(json!({ "pid": pid, "bytes": bytes, "path": out.display().to_string() }))
                .artifact(Artifact { kind: "gcdump".to_string(), path: out.display().to_string(), bytes, resource: out.display().to_string(), sensitivity: Some("medium".to_string()) })
                .command(cmd_str)
                .docs(DOTNET_DOCS)
                .to_value(),
        ))
    }

    #[tool(
        name = "dotnet.analyze",
        description = "Analyze a managed dump with dotnet-dump (default SOS: clrthreads, clrstack -all). Accepts a dump id or path. Read-only; needs dotnet-dump."
    )]
    async fn dotnet_analyze(&self, Parameters(a): Parameters<DotnetAnalyzeArgs>) -> Result<CallToolResult, McpError> {
        let tool = "dotnet.analyze";
        let dd = match self.state.locator.find("dotnet-dump.exe") {
            Some(p) => p,
            None => return Ok(text(error(tool, ErrorKind::ToolNotInstalled, "dotnet-dump not found", "dotnet tool install -g dotnet-dump", Some(DOTNET_DOCS)))),
        };
        let path = {
            let reg = self.state.dumps.lock().unwrap();
            let id = a.dump.trim_start_matches("heisenberg://dumps/");
            reg.get(id).map(|r| r.path.clone()).unwrap_or_else(|| a.dump.clone())
        };
        if !std::path::Path::new(&path).is_file() {
            return Ok(text(error(tool, ErrorKind::TargetNotFound, format!("no dump at {path}"), "capture with dotnet.dump or pass a path", Some(DOTNET_DOCS))));
        }
        let cmds = a.commands.clone().unwrap_or_else(|| vec!["clrthreads".to_string(), "clrstack -all".to_string()]);
        let mut args: Vec<String> = vec!["analyze".to_string(), path.clone()];
        for c in &cmds {
            args.push("-c".to_string());
            args.push(c.clone());
        }
        args.push("-c".to_string());
        args.push("exit".to_string());
        let output = match tokio::time::timeout(Duration::from_secs(300), Command::new(&dd).args(&args).output()).await {
            Err(_) => return Ok(text(error(tool, ErrorKind::Timeout, "dotnet-dump analyze timed out", "retry", Some(DOTNET_DOCS)))),
            Ok(Err(e)) => return Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch dotnet-dump: {e}"), "check the tool", Some(DOTNET_DOCS)))),
            Ok(Ok(o)) => o,
        };
        let raw = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        self.state.audit.record(tool, &format!("analyzed {path}"), None, "analyzed", None);
        Ok(text(
            Outcome::new(tool, format!("analyzed managed dump {path}"))
                .data(json!({ "path": path, "commands": cmds, "raw": last_chars(&raw, 8000) }))
                .command(format!("dotnet-dump analyze \"{path}\" -c ... -c exit"))
                .docs(DOTNET_DOCS)
                .to_value(),
        ))
    }

    #[tool(
        name = "collect.package",
        description = "Bundle a portable case: env snapshot + policy + change ledger + job/dump lists + audit journal into one zipped manifest (references artifacts by path/hash; does not copy multi-GB dumps). Read-only."
    )]
    async fn collect_package(
        &self,
        Parameters(a): Parameters<CollectPackageArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "collect.package";
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let case_dir = self.state.store.cases_dir().join(format!("case_{ts}"));
        if let Err(e) = std::fs::create_dir_all(&case_dir) {
            return Ok(text(error(tool, ErrorKind::Internal, format!("failed to create case dir: {e}"), "check HEISENBERG_HOME is writable", None)));
        }

        let manifest = json!({
            "generated": crate::store::now_rfc3339(),
            "host": crate::store::hostname(),
            "note": a.note,
            "env": serde_json::to_value(env_probe::probe()).unwrap_or_else(|_| json!({})),
            "policy": {
                "declaredClass": self.state.policy.class,
                "effectiveClass": self.state.policy.effective_class(),
                "source": self.state.policy.source,
            },
            "changes": self.state.ledger.lock().unwrap().list(),
            "jobs": self.state.jobs.lock().unwrap().list(),
            "dumps": self.state.dumps.lock().unwrap().list(),
            "audit": self.state.audit.tail(1000),
        });
        let manifest_path = case_dir.join("manifest.json");
        if let Err(e) = std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap_or_default()) {
            return Ok(text(error(tool, ErrorKind::Internal, format!("failed to write manifest: {e}"), "check disk space", None)));
        }

        let zip = self.state.store.cases_dir().join(format!("case_{ts}.zip"));
        let ps = format!(
            "Compress-Archive -Path '{}\\*' -DestinationPath '{}' -Force",
            case_dir.display(),
            zip.display()
        );
        let zipped = tokio::time::timeout(
            Duration::from_secs(120),
            Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &ps]).output(),
        )
        .await;
        let (artifact_path, bytes) = match zipped {
            Ok(Ok(o)) if o.status.success() && zip.is_file() => {
                (zip.display().to_string(), std::fs::metadata(&zip).map(|m| m.len()).unwrap_or(0))
            }
            _ => {
                // Fall back to the uncompressed case folder if zipping failed.
                (case_dir.display().to_string(), 0)
            }
        };
        self.state.audit.record(tool, &format!("packaged case to {artifact_path}"), None, "packaged", None);
        Ok(text(
            Outcome::new(tool, format!("packaged case -> {artifact_path}"))
                .data(json!({ "caseDir": case_dir.display().to_string(), "archive": artifact_path, "bytes": bytes, "manifest": manifest_path.display().to_string() }))
                .artifact(Artifact { kind: "case".to_string(), path: artifact_path.clone(), bytes, resource: artifact_path, sensitivity: Some("medium".to_string()) })
                .command(ps)
                .warn("the manifest references dumps/traces by path; include those files when sending the case off-box, and review for sensitive data first")
                .to_value(),
        ))
    }

    #[tool(
        name = "report.generate",
        description = "Generate a human-readable Markdown incident report (env, hypervisor, dumps, changes, recent audit) and write it as an artifact. Read-only."
    )]
    async fn report_generate(&self) -> Result<CallToolResult, McpError> {
        let tool = "report.generate";
        let env = env_probe::probe();
        let mut md = String::new();
        md.push_str(&format!("# Heisenberg report — {}\n\n", crate::store::hostname()));
        md.push_str(&format!("_Generated {} (UTC)_\n\n", crate::store::now_rfc3339()));
        md.push_str("## Machine\n\n");
        md.push_str(&format!(
            "- OS: {} build {} ({})\n- Arch: {} (native {})\n- Session {}{}\n- Integrity: {}\n- SeDebug: {} · SeTcb: {}\n\n",
            env.os.name, env.os.build, env.os.edition_id,
            env.arch.process_arch, env.arch.native_arch,
            env.session_id, if env.in_session0 { " (session 0)" } else { "" },
            env.integrity_level, env.privileges.se_debug.held, env.privileges.se_tcb.held,
        ));

        {
            let dumps = self.state.dumps.lock().unwrap();
            md.push_str(&format!("## Dumps ({})\n\n", dumps.list().len()));
            if !dumps.list().is_empty() {
                md.push_str("| id | pid | kind | MB | sensitivity | created |\n|---|---|---|---|---|---|\n");
                for d in dumps.list() {
                    md.push_str(&format!("| {} | {} | {} | {:.1} | {} | {} |\n", d.id, d.pid, d.kind, d.bytes as f64 / 1048576.0, d.sensitivity, d.created));
                }
                md.push('\n');
            }
        }
        {
            let ledger = self.state.ledger.lock().unwrap();
            md.push_str(&format!("## Changes ({})\n\n", ledger.list().len()));
            if !ledger.list().is_empty() {
                md.push_str("| id | tool | summary | status |\n|---|---|---|---|\n");
                for c in ledger.list() {
                    md.push_str(&format!("| {} | {} | {} | {:?} |\n", c.id, c.tool, c.summary, c.status));
                }
                md.push('\n');
            }
        }
        let recent = self.state.audit.tail(25);
        md.push_str(&format!("## Recent activity ({} of last 25)\n\n", recent.len()));
        for e in &recent {
            md.push_str(&format!(
                "- `{}` {} — {} ({})\n",
                e.get("ts").and_then(|v| v.as_str()).unwrap_or(""),
                e.get("tool").and_then(|v| v.as_str()).unwrap_or(""),
                e.get("summary").and_then(|v| v.as_str()).unwrap_or(""),
                e.get("outcome").and_then(|v| v.as_str()).unwrap_or(""),
            ));
        }

        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let path = self.state.store.cases_dir().join(format!("report_{ts}.md"));
        if let Err(e) = std::fs::write(&path, md.as_bytes()) {
            return Ok(text(error(tool, ErrorKind::Internal, format!("failed to write report: {e}"), "check HEISENBERG_HOME is writable", None)));
        }
        let bytes = md.len() as u64;
        self.state.audit.record(tool, &format!("generated report {}", path.display()), None, "generated", None);
        Ok(text(
            Outcome::new(tool, format!("generated report -> {}", path.display()))
                .data(json!({ "path": path.display().to_string(), "markdown": md }))
                .artifact(Artifact { kind: "report".to_string(), path: path.display().to_string(), bytes, resource: path.display().to_string(), sensitivity: Some("low".to_string()) })
                .to_value(),
        ))
    }

    #[tool(
        name = "artifacts.purge",
        description = "Delete captured artifacts (dumps/traces/etl/run/pml/gcdump/evtx) from the store to reclaim disk. Defaults to a dry-run preview; set dry_run=false to delete. Optionally filter by age."
    )]
    async fn artifacts_purge(
        &self,
        Parameters(a): Parameters<ArtifactsPurgeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "artifacts.purge";
        let exts = ["dmp", "etl", "run", "pml", "gcdump", "evtx", "nettrace"];
        let dir = self.state.store.artifacts_dir();
        let now = std::time::SystemTime::now();
        let mut candidates: Vec<(String, u64, f64)> = Vec::new(); // path, bytes, age_days
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for entry in rd.flatten() {
                let p = entry.path();
                let ext_ok = p
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| exts.contains(&e.to_ascii_lowercase().as_str()))
                    .unwrap_or(false);
                if !ext_ok {
                    continue;
                }
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let age_days = meta
                    .modified()
                    .ok()
                    .and_then(|m| now.duration_since(m).ok())
                    .map(|d| d.as_secs_f64() / 86400.0)
                    .unwrap_or(0.0);
                if let Some(days) = a.older_than_days {
                    if age_days < days as f64 {
                        continue;
                    }
                }
                candidates.push((p.display().to_string(), meta.len(), age_days));
            }
        }
        let total: u64 = candidates.iter().map(|(_, b, _)| *b).sum();
        let list: Vec<serde_json::Value> = candidates
            .iter()
            .map(|(p, b, age)| json!({ "path": p, "bytes": b, "ageDays": (age * 10.0).round() / 10.0 }))
            .collect();

        if a.dry_run {
            return Ok(text(
                Outcome::new(tool, format!("[dry-run] {} artifact(s), {:.1} MB would be purged", candidates.len(), total as f64 / 1048576.0))
                    .data(json!({ "dryRun": true, "count": candidates.len(), "totalBytes": total, "artifacts": list }))
                    .warn("dry-run: nothing deleted. Re-call with dry_run=false to delete.")
                    .to_value(),
            ));
        }

        let mut deleted = 0u64;
        let mut freed = 0u64;
        for (p, b, _) in &candidates {
            if std::fs::remove_file(p).is_ok() {
                deleted += 1;
                freed += *b;
            }
        }
        self.state.audit.record(tool, &format!("purged {deleted} artifacts, {freed} bytes"), None, "purged", None);
        Ok(text(
            Outcome::new(tool, format!("purged {deleted} artifact(s), freed {:.1} MB", freed as f64 / 1048576.0))
                .data(json!({ "dryRun": false, "deleted": deleted, "freedBytes": freed }))
                .to_value(),
        ))
    }

    /// Run a command and capture combined stdout+stderr (best-effort).
    async fn run_capture(&self, program: &str, args: &[&str], secs: u64) -> (bool, String) {
        match tokio::time::timeout(
            Duration::from_secs(secs),
            Command::new(program).args(args).output(),
        )
        .await
        {
            Ok(Ok(o)) => (
                o.status.success(),
                format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
            ),
            Ok(Err(e)) => (false, format!("launch error: {e}")),
            Err(_) => (false, "timed out".to_string()),
        }
    }

    #[tool(
        name = "system.triage",
        description = "First-response triage on a (possibly broken) box: OS/system info, services, tasklist /svc, boot config, driver list, detected hypervisor, and key log locations. Read-only. The first thing to run on arrival."
    )]
    async fn system_triage(&self) -> Result<CallToolResult, McpError> {
        let (_, systeminfo) = self.run_capture("systeminfo", &[], 60).await;
        let (_, services) = self.run_capture("sc", &["query", "state=", "all"], 30).await;
        let (_, tasks) = self.run_capture("tasklist", &["/svc"], 30).await;
        let (bcd_ok, bcd) = self.run_capture("bcdedit", &["/enum", "{current}"], 20).await;
        let (_, drivers) = self.run_capture("driverquery", &["/v"], 30).await;
        let sr = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let hv = kernel::detect_hypervisor();
        let v = Outcome::new(
            "system.triage",
            format!("triage gathered on {} ({hv})", crate::store::hostname()),
        )
        .data(json!({
            "hypervisor": hv,
            "systeminfo": last_chars(&systeminfo, 4000),
            "services": last_chars(&services, 4000),
            "tasklist": last_chars(&tasks, 4000),
            "bootConfig": if bcd_ok { bcd } else { format!("(needs elevation) {}", bcd.trim()) },
            "drivers": last_chars(&drivers, 3000),
            "logLocations": [
                format!("{sr}\\Logs\\CBS\\CBS.log"),
                format!("{sr}\\Minidump"),
                format!("{sr}\\LiveKernelReports"),
                format!("{sr}\\MEMORY.DMP"),
                r"%ProgramData%\Microsoft\Windows\WER\ReportQueue",
            ],
        }))
        .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "inspect.verify",
        description = "Verify an executable's Authenticode signature (status, signer, thumbprint) via Get-AuthenticodeSignature. Read-only."
    )]
    async fn inspect_verify(
        &self,
        Parameters(a): Parameters<PathArg>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "inspect.verify";
        if !std::path::Path::new(&a.path).is_file() {
            return Ok(text(error(tool, ErrorKind::TargetNotFound, format!("no file at {}", a.path), "pass a valid file path", None)));
        }
        let escaped = a.path.replace('\'', "''");
        let ps = format!(
            "(Get-AuthenticodeSignature -LiteralPath '{escaped}') | Select-Object Status,StatusMessage,@{{n='Signer';e={{$_.SignerCertificate.Subject}}}},@{{n='Thumbprint';e={{$_.SignerCertificate.Thumbprint}}}} | ConvertTo-Json -Compress"
        );
        let (_, out) = self
            .run_capture("powershell", &["-NoProfile", "-NonInteractive", "-Command", ps.as_str()], 30)
            .await;
        let parsed: serde_json::Value =
            serde_json::from_str(out.trim()).unwrap_or_else(|_| json!({ "raw": out.trim() }));
        let status = parsed.get("Status").and_then(|v| v.as_str()).unwrap_or("?").to_string();
        let v = Outcome::new(tool, format!("{}: {status}", a.path))
            .data(json!({ "path": a.path, "signature": parsed }))
            .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "inspect.network",
        description = "List active TCP/UDP connections with owning pids (netstat -ano). Read-only."
    )]
    async fn inspect_network(&self) -> Result<CallToolResult, McpError> {
        let (_, out) = self.run_capture("netstat", &["-ano"], 30).await;
        let conns = out
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                t.starts_with("TCP") || t.starts_with("UDP")
            })
            .count();
        let v = Outcome::new("inspect.network", format!("{conns} connection(s)"))
            .data(json!({ "connections": conns, "raw": last_chars(&out, 6000) }))
            .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "inspect.processTree",
        description = "Enumerate running processes as a tree (pid, ppid, name) from a Toolhelp snapshot. Read-only."
    )]
    async fn inspect_process_tree(&self) -> Result<CallToolResult, McpError> {
        use std::collections::HashMap;
        let procs = proc::list_processes_ext();
        let mut info: HashMap<u32, String> = HashMap::new();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for (pid, ppid, name) in &procs {
            info.insert(*pid, name.clone());
            children.entry(*ppid).or_default().push(*pid);
        }
        // Roots: processes whose parent is not itself a live pid (or self-parent).
        let roots: Vec<u32> = procs
            .iter()
            .filter(|(pid, ppid, _)| !info.contains_key(ppid) || ppid == pid)
            .map(|(pid, _, _)| *pid)
            .collect();
        let tree: Vec<serde_json::Value> = roots
            .iter()
            .map(|r| build_proc_node(*r, &info, &children, 0))
            .collect();
        let v = Outcome::new("inspect.processTree", format!("{} processes", procs.len()))
            .data(json!({ "count": procs.len(), "tree": tree }))
            .to_value();
        Ok(text(v))
    }

    #[tool(
        name = "postmortem.aeDebug",
        description = "Set the AeDebug JIT postmortem debugger (Debugger + Auto=1) so any unhandled crash drops to a scripted dump. State-changing, reversible via the ledger; needs elevation. dry_run + confirm."
    )]
    async fn postmortem_aedebug(
        &self,
        Parameters(a): Parameters<AeDebugArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "postmortem.aeDebug";
        let prior_debugger = regutil::hklm_read_sz(AEDEBUG_KEY, "Debugger");
        let prior_auto = regutil::hklm_read_sz(AEDEBUG_KEY, "Auto");
        let exists = regutil::hklm_key_exists(AEDEBUG_KEY);
        let debugger = match a.debugger.clone() {
            Some(d) => d,
            None => match self.state.locator.find("cdb.exe") {
                Some(c) => format!("\"{}\" -p %ld -e %ld -g", c.display()),
                None => {
                    return Ok(text(error(tool, ErrorKind::InvalidArgument, "no debugger given and cdb.exe not found", "pass `debugger`, or install the Debugging Tools for Windows", Some(POSTMORTEM_DOCS))))
                }
            },
        };
        let cmd = format!("reg add \"HKLM\\{AEDEBUG_KEY}\" /v Debugger /t REG_SZ /d \"{debugger}\" /f  (+ Auto=1)");

        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            return Ok(text(
                Outcome::new(tool, format!("[dry-run] would set AeDebug to {debugger} (gate: {:?})", decision.gate))
                    .data(json!({ "debugger": debugger, "prior": { "Debugger": prior_debugger, "Auto": prior_auto }, "gate": decision }))
                    .command(cmd)
                    .docs(POSTMORTEM_DOCS)
                    .warn("dry-run: no change made")
                    .to_value(),
            ));
        }
        if !env_probe::is_elevated() {
            return Ok(text(error(tool, ErrorKind::RequiresElevation, "writing AeDebug needs an elevated token", "re-run Heisenberg elevated", Some(POSTMORTEM_DOCS))));
        }
        let decision = match gate::enforce(&self.state.policy, tool, EffectTier::StateChanging, AEDEBUG_TOKEN, a.confirm.as_deref(), &self.state.approvals) {
            Ok(d) => d,
            Err(b) => {
                self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None);
                return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(POSTMORTEM_DOCS))));
            }
        };
        let id = {
            let mut l = self.state.ledger.lock().unwrap();
            l.begin(
                tool,
                "set AeDebug postmortem debugger",
                RevertPlan::RegRestore {
                    subkey: AEDEBUG_KEY.to_string(),
                    strings: vec![("Debugger".to_string(), prior_debugger), ("Auto".to_string(), prior_auto)],
                    dwords: vec![],
                    created_key: !exists,
                },
            )
        };
        let r = regutil::hklm_set_sz(AEDEBUG_KEY, "Debugger", &debugger)
            .and_then(|_| regutil::hklm_set_sz(AEDEBUG_KEY, "Auto", "1"));
        match r {
            Ok(_) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
                self.state.audit.record(tool, "AeDebug set", Some(&format!("{:?}", decision.gate)), "applied", Some(&id));
                Ok(text(
                    Outcome::new(tool, format!("set AeDebug postmortem debugger; change {id}"))
                        .data(json!({ "debugger": debugger, "changeId": id }))
                        .command(cmd)
                        .docs(POSTMORTEM_DOCS)
                        .warn("every unhandled user-mode crash now launches this debugger; revert with changes.revert when done")
                        .to_value(),
                ))
            }
            Err(e) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
                let (k, remedy) = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    (ErrorKind::RequiresElevation, "re-run elevated")
                } else {
                    (ErrorKind::Internal, "check AeDebug permissions")
                };
                Ok(text(error(tool, k, format!("failed to write AeDebug: {e}"), remedy, Some(POSTMORTEM_DOCS))))
            }
        }
    }

    #[tool(
        name = "dump.onCrashInstall",
        description = "Configure WER LocalDumps so future crashes of an image (or all processes) auto-write a dump. State-changing, reversible via the ledger; needs elevation. dry_run + confirm."
    )]
    async fn dump_on_crash_install(
        &self,
        Parameters(a): Parameters<OnCrashInstallArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "dump.onCrashInstall";
        let subkey = match &a.image {
            Some(img) => format!("{WER_LOCALDUMPS}\\{img}"),
            None => WER_LOCALDUMPS.to_string(),
        };
        let dumptype = if a.full { 2u32 } else { 1u32 };
        let folder = a.dump_folder.clone().unwrap_or_else(|| r"%LOCALAPPDATA%\CrashDumps".to_string());
        let prior_type = regutil::hklm_read_dword(&subkey, "DumpType");
        let prior_folder = regutil::hklm_read_sz(&subkey, "DumpFolder");
        let exists = regutil::hklm_key_exists(&subkey);
        let target = a.image.clone().unwrap_or_else(|| "all processes".to_string());
        let cmd = format!("reg add \"HKLM\\{subkey}\" /v DumpType /t REG_DWORD /d {dumptype} /f  (+ DumpFolder)");

        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            return Ok(text(
                Outcome::new(tool, format!("[dry-run] would auto-dump {target} ({}) to {folder}", if a.full { "full" } else { "mini" }))
                    .data(json!({ "target": target, "dumpType": dumptype, "dumpFolder": folder, "prior": { "DumpType": prior_type, "DumpFolder": prior_folder }, "gate": decision }))
                    .command(cmd)
                    .docs(POSTMORTEM_DOCS)
                    .warn("dry-run: no change made")
                    .to_value(),
            ));
        }
        if !env_probe::is_elevated() {
            return Ok(text(error(tool, ErrorKind::RequiresElevation, "writing WER LocalDumps needs an elevated token", "re-run Heisenberg elevated", Some(POSTMORTEM_DOCS))));
        }
        let decision = match gate::enforce(&self.state.policy, tool, EffectTier::StateChanging, WER_TOKEN, a.confirm.as_deref(), &self.state.approvals) {
            Ok(d) => d,
            Err(b) => {
                self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None);
                return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(POSTMORTEM_DOCS))));
            }
        };
        let id = {
            let mut l = self.state.ledger.lock().unwrap();
            l.begin(
                tool,
                &format!("WER LocalDumps for {target}"),
                RevertPlan::RegRestore {
                    subkey: subkey.clone(),
                    strings: vec![("DumpFolder".to_string(), prior_folder)],
                    dwords: vec![("DumpType".to_string(), prior_type)],
                    created_key: !exists,
                },
            )
        };
        let r = regutil::hklm_set_dword(&subkey, "DumpType", dumptype)
            .and_then(|_| regutil::hklm_set_sz(&subkey, "DumpFolder", &folder));
        match r {
            Ok(_) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
                self.state.audit.record(tool, &format!("WER LocalDumps set for {target}"), Some(&format!("{:?}", decision.gate)), "applied", Some(&id));
                Ok(text(
                    Outcome::new(tool, format!("future crashes of {target} will auto-dump to {folder}; change {id}"))
                        .data(json!({ "target": target, "dumpType": dumptype, "dumpFolder": folder, "changeId": id }))
                        .command(cmd)
                        .docs(POSTMORTEM_DOCS)
                        .warn("revert with changes.revert when done; dumps may contain secrets (high-sensitivity)")
                        .to_value(),
                ))
            }
            Err(e) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
                let (k, remedy) = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    (ErrorKind::RequiresElevation, "re-run elevated")
                } else {
                    (ErrorKind::Internal, "check WER LocalDumps permissions")
                };
                Ok(text(error(tool, k, format!("failed to write WER LocalDumps: {e}"), remedy, Some(POSTMORTEM_DOCS))))
            }
        }
    }

    #[tool(
        name = "dump.onTrigger",
        description = "Arm ProcDump to dump a process in the background when a trigger fires (unhandled/firstchance exception, CPU threshold, or hang); returns a jobId. Read-only capture; needs ProcDump staged. Stop with job.stop/job.cancel."
    )]
    async fn dump_on_trigger(
        &self,
        Parameters(a): Parameters<DumpOnTriggerArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "dump.onTrigger";
        let docs = "https://learn.microsoft.com/sysinternals/downloads/procdump";
        let pd = match self.state.locator.find("procdump.exe") {
            Some(p) => p,
            None => {
                let mut v = error(tool, ErrorKind::ToolNotInstalled, "procdump.exe not found", "install Sysinternals ProcDump or stage it in --tools-dir", Some(docs));
                v["error"]["wingetId"] = json!("Microsoft.Sysinternals.ProcDump");
                return Ok(text(v));
            }
        };
        let pid = match proc::resolve(a.pid, a.name.as_deref()) {
            Ok(p) => p,
            Err(proc::TargetError::NotFound(m)) => return Ok(text(error(tool, ErrorKind::TargetNotFound, format!("no process matched {m}"), "pass a pid or name", Some(docs)))),
            Err(proc::TargetError::Ambiguous { name, pids }) => {
                let mut v = error(tool, ErrorKind::AmbiguousTarget, format!("'{name}' matches {} processes", pids.len()), "pass a specific pid", Some(docs));
                v["error"]["candidates"] = json!(pids);
                return Ok(text(v));
            }
        };
        let on = a.on.clone().unwrap_or_else(|| "unhandled".to_string());
        let mut trig: Vec<String> = match on.to_lowercase().as_str() {
            "unhandled" | "exception" => vec!["-e".to_string()],
            "firstchance" => vec!["-e".to_string(), "1".to_string()],
            "cpu" => vec!["-c".to_string(), a.threshold.unwrap_or(80).to_string()],
            "hang" => vec!["-h".to_string()],
            _ => return Ok(text(error(tool, ErrorKind::InvalidArgument, format!("unknown trigger '{on}'"), "use unhandled|firstchance|cpu|hang", Some(docs)))),
        };
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let out = self.state.store.artifacts_dir().join(format!("trig_{pid}_{ts}.dmp"));
        let mut args: Vec<String> = vec!["-accepteula".to_string()];
        args.append(&mut trig);
        args.push(if a.full { "-ma".to_string() } else { "-mp".to_string() });
        args.push("-n".to_string());
        args.push("1".to_string());
        args.push(pid.to_string());
        args.push(out.display().to_string());
        let cmd_str = format!("procdump {}", args.join(" "));
        match std::process::Command::new(&pd).args(&args).spawn() {
            Ok(child) => {
                let tpid = child.id();
                let job = {
                    let mut j = self.state.jobs.lock().unwrap();
                    j.add("procdump", Some(tpid), Some(out.display().to_string()), &format!("procdump {on} trigger on pid {pid} -> {}", out.display()))
                };
                self.state.audit.record(tool, &format!("armed procdump job {}", job.id), None, "started", Some(&job.id));
                Ok(text(
                    Outcome::new(tool, format!("armed {on} trigger on pid {pid} (job {})", job.id))
                        .data(json!({ "jobId": job.id, "targetPid": pid, "trigger": on, "backingFile": out.display().to_string(), "resource": format!("heisenberg://captures/{}", job.id) }))
                        .command(cmd_str)
                        .docs(docs)
                        .warn("waiting for the trigger; the dump writes when it fires. Stop with job.stop/job.cancel. Full dumps are high-sensitivity.")
                        .to_value(),
                ))
            }
            Err(e) => Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch procdump: {e}"), "check the ProcDump path", Some(docs)))),
        }
    }

    #[tool(
        name = "service.startupDebug",
        description = "Attach a debugger to an image at process start via the IFEO Debugger value — for a service that crashes or hangs on startup. State-changing, reversible via the ledger; needs elevation. dry_run + confirm."
    )]
    async fn service_startup_debug(
        &self,
        Parameters(a): Parameters<ServiceDebugArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "service.startupDebug";
        let docs = "https://learn.microsoft.com/windows-hardware/drivers/debugger/debugging-a-service";
        let subkey = format!(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
            a.image
        );
        let prior = regutil::hklm_read_sz(&subkey, "Debugger");
        let exists = regutil::hklm_key_exists(&subkey);
        let debugger = match a.debugger.clone() {
            Some(d) => d,
            None => match self.state.locator.find("cdb.exe") {
                Some(c) => format!("\"{}\" -server tcp:port=5005 -g", c.display()),
                None => return Ok(text(error(tool, ErrorKind::InvalidArgument, "no debugger given and cdb.exe not found", "pass `debugger` or install the Debugging Tools for Windows", Some(docs)))),
            },
        };
        let cmd = format!("reg add \"HKLM\\{subkey}\" /v Debugger /t REG_SZ /d \"{debugger}\" /f");

        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            return Ok(text(
                Outcome::new(tool, format!("[dry-run] would attach a debugger to {} at start (gate: {:?})", a.image, decision.gate))
                    .data(json!({ "image": a.image, "debugger": debugger, "prior": prior, "gate": decision }))
                    .command(cmd)
                    .docs(docs)
                    .warn("dry-run: no change made")
                    .to_value(),
            ));
        }
        if !env_probe::is_elevated() {
            return Ok(text(error(tool, ErrorKind::RequiresElevation, "writing IFEO needs an elevated token", "re-run Heisenberg elevated", Some(docs))));
        }
        let decision = match gate::enforce(&self.state.policy, tool, EffectTier::StateChanging, "set-service-debugger", a.confirm.as_deref(), &self.state.approvals) {
            Ok(d) => d,
            Err(b) => {
                self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None);
                return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(docs))));
            }
        };
        let id = {
            let mut l = self.state.ledger.lock().unwrap();
            l.begin(
                tool,
                &format!("IFEO Debugger for {}", a.image),
                RevertPlan::RegRestore {
                    subkey: subkey.clone(),
                    strings: vec![("Debugger".to_string(), prior)],
                    dwords: vec![],
                    created_key: !exists,
                },
            )
        };
        match regutil::hklm_set_sz(&subkey, "Debugger", &debugger) {
            Ok(_) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
                self.state.audit.record(tool, &format!("service debugger set for {}", a.image), Some(&format!("{:?}", decision.gate)), "applied", Some(&id));
                Ok(text(
                    Outcome::new(tool, format!("attached a debugger to {} at start; change {id}", a.image))
                        .data(json!({ "image": a.image, "debugger": debugger, "changeId": id }))
                        .command(cmd)
                        .docs(docs)
                        .warn("the debugger launches when the image starts; if a service times out at start, also raise HKLM\\SYSTEM\\CurrentControlSet\\Control\\ServicesPipeTimeout. Revert with changes.revert.")
                        .to_value(),
                ))
            }
            Err(e) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
                let (k, remedy) = if e.kind() == std::io::ErrorKind::PermissionDenied {
                    (ErrorKind::RequiresElevation, "re-run elevated")
                } else {
                    (ErrorKind::Internal, "check IFEO permissions")
                };
                Ok(text(error(tool, k, format!("failed to write IFEO Debugger: {e}"), remedy, Some(docs))))
            }
        }
    }

    #[tool(
        name = "remote.debugServer",
        description = "Start a user-mode process server (dbgsrv) in the background so a remote WinDbg can debug processes on this box; returns a jobId and the connect string. Needs dbgsrv (ships with the Debugging Tools). Stop with job.stop/job.cancel."
    )]
    async fn remote_debug_server(
        &self,
        Parameters(a): Parameters<RemoteServerArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "remote.debugServer";
        let docs = "https://learn.microsoft.com/windows-hardware/drivers/debugger/-server--start-the-process-server";
        let ds = match self.state.locator.find("dbgsrv.exe") {
            Some(p) => p,
            None => {
                let mut v = error(tool, ErrorKind::ToolNotInstalled, "dbgsrv.exe not found", "install the Debugging Tools for Windows (winget install Microsoft.WinDbg)", Some(docs));
                v["error"]["wingetId"] = json!("Microsoft.WinDbg");
                return Ok(text(v));
            }
        };
        let conn = format!("tcp:port={}", a.port);
        let cmd_str = format!("dbgsrv -t {conn}");
        match std::process::Command::new(&ds).arg("-t").arg(&conn).spawn() {
            Ok(child) => {
                let tpid = child.id();
                let job = {
                    let mut j = self.state.jobs.lock().unwrap();
                    j.add("dbgsrv", Some(tpid), None, &format!("dbgsrv process server on {conn}"))
                };
                self.state.audit.record(tool, &format!("started dbgsrv job {}", job.id), None, "started", Some(&job.id));
                let host = crate::store::hostname();
                Ok(text(
                    Outcome::new(tool, format!("process server listening on {conn} (job {})", job.id))
                        .data(json!({
                            "jobId": job.id, "port": a.port, "pid": tpid,
                            "connect": format!("remote WinDbg: File > Connect to Remote Stub -> tcp:port={},server={host}   (or windbg -premote tcp:port={},server={host})", a.port, a.port),
                            "resource": format!("heisenberg://captures/{}", job.id)
                        }))
                        .command(cmd_str)
                        .docs(docs)
                        .warn("the server exposes this machine's processes to the remote debugger; firewall the port and stop it (job.stop) when done")
                        .to_value(),
                ))
            }
            Err(e) => Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch dbgsrv: {e}"), "check the dbgsrv path", Some(docs)))),
        }
    }

    #[tool(
        name = "leak.heapTrackStart",
        description = "Enable the user-mode stack-trace DB (IFEO GlobalFlag 'ust') for an image so UMDH can attribute heap allocations. State-changing, reversible; needs elevation. Restart the target, then use leak.heapSnapshot. dry_run + confirm."
    )]
    async fn leak_heap_track_start(
        &self,
        Parameters(a): Parameters<AppVerifierArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "leak.heapTrackStart";
        let docs = "https://learn.microsoft.com/windows-hardware/drivers/debugger/umdh";
        let subkey = format!(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{}",
            a.image
        );
        let prior_gf = regutil::hklm_read_dword(&subkey, "GlobalFlag");
        let exists = regutil::hklm_key_exists(&subkey);
        let new_gf = prior_gf.unwrap_or(0) | FLG_USER_STACK_TRACE_DB;
        let cmd = format!("gflags /i {} +ust", a.image);
        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            return Ok(text(
                Outcome::new(tool, format!("[dry-run] would enable heap stack DB for {} (gate: {:?})", a.image, decision.gate))
                    .data(json!({ "image": a.image, "priorGlobalFlag": prior_gf, "wouldSet": new_gf, "gate": decision }))
                    .command(cmd).docs(docs).warn("dry-run: no change made").to_value(),
            ));
        }
        if !env_probe::is_elevated() {
            return Ok(text(error(tool, ErrorKind::RequiresElevation, "writing IFEO needs an elevated token", "re-run elevated", Some(docs))));
        }
        let decision = match gate::enforce(&self.state.policy, tool, EffectTier::StateChanging, "enable-heap-track", a.confirm.as_deref(), &self.state.approvals) {
            Ok(d) => d,
            Err(b) => { self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None); return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(docs)))); }
        };
        let id = { let mut l = self.state.ledger.lock().unwrap(); l.begin(tool, &format!("enable heap stack DB for {}", a.image), RevertPlan::RegRestore { subkey: subkey.clone(), strings: vec![], dwords: vec![("GlobalFlag".to_string(), prior_gf)], created_key: !exists }) };
        match regutil::hklm_set_dword(&subkey, "GlobalFlag", new_gf) {
            Ok(_) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
                self.state.audit.record(tool, &format!("ust enabled for {}", a.image), Some(&format!("{:?}", decision.gate)), "applied", Some(&id));
                Ok(text(Outcome::new(tool, format!("enabled heap stack DB for {}; change {id}", a.image)).data(json!({ "image": a.image, "globalFlag": new_gf, "changeId": id })).command(cmd).docs(docs).warn("restart the target so the stack DB takes effect, then snapshot with leak.heapSnapshot; revert with changes.revert").to_value()))
            }
            Err(e) => {
                self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
                let (k, remedy) = if e.kind() == std::io::ErrorKind::PermissionDenied { (ErrorKind::RequiresElevation, "re-run elevated") } else { (ErrorKind::Internal, "check IFEO permissions") };
                Ok(text(error(tool, k, format!("failed to write IFEO: {e}"), remedy, Some(docs))))
            }
        }
    }

    #[tool(
        name = "leak.heapSnapshot",
        description = "Take a UMDH heap snapshot of a process (needs ust enabled via leak.heapTrackStart and the target restarted). Read-only; needs umdh."
    )]
    async fn leak_heap_snapshot(
        &self,
        Parameters(a): Parameters<DotnetTargetArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "leak.heapSnapshot";
        let docs = "https://learn.microsoft.com/windows-hardware/drivers/debugger/umdh";
        let umdh = match self.state.locator.find("umdh.exe") {
            Some(p) => p,
            None => { let mut v = error(tool, ErrorKind::ToolNotInstalled, "umdh.exe not found", "install the Debugging Tools for Windows", Some(docs)); v["error"]["wingetId"] = json!("Microsoft.WinDbg"); return Ok(text(v)); }
        };
        let pid = match proc::resolve(a.pid, a.name.as_deref()) {
            Ok(p) => p,
            Err(proc::TargetError::NotFound(m)) => return Ok(text(error(tool, ErrorKind::TargetNotFound, format!("no process matched {m}"), "pass a pid or name", Some(docs)))),
            Err(proc::TargetError::Ambiguous { name, pids }) => { let mut v = error(tool, ErrorKind::AmbiguousTarget, format!("'{name}' matches {} processes", pids.len()), "pass a specific pid", Some(docs)); v["error"]["candidates"] = json!(pids); return Ok(text(v)); }
        };
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let out = self.state.store.artifacts_dir().join(format!("umdh_{pid}_{ts}.log"));
        let output = tokio::time::timeout(Duration::from_secs(120), Command::new(&umdh).arg(format!("-p:{pid}")).arg(format!("-f:{}", out.display())).output()).await;
        match output {
            Ok(Ok(o)) if o.status.success() && out.is_file() => {
                let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
                self.state.audit.record(tool, &format!("umdh snapshot of pid {pid}"), None, "captured", None);
                Ok(text(Outcome::new(tool, format!("UMDH snapshot of pid {pid} ({bytes} bytes)")).data(json!({ "pid": pid, "path": out.display().to_string(), "bytes": bytes })).artifact(Artifact { kind: "umdh".to_string(), path: out.display().to_string(), bytes, resource: out.display().to_string(), sensitivity: Some("low".to_string()) }).docs(docs).warn("take a baseline and a later snapshot, then diff with leak.heapDiff").to_value()))
            }
            Ok(Ok(o)) => Ok(text(error(tool, ErrorKind::AnalysisFailed, format!("umdh failed for pid {pid}: {}", String::from_utf8_lossy(&o.stderr).trim()), "ensure ust is enabled (leak.heapTrackStart) and the target was restarted", Some(docs)))),
            Ok(Err(e)) => Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch umdh: {e}"), "check the umdh path", Some(docs)))),
            Err(_) => Ok(text(error(tool, ErrorKind::Timeout, "umdh timed out", "retry", Some(docs)))),
        }
    }

    #[tool(
        name = "leak.heapDiff",
        description = "Diff two UMDH snapshots to surface leaked allocation stacks. Read-only; needs umdh."
    )]
    async fn leak_heap_diff(
        &self,
        Parameters(a): Parameters<LeakDiffArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "leak.heapDiff";
        let docs = "https://learn.microsoft.com/windows-hardware/drivers/debugger/umdh";
        let umdh = match self.state.locator.find("umdh.exe") {
            Some(p) => p,
            None => return Ok(text(error(tool, ErrorKind::ToolNotInstalled, "umdh.exe not found", "install the Debugging Tools for Windows", Some(docs)))),
        };
        if !std::path::Path::new(&a.baseline).is_file() || !std::path::Path::new(&a.current).is_file() {
            return Ok(text(error(tool, ErrorKind::TargetNotFound, "baseline or current snapshot not found", "pass two valid UMDH snapshot paths", Some(docs))));
        }
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let out = self.state.store.artifacts_dir().join(format!("umdh_diff_{ts}.log"));
        let output = tokio::time::timeout(Duration::from_secs(120), Command::new(&umdh).arg(&a.baseline).arg(&a.current).arg(format!("-f:{}", out.display())).output()).await;
        match output {
            Ok(Ok(o)) if o.status.success() && out.is_file() => {
                let raw = std::fs::read_to_string(&out).unwrap_or_default();
                self.state.audit.record(tool, "umdh diff", None, "analyzed", None);
                Ok(text(Outcome::new(tool, format!("UMDH diff -> {}", out.display())).data(json!({ "path": out.display().to_string(), "raw": last_chars(&raw, 8000) })).artifact(Artifact { kind: "umdh-diff".to_string(), path: out.display().to_string(), bytes: raw.len() as u64, resource: out.display().to_string(), sensitivity: Some("low".to_string()) }).docs(docs).to_value()))
            }
            Ok(Ok(o)) => Ok(text(error(tool, ErrorKind::AnalysisFailed, format!("umdh diff failed: {}", String::from_utf8_lossy(&o.stderr).trim()), "ensure both snapshots are valid", Some(docs)))),
            Ok(Err(e)) => Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch umdh: {e}"), "check umdh", Some(docs)))),
            Err(_) => Ok(text(error(tool, ErrorKind::Timeout, "umdh diff timed out", "retry", Some(docs)))),
        }
    }

    #[tool(
        name = "boot.trace",
        description = "Configure a WPR boot trace (action: arm | collect | cancel). 'arm' needs a reboot; 'collect' finalizes the .etl after reboot. State-changing; needs elevation. dry_run + confirm."
    )]
    async fn boot_trace(
        &self,
        Parameters(a): Parameters<BootTraceArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "boot.trace";
        let docs = WPR_DOCS;
        let action = a.action.to_lowercase();
        if !matches!(action.as_str(), "arm" | "collect" | "cancel") {
            return Ok(text(error(tool, ErrorKind::InvalidArgument, format!("unknown action '{}'", a.action), "use arm|collect|cancel", Some(docs))));
        }
        let profile = a.profile.clone().unwrap_or_else(|| "GeneralProfile".to_string());
        if a.dry_run {
            let decision = self.state.policy.decide(tool, EffectTier::StateChanging);
            let preview = match action.as_str() {
                "arm" => format!("wpr -boottrace -addboot {profile} -filemode"),
                "collect" => "wpr -boottrace -stopboot <out.etl>".to_string(),
                _ => "wpr -boottrace -cancelboot".to_string(),
            };
            return Ok(text(Outcome::new(tool, format!("[dry-run] boot.trace {action} (gate: {:?})", decision.gate)).data(json!({ "action": action, "profile": profile, "gate": decision })).command(preview).docs(docs).warn("dry-run: no change made").to_value()));
        }
        if !env_probe::is_elevated() {
            return Ok(text(error(tool, ErrorKind::RequiresElevation, "WPR boot trace needs an elevated token", "re-run elevated", Some(docs))));
        }
        match action.as_str() {
            "arm" => {
                let decision = match gate::enforce(&self.state.policy, tool, EffectTier::StateChanging, "boot-trace", a.confirm.as_deref(), &self.state.approvals) {
                    Ok(d) => d,
                    Err(b) => { self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None); return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(docs)))); }
                };
                let id = { let mut l = self.state.ledger.lock().unwrap(); l.begin(tool, "arm WPR boot trace", RevertPlan::Command { program: "wpr".to_string(), args: vec!["-boottrace".to_string(), "-cancelboot".to_string()], describe: "cancel the armed boot trace".to_string() }) };
                let (ok, o) = self.run_capture("wpr", &["-boottrace", "-addboot", &profile, "-filemode"], 60).await;
                if ok {
                    self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Applied);
                    self.state.audit.record(tool, "boot trace armed", Some(&format!("{:?}", decision.gate)), "applied", Some(&id));
                    Ok(text(Outcome::new(tool, format!("armed WPR boot trace ({profile}); change {id}")).data(json!({ "profile": profile, "changeId": id })).command(format!("wpr -boottrace -addboot {profile} -filemode")).docs(docs).warn("reboot the machine, then run boot.trace action=collect to write the .etl; or changes.revert / action=cancel to abort").to_value()))
                } else {
                    self.state.ledger.lock().unwrap().mark(&id, ChangeStatus::Failed);
                    Ok(text(error(tool, ErrorKind::Internal, format!("wpr -addboot failed: {}", o.trim()), "run elevated; check the profile", Some(docs))))
                }
            }
            "collect" => {
                let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
                let etl = self.state.store.artifacts_dir().join(format!("boot_{ts}.etl"));
                let (ok, o) = self.run_capture("wpr", &["-boottrace", "-stopboot", &etl.display().to_string()], 300).await;
                if ok && etl.is_file() {
                    let bytes = std::fs::metadata(&etl).map(|m| m.len()).unwrap_or(0);
                    self.state.audit.record(tool, "boot trace collected", None, "collected", None);
                    Ok(text(Outcome::new(tool, format!("collected boot trace -> {} ({:.1} MB)", etl.display(), bytes as f64 / 1048576.0)).data(json!({ "path": etl.display().to_string(), "bytes": bytes })).artifact(Artifact { kind: "trace".to_string(), path: etl.display().to_string(), bytes, resource: etl.display().to_string(), sensitivity: Some("medium".to_string()) }).docs(docs).to_value()))
                } else {
                    Ok(text(error(tool, ErrorKind::Internal, format!("wpr -stopboot failed: {}", o.trim()), "was a boot trace armed and the machine rebooted?", Some(docs))))
                }
            }
            _ => {
                let (ok, o) = self.run_capture("wpr", &["-boottrace", "-cancelboot"], 60).await;
                self.state.audit.record(tool, "boot trace cancelled", None, if ok { "cancelled" } else { "failed" }, None);
                if ok { Ok(text(Outcome::new(tool, "cancelled the armed boot trace").docs(docs).to_value())) }
                else { Ok(text(error(tool, ErrorKind::Internal, format!("wpr -cancelboot failed: {}", o.trim()), "no boot trace may be armed", Some(docs)))) }
            }
        }
    }

    #[tool(
        name = "remote.logCollect",
        description = "Query an event-log channel on a REMOTE host via wevtutil /r. Read-only; needs network reachability and permissions on the target."
    )]
    async fn remote_log_collect(
        &self,
        Parameters(a): Parameters<RemoteLogArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "remote.logCollect";
        let docs = WEVTUTIL_DOCS;
        let rflag = format!("/r:{}", a.host);
        let cflag = format!("/c:{}", a.count);
        let (ok, o) = self.run_capture("wevtutil", &["qe", a.channel.as_str(), &rflag, &cflag, "/rd:true", "/f:text"], 60).await;
        if !ok {
            let low = o.to_lowercase();
            let k = if low.contains("access is denied") { ErrorKind::AccessDenied } else if low.contains("rpc") || low.contains("could not connect") { ErrorKind::Internal } else { ErrorKind::InvalidArgument };
            return Ok(text(error(tool, k, format!("remote wevtutil failed: {}", o.trim()), "check the host, network, and permissions (WinRM/RPC)", Some(docs))));
        }
        let events = o.matches("Event[").count();
        Ok(text(Outcome::new(tool, format!("{events} event(s) from {} on {}", a.channel, a.host)).data(json!({ "host": a.host, "channel": a.channel, "count": events, "raw": last_chars(&o, 8000) })).docs(docs).to_value()))
    }

    #[tool(
        name = "remote.dumpCapture",
        description = "Capture a full dump of a process on a REMOTE host via PsExec + ProcDump (both must be available on the target); the dump lands on the remote host for UNC retrieval. State-changing on the remote; needs PsExec + admin on the target. confirm per box class."
    )]
    async fn remote_dump_capture(
        &self,
        Parameters(a): Parameters<RemoteDumpArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "remote.dumpCapture";
        let docs = "https://learn.microsoft.com/sysinternals/downloads/psexec";
        let ps = match self.state.locator.find("PsExec.exe") {
            Some(p) => p,
            None => { let mut v = error(tool, ErrorKind::ToolNotInstalled, "PsExec.exe not found", "stage Sysinternals PsExec in --tools-dir", Some(docs)); v["error"]["wingetId"] = json!("Microsoft.Sysinternals.PsExec"); return Ok(text(v)); }
        };
        let target = match (a.pid, &a.name) {
            (Some(p), _) => p.to_string(),
            (None, Some(n)) => n.clone(),
            (None, None) => return Ok(text(error(tool, ErrorKind::InvalidArgument, "no pid or name given", "pass pid or name of the remote process", Some(docs)))),
        };
        let decision = match gate::enforce(&self.state.policy, tool, EffectTier::StateChanging, "remote-dump", a.confirm.as_deref(), &self.state.approvals) {
            Ok(d) => d,
            Err(b) => { self.state.audit.record(tool, &b.reason, Some(&format!("{:?}", b.gate)), "blocked", None); return Ok(text(error(tool, b.kind, b.reason, b.remedy, Some(docs)))); }
        };
        let remote_path = format!(r"C:\Windows\Temp\heisenberg_{target}.dmp");
        let host_arg = format!(r"\\{}", a.host);
        let (ok, o) = self.run_capture(
            &ps.display().to_string(),
            &[&host_arg, "-s", "-nobanner", "-accepteula", "procdump", "-accepteula", "-ma", &target, &remote_path],
            180,
        ).await;
        self.state.audit.record(tool, &format!("remote dump of {target} on {}", a.host), Some(&format!("{:?}", decision.gate)), if ok { "captured" } else { "failed" }, None);
        if ok {
            Ok(text(Outcome::new(tool, format!("captured remote dump of {target} on {}", a.host)).data(json!({ "host": a.host, "target": target, "remotePath": remote_path, "unc": format!(r"\\{}\C$\Windows\Temp\heisenberg_{target}.dmp", a.host) })).command(format!("psexec \\\\{} -s procdump -ma {target} {remote_path}", a.host)).docs(docs).warn("the dump is on the REMOTE host; retrieve it via UNC (\\\\host\\C$\\...). Full dumps are high-sensitivity.").to_value()))
        } else {
            Ok(text(error(tool, ErrorKind::AnalysisFailed, format!("remote capture failed: {}", o.trim()), "ensure PsExec admin access and ProcDump on the target", Some(docs))))
        }
    }

    #[tool(
        name = "gpu.tdrAnalyze",
        description = "Analyze a kernel dump for a GPU TDR / display timeout (bugcheck 0x116 VIDEO_TDR_FAILURE / 0x117 VIDEO_TDR_TIMEOUT). Read-only; needs cdb."
    )]
    async fn gpu_tdr_analyze(
        &self,
        Parameters(a): Parameters<DumpAnalyzeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "gpu.tdrAnalyze";
        let cmds = a.commands.clone().unwrap_or_else(|| "!analyze -v; q".to_string());
        match self.run_cdb_on(tool, &a.dump, &cmds).await {
            Ok((path, raw, cmd_str)) => {
                let up = raw.to_uppercase();
                let tdr = up.contains("VIDEO_TDR") || raw.contains("0x116") || raw.contains("0x117");
                let mut out = Outcome::new(tool, format!("{}TDR analysis of {path}", if tdr { "" } else { "no " }))
                    .data(json!({ "path": path, "tdrDetected": tdr, "raw": last_chars(&raw, 8000) }))
                    .command(cmd_str)
                    .docs("https://learn.microsoft.com/windows-hardware/drivers/display/tdr-debugging");
                if tdr { out = out.warn("VIDEO_TDR detected — a GPU stopped responding and was reset; inspect the graphics driver and !analyze output"); }
                self.state.audit.record(tool, &format!("tdr analysis {path}"), None, "analyzed", None);
                Ok(text(out.to_value()))
            }
            Err(ct) => Ok(ct),
        }
    }

    #[tool(
        name = "inspect.autoruns",
        description = "Enumerate autostart / persistence points (Autoruns) as CSV. Read-only; needs autorunsc staged."
    )]
    async fn inspect_autoruns(&self) -> Result<CallToolResult, McpError> {
        let tool = "inspect.autoruns";
        let docs = "https://learn.microsoft.com/sysinternals/downloads/autoruns";
        let ar = match self.state.locator.find("autorunsc.exe") {
            Some(p) => p,
            None => { let mut v = error(tool, ErrorKind::ToolNotInstalled, "autorunsc.exe not found", "stage Sysinternals Autoruns in --tools-dir", Some(docs)); v["error"]["wingetId"] = json!("Microsoft.Sysinternals.Autoruns"); return Ok(text(v)); }
        };
        let output = tokio::time::timeout(Duration::from_secs(120), Command::new(&ar).args(["-accepteula", "-nobanner", "-a", "*", "-c"]).output()).await;
        match output {
            Ok(Ok(o)) => {
                let raw = String::from_utf8_lossy(&o.stdout).to_string();
                let entries = raw.lines().count().saturating_sub(1);
                self.state.audit.record(tool, "autoruns enumerated", None, "captured", None);
                Ok(text(Outcome::new(tool, format!("{entries} autostart entries")).data(json!({ "entries": entries, "csv": last_chars(&raw, 8000) })).docs(docs).to_value()))
            }
            Ok(Err(e)) => Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch autorunsc: {e}"), "check the autorunsc path", Some(docs)))),
            Err(_) => Ok(text(error(tool, ErrorKind::Timeout, "autorunsc timed out", "retry", Some(docs)))),
        }
    }

    #[tool(
        name = "dotnet.trace",
        description = "Collect a timed CPU/allocation trace of a .NET process (dotnet-trace) to a .nettrace. Read-only; needs the dotnet-trace global tool."
    )]
    async fn dotnet_trace(
        &self,
        Parameters(a): Parameters<DotnetTimedArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "dotnet.trace";
        let dt = match self.state.locator.find("dotnet-trace.exe") {
            Some(p) => p,
            None => {
                let mut v = error(tool, ErrorKind::ToolNotInstalled, "dotnet-trace not found", "install it: dotnet tool install -g dotnet-trace", Some(DOTNET_DOCS));
                v["error"]["install"] = json!("dotnet tool install -g dotnet-trace");
                return Ok(text(v));
            }
        };
        let pid = match proc::resolve(a.pid, a.name.as_deref()) {
            Ok(p) => p,
            Err(proc::TargetError::NotFound(m)) => return Ok(text(error(tool, ErrorKind::TargetNotFound, format!("no process matched {m}"), "pass a pid or name", Some(DOTNET_DOCS)))),
            Err(proc::TargetError::Ambiguous { name, pids }) => { let mut v = error(tool, ErrorKind::AmbiguousTarget, format!("'{name}' matches {} processes", pids.len()), "pass a specific pid", Some(DOTNET_DOCS)); v["error"]["candidates"] = json!(pids); return Ok(text(v)); }
        };
        let secs = a.duration_sec.clamp(1, 600);
        let dur = format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60);
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let out = self.state.store.artifacts_dir().join(format!("trace_{pid}_{ts}.nettrace"));
        let cmd = format!("dotnet-trace collect -p {pid} --duration {dur} -o \"{}\"", out.display());
        let output = tokio::time::timeout(Duration::from_secs(secs + 90), Command::new(&dt).arg("collect").arg("-p").arg(pid.to_string()).arg("--duration").arg(&dur).arg("-o").arg(&out).output()).await;
        match output {
            Ok(Ok(o)) if o.status.success() && out.is_file() => {
                let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
                self.state.audit.record(tool, &format!("traced pid {pid} for {secs}s"), None, "captured", None);
                Ok(text(Outcome::new(tool, format!("collected a {secs}s .NET trace of pid {pid} ({:.1} MB)", bytes as f64 / 1048576.0)).data(json!({ "pid": pid, "durationSec": secs, "path": out.display().to_string(), "bytes": bytes })).artifact(Artifact { kind: "nettrace".to_string(), path: out.display().to_string(), bytes, resource: out.display().to_string(), sensitivity: Some("medium".to_string()) }).command(cmd).docs(DOTNET_DOCS).to_value()))
            }
            Ok(Ok(o)) => Ok(text(error(tool, ErrorKind::AnalysisFailed, format!("dotnet-trace failed: {}", String::from_utf8_lossy(&o.stderr).trim()), "ensure the target is a .NET process", Some(DOTNET_DOCS)))),
            Ok(Err(e)) => Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch dotnet-trace: {e}"), "check the tool", Some(DOTNET_DOCS)))),
            Err(_) => Ok(text(error(tool, ErrorKind::Timeout, "dotnet-trace timed out", "retry with a shorter duration", Some(DOTNET_DOCS)))),
        }
    }

    #[tool(
        name = "dotnet.counters",
        description = "Collect .NET performance counters for a duration (dotnet-counters) to CSV. Read-only; needs the dotnet-counters global tool."
    )]
    async fn dotnet_counters(
        &self,
        Parameters(a): Parameters<DotnetTimedArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "dotnet.counters";
        let dc = match self.state.locator.find("dotnet-counters.exe") {
            Some(p) => p,
            None => {
                let mut v = error(tool, ErrorKind::ToolNotInstalled, "dotnet-counters not found", "install it: dotnet tool install -g dotnet-counters", Some(DOTNET_DOCS));
                v["error"]["install"] = json!("dotnet tool install -g dotnet-counters");
                return Ok(text(v));
            }
        };
        let pid = match proc::resolve(a.pid, a.name.as_deref()) {
            Ok(p) => p,
            Err(proc::TargetError::NotFound(m)) => return Ok(text(error(tool, ErrorKind::TargetNotFound, format!("no process matched {m}"), "pass a pid or name", Some(DOTNET_DOCS)))),
            Err(proc::TargetError::Ambiguous { name, pids }) => { let mut v = error(tool, ErrorKind::AmbiguousTarget, format!("'{name}' matches {} processes", pids.len()), "pass a specific pid", Some(DOTNET_DOCS)); v["error"]["candidates"] = json!(pids); return Ok(text(v)); }
        };
        let secs = a.duration_sec.clamp(1, 600);
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
        let out = self.state.store.artifacts_dir().join(format!("counters_{pid}_{ts}.csv"));
        // dotnet-counters collect runs until stopped; bound it by killing after the duration.
        let mut c = Command::new(&dc);
        c.arg("collect").arg("-p").arg(pid.to_string()).arg("--format").arg("csv").arg("-o").arg(&out).kill_on_drop(true);
        match c.spawn() {
            Ok(mut child) => {
                tokio::time::sleep(Duration::from_secs(secs)).await;
                let _ = child.start_kill();
                let _ = child.wait().await;
                if out.is_file() {
                    let bytes = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
                    self.state.audit.record(tool, &format!("counters pid {pid} for {secs}s"), None, "captured", None);
                    Ok(text(Outcome::new(tool, format!("collected {secs}s of .NET counters for pid {pid}")).data(json!({ "pid": pid, "durationSec": secs, "path": out.display().to_string(), "bytes": bytes })).artifact(Artifact { kind: "counters-csv".to_string(), path: out.display().to_string(), bytes, resource: out.display().to_string(), sensitivity: Some("low".to_string()) }).command(format!("dotnet-counters collect -p {pid} --format csv -o <csv> (stopped after {secs}s)")).docs(DOTNET_DOCS).to_value()))
                } else {
                    Ok(text(error(tool, ErrorKind::AnalysisFailed, "no counters CSV produced", "ensure the target is a .NET process", Some(DOTNET_DOCS))))
                }
            }
            Err(e) => Ok(text(error(tool, ErrorKind::Internal, format!("failed to launch dotnet-counters: {e}"), "check the tool", Some(DOTNET_DOCS)))),
        }
    }

    #[tool(
        name = "inspect.access",
        description = "Show effective access (ACLs / who can do what) for a file or directory via Sysinternals AccessChk. Read-only; needs accesschk."
    )]
    async fn inspect_access(
        &self,
        Parameters(a): Parameters<PathArg>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "inspect.access";
        let docs = "https://learn.microsoft.com/sysinternals/downloads/accesschk";
        let ac = match self.state.locator.find("accesschk.exe") {
            Some(p) => p,
            None => {
                let mut v = error(tool, ErrorKind::ToolNotInstalled, "accesschk.exe not found", "run tools.install sysinternals, or stage it in --tools-dir", Some(docs));
                v["error"]["install"] = json!("tools.install sysinternals");
                return Ok(text(v));
            }
        };
        let (_ok, out) = self.run_capture(&ac.display().to_string(), &["-accepteula", "-nobanner", a.path.as_str()], 60).await;
        Ok(text(Outcome::new(tool, format!("access for {}", a.path)).data(json!({ "path": a.path, "raw": last_chars(&out, 6000) })).docs(docs).to_value()))
    }

    #[tool(
        name = "analyze.foreignDump",
        description = "Analyze a dump captured on a different build/arch: set .exepath/.sympath to the matching images, then !analyze. Read-only; needs cdb."
    )]
    async fn analyze_foreign_dump(
        &self,
        Parameters(a): Parameters<ForeignDumpArgs>,
    ) -> Result<CallToolResult, McpError> {
        let mut cmds = String::new();
        if let Some(ip) = &a.image_path {
            cmds.push_str(&format!(".exepath+ {ip}; "));
        }
        if let Some(sp) = &a.sym_path {
            cmds.push_str(&format!(".sympath {sp}; "));
        }
        cmds.push_str(&a.commands.clone().unwrap_or_else(|| "!analyze -v; lm; q".to_string()));
        self.simple_analyze("analyze.foreignDump", &a.dump, None, &cmds).await
    }

    #[tool(
        name = "audit.export",
        description = "Export the append-only audit journal: path, entry count, and the recent entries. Read-only."
    )]
    async fn audit_export(&self) -> Result<CallToolResult, McpError> {
        let path = self.state.store.audit_path();
        let count = self.state.audit.tail(1_000_000).len();
        let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let mut out = Outcome::new("audit.export", format!("{count} audit entries"))
            .data(json!({ "path": path.display().to_string(), "count": count, "recent": self.state.audit.tail(50) }));
        if bytes > 0 {
            out = out.artifact(Artifact {
                kind: "audit".to_string(),
                path: path.display().to_string(),
                bytes,
                resource: "heisenberg://audit".to_string(),
                sensitivity: Some("low".to_string()),
            });
        }
        Ok(text(out.to_value()))
    }

    #[tool(
        name = "dump.open",
        description = "Open an interactive cdb session on a dump (id or path) and keep it alive for dump.command. Read-only (post-mortem). Needs cdb; returns a session id."
    )]
    async fn dump_open(
        &self,
        Parameters(a): Parameters<DumpOpenArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "dump.open";
        let docs = "https://learn.microsoft.com/windows-hardware/drivers/debugger/";
        let path = {
            let reg = self.state.dumps.lock().unwrap();
            let id = a.dump.trim_start_matches("heisenberg://dumps/");
            reg.get(id).map(|r| r.path.clone()).unwrap_or_else(|| a.dump.clone())
        };
        if !std::path::Path::new(&path).is_file() {
            return Ok(text(error(tool, ErrorKind::TargetNotFound, format!("no dump at {path}"), "pass a dump id or a valid path", Some(docs))));
        }
        if self.state.locator.find("cdb.exe").is_none() {
            let mut v = error(tool, ErrorKind::ToolNotInstalled, "cdb.exe not found", "install the Debugging Tools for Windows (winget install Microsoft.WinDbg)", Some(docs));
            v["error"]["wingetId"] = json!("Microsoft.WinDbg");
            return Ok(text(v));
        }
        let sympath = a.sympath.clone().or_else(|| regutil::get_hkcu_env("_NT_SYMBOL_PATH")).unwrap_or_else(|| {
            format!("srv*{}*https://msdl.microsoft.com/download/symbols", self.state.store.root.join("symbols").display())
        });
        let meta = self.state.sessions.open(path.clone(), sympath);
        self.state.audit.record(tool, &format!("opened session {} on {path}", meta.id), None, "opened", Some(&meta.id));
        Ok(text(
            Outcome::new(tool, format!("opened cdb session {} on {path}", meta.id))
                .data(json!({ "session": meta.id, "target": meta.target, "created": meta.created }))
                .docs(docs)
                .warn("run commands with dump.command {session, command}; close with dump.close when done")
                .to_value(),
        ))
    }

    /// Run one cdb command set against a dump (`-z ... -y ... -c "...; q"`).
    async fn cdb_oneshot(&self, path: &str, sympath: &str, cmds: &str) -> Result<String, (ErrorKind, String)> {
        let cdb = self
            .state
            .locator
            .find("cdb.exe")
            .ok_or((ErrorKind::ToolNotInstalled, "cdb.exe not found".to_string()))?;
        let out = tokio::time::timeout(
            Duration::from_secs(300),
            Command::new(&cdb).arg("-z").arg(path).arg("-y").arg(sympath).arg("-c").arg(cmds).output(),
        )
        .await
        .map_err(|_| (ErrorKind::Timeout, "cdb timed out after 300s".to_string()))?
        .map_err(|e| (ErrorKind::Internal, format!("failed to launch cdb: {e}")))?;
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    #[tool(
        name = "dump.command",
        description = "Run a cdb command in an open dump session (from dump.open) and return its output. Read-only (post-mortem) — each command re-execs cdb on the immutable dump."
    )]
    async fn dump_command(
        &self,
        Parameters(a): Parameters<SessionCommandArgs>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "dump.command";
        let session = match self.state.sessions.get(&a.session) {
            Some(s) => s,
            None => {
                return Ok(text(error(tool, ErrorKind::SessionNotFound, format!("no session {}", a.session), "open one with dump.open; list via heisenberg://sessions", None)))
            }
        };
        let cmds = format!("{}; q", a.command);
        match self.cdb_oneshot(&session.target, &session.sympath, &cmds).await {
            Ok(raw) => {
                self.state.audit.record(tool, &format!("ran '{}' in {}", a.command, a.session), None, "ran", Some(&a.session));
                Ok(text(
                    Outcome::new(tool, format!("ran '{}' in session {}", a.command, a.session))
                        .data(json!({ "session": a.session, "command": a.command, "output": last_chars(&raw, 8000) }))
                        .to_value(),
                ))
            }
            Err((k, e)) => Ok(text(error(tool, k, e, "check cdb and the dump", None))),
        }
    }

    #[tool(
        name = "dump.close",
        description = "Close an interactive cdb dump session opened with dump.open."
    )]
    async fn dump_close(
        &self,
        Parameters(a): Parameters<SessionIdArg>,
    ) -> Result<CallToolResult, McpError> {
        let tool = "dump.close";
        let closed = self.state.sessions.close(&a.session);
        self.state.audit.record(tool, &format!("close session {}", a.session), None, if closed { "closed" } else { "noop" }, Some(&a.session));
        if closed {
            Ok(text(Outcome::new(tool, format!("closed session {}", a.session)).data(json!({ "session": a.session })).to_value()))
        } else {
            Ok(text(error(tool, ErrorKind::SessionNotFound, format!("no session {}", a.session), "list via heisenberg://sessions", None)))
        }
    }
}

fn user_msg(text: String) -> Vec<PromptMessage> {
    vec![PromptMessage::new_text(Role::User, text)]
}

#[prompt_router]
impl Heisenberg {
    #[prompt(
        name = "triage-broken-box",
        description = "First-response triage playbook for a broken or unfamiliar Windows box."
    )]
    async fn p_triage(&self) -> Result<Vec<PromptMessage>, McpError> {
        Ok(user_msg(
            "Triage this Windows box, breadth-first and read-only:\n\
             1. system.triage — services, boot config, drivers, hypervisor, and log locations.\n\
             2. env.check — OS build/edition, arch, integrity, privileges (SeDebug/SeTcb), session.\n\
             3. kernel.status — crash-dump mode + whether kernel debugging is configured.\n\
             4. tools.list — what debugging tools are present; run env.provision or tools.install for gaps.\n\
             5. logs.eventQuery (System, then Application) — recent errors; export with logs.eventExport.\n\
             6. inspect.processTree / inspect.network — what's running and talking.\n\
             7. collect.package — bundle the findings into a portable case.\n\
             Report what's abnormal and propose the next, narrower step."
                .to_string(),
        ))
    }

    #[prompt(
        name = "diagnose-crash",
        description = "Investigate a crashing process (live target) or an existing crash dump."
    )]
    async fn p_crash(
        &self,
        Parameters(a): Parameters<PromptTargetArgs>,
    ) -> Result<Vec<PromptMessage>, McpError> {
        let t = a.target.unwrap_or_else(|| "<pid | name | dump-id>".to_string());
        Ok(user_msg(format!(
            "Diagnose the crash for '{t}':\n\
             1. If it's a live process: dump.capture {{pid|name}} (full). For an intermittent crash, \
             instead arm dump.onTrigger (on=unhandled) or dump.onCrashInstall, then reproduce.\n\
             2. Ensure symbols: symbols.show; if unset, symbols.configure to the msdl public server.\n\
             3. dump.analyze on the dump — read the exceptionCode, faultingModule and the faulting stack.\n\
             4. inspect.verify the faulting module (signature/version) if a bad/mismatched DLL is suspected.\n\
             5. If managed (.NET): dotnet.analyze for the CLR stack.\n\
             Summarize the faulting frame and the likely cause."
        )))
    }

    #[prompt(
        name = "diagnose-hang",
        description = "Investigate a hung/unresponsive process (deadlock or waiting)."
    )]
    async fn p_hang(
        &self,
        Parameters(a): Parameters<PromptTargetArgs>,
    ) -> Result<Vec<PromptMessage>, McpError> {
        let t = a.target.unwrap_or_else(|| "<pid | name>".to_string());
        Ok(user_msg(format!(
            "Diagnose the hang for '{t}':\n\
             1. dump.capture {{pid|name}} (full) while it's hung.\n\
             2. analyze.deadlock — lock/critical-section/monitor wait chains across all threads.\n\
             3. If no lock cycle, read ~*k (all-thread stacks via dump.analyze) for what threads are waiting on.\n\
             4. If managed: dotnet.analyze (sync blocks / async) with analyze.async.\n\
             Name the blocking chain or the wait, and which thread owns the resource."
        )))
    }

    #[prompt(
        name = "diagnose-deadlock",
        description = "Find a lock/critical-section/monitor deadlock in a dump."
    )]
    async fn p_deadlock(
        &self,
        Parameters(a): Parameters<PromptTargetArgs>,
    ) -> Result<Vec<PromptMessage>, McpError> {
        let t = a.target.unwrap_or_else(|| "<pid | name | dump-id>".to_string());
        Ok(user_msg(format!(
            "Hunt a deadlock for '{t}':\n\
             1. Get a dump (dump.capture) if you don't have one.\n\
             2. analyze.deadlock — !locks, !cs, !syncblk, and all-thread stacks.\n\
             3. For each held lock, identify the owning thread and what it is itself waiting on.\n\
             Report the cycle (thread A holds X waits Y; thread B holds Y waits X)."
        )))
    }

    #[prompt(
        name = "diagnose-high-cpu",
        description = "Attribute high CPU to a thread/module."
    )]
    async fn p_highcpu(
        &self,
        Parameters(a): Parameters<PromptTargetArgs>,
    ) -> Result<Vec<PromptMessage>, McpError> {
        let t = a.target.unwrap_or_else(|| "<pid | name>".to_string());
        Ok(user_msg(format!(
            "Diagnose high CPU for '{t}':\n\
             1. dump.capture {{pid|name}} (full) during the spike — or dump.onTrigger (on=cpu, threshold).\n\
             2. analyze.highCpu — !runaway to rank threads by CPU, then their stacks.\n\
             3. For a time-based view, logs.etwStart with the CPU profile, reproduce, logs.etwStop, hand the .etl to WPA/findneedle.\n\
             Name the hot thread and the function/module burning CPU."
        )))
    }

    #[prompt(
        name = "diagnose-leak",
        description = "Investigate a memory or handle leak."
    )]
    async fn p_leak(
        &self,
        Parameters(a): Parameters<PromptTargetArgs>,
    ) -> Result<Vec<PromptMessage>, McpError> {
        let t = a.target.unwrap_or_else(|| "<image.exe | pid>".to_string());
        Ok(user_msg(format!(
            "Investigate a leak in '{t}':\n\
             HEAP (native): leak.heapTrackStart <image> to enable the stack DB, restart the target, then \
             leak.heapSnapshot for a baseline, let it leak, snapshot again, and leak.heapDiff the two.\n\
             HANDLES: dump.capture then analyze.handles (!handle summary) — watch for a growing type.\n\
             MANAGED (.NET): dotnet.gcHeap for a GC snapshot (diff two), or dotnet.analyze (!dumpheap -stat).\n\
             Report the allocation site / handle type that grows, and revert any gflags with changes.revert."
        )))
    }

    #[prompt(
        name = "diagnose-service-start",
        description = "Debug a Windows service that crashes or hangs at startup."
    )]
    async fn p_service(
        &self,
        Parameters(a): Parameters<PromptTargetArgs>,
    ) -> Result<Vec<PromptMessage>, McpError> {
        let t = a.target.unwrap_or_else(|| "<service-image.exe>".to_string());
        Ok(user_msg(format!(
            "Debug startup failure of service '{t}':\n\
             1. logs.eventQuery (System) for the SCM error (timeout vs crash).\n\
             2. service.startupDebug <image> to attach a debugger at process start (reversible via changes.revert); \
             if it times out at start, also raise ServicesPipeTimeout (noted by the tool).\n\
             3. Or dump.onCrashInstall <image> so a startup crash auto-dumps, then dump.analyze.\n\
             4. Services run in session 0 — if a UI is needed, session.launchInUser (needs SYSTEM/SeTcb).\n\
             Report whether it's a crash (and the faulting frame) or a timeout (and what it's blocked on)."
        )))
    }

    #[prompt(
        name = "app-wont-launch",
        description = "Investigate an application that fails to start."
    )]
    async fn p_wontlaunch(
        &self,
        Parameters(a): Parameters<PromptTargetArgs>,
    ) -> Result<Vec<PromptMessage>, McpError> {
        let t = a.target.unwrap_or_else(|| "<image.exe>".to_string());
        Ok(user_msg(format!(
            "Investigate why '{t}' won't launch:\n\
             1. gflags.get <image> — a leftover IFEO Debugger or full page heap can block/redirect startup.\n\
             2. inspect.verify <path> — signature/version of the exe and suspect DLLs (DLL-hell / blocked binary).\n\
             3. logs.eventQuery (Application) for the load error (SideBySide, 0xc0000135 missing DLL, etc.).\n\
             4. Capture a startup crash with dump.onCrashInstall, or set postmortem.aeDebug and reproduce.\n\
             Report the blocking cause (bad IFEO, missing/mismatched DLL, AV, crash)."
        )))
    }

    #[prompt(
        name = "analyze-existing-dump",
        description = "Analyze a user-mode or kernel dump you already have."
    )]
    async fn p_existing(
        &self,
        Parameters(a): Parameters<PromptTargetArgs>,
    ) -> Result<Vec<PromptMessage>, McpError> {
        let t = a.target.unwrap_or_else(|| "<dump-id | path>".to_string());
        Ok(user_msg(format!(
            "Analyze dump '{t}':\n\
             1. symbols.show; symbols.configure to the public server if needed (analyze an off-box dump with the \
             matching image/symbol paths).\n\
             2. dump.analyze — !analyze -v, stacks, modules; read the verdict.\n\
             3. Pivot by symptom: analyze.deadlock / analyze.highCpu / analyze.handles / analyze.verifierStop, \
             or dotnet.analyze for managed.\n\
             Report the root cause with the faulting/owning frame."
        )))
    }

    #[prompt(
        name = "analyze-bugcheck",
        description = "Analyze a kernel crash (BSOD / memory.dmp)."
    )]
    async fn p_bugcheck(
        &self,
        Parameters(a): Parameters<PromptTargetArgs>,
    ) -> Result<Vec<PromptMessage>, McpError> {
        let t = a.target.unwrap_or_else(|| r"C:\Windows\MEMORY.DMP".to_string());
        Ok(user_msg(format!(
            "Analyze the bugcheck in '{t}':\n\
             1. kernel.status — confirm the crash-dump mode; the dump is usually C:\\Windows\\MEMORY.DMP or \\Minidump.\n\
             2. symbols.configure to the public server.\n\
             3. dump.analyze — !analyze -v gives the bugcheck code and the culprit driver/module.\n\
             4. If a GPU timeout (0x116/0x117), use gpu.tdrAnalyze; if a Driver Verifier stop, analyze.verifierStop.\n\
             Report the bugcheck code and the driver at fault."
        )))
    }

    #[prompt(
        name = "diagnose-verifier-stop",
        description = "Decode a Driver/Application Verifier stop."
    )]
    async fn p_verifier(
        &self,
        Parameters(a): Parameters<PromptTargetArgs>,
    ) -> Result<Vec<PromptMessage>, McpError> {
        let t = a.target.unwrap_or_else(|| "<dump-id | path>".to_string());
        Ok(user_msg(format!(
            "Decode the Verifier stop in '{t}':\n\
             1. analyze.verifierStop — !analyze -v + !verifier to name the exact rule violated.\n\
             2. For user-mode App Verifier, enable checks with appverifier.enable <image> (reversible), reproduce, re-dump.\n\
             Report the violated rule and the offending call."
        )))
    }
}

#[tool_handler]
#[prompt_handler]
impl ServerHandler for Heisenberg {
    fn get_info(&self) -> ServerConfig {
        let mut info = Implementation::from_build_env();
        info.name = "heisenberg".to_string();
        info.version = env!("CARGO_PKG_VERSION").to_string();
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
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
            Resource::new("heisenberg://captures", "Background capture jobs".to_string()),
            Resource::new("heisenberg://cases", "Exported case bundles".to_string()),
            Resource::new("heisenberg://sessions", "Open debug sessions".to_string()),
            Resource::new("heisenberg://approvals", "Human-approval broker grants".to_string()),
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
            "heisenberg://captures" => {
                let j = self.state.jobs.lock().unwrap();
                serde_json::to_string_pretty(&json!({ "jobs": j.list() })).ok()
            }
            "heisenberg://cases" => {
                let dir = self.state.store.cases_dir();
                let mut cases: Vec<serde_json::Value> = Vec::new();
                if let Ok(rd) = std::fs::read_dir(&dir) {
                    for e in rd.flatten() {
                        let p = e.path();
                        let bytes = e.metadata().map(|m| m.len()).ok();
                        cases.push(json!({ "name": p.file_name().and_then(|n| n.to_str()).unwrap_or(""), "path": p.display().to_string(), "bytes": bytes }));
                    }
                }
                serde_json::to_string_pretty(&json!({ "cases": cases })).ok()
            }
            "heisenberg://sessions" => {
                serde_json::to_string_pretty(&json!({ "sessions": self.state.sessions.list() })).ok()
            }
            "heisenberg://approvals" => {
                serde_json::to_string_pretty(&json!({ "approvals": self.state.approvals.list() })).ok()
            }
            other if other.starts_with("heisenberg://dumps/") => {
                let id = &other["heisenberg://dumps/".len()..];
                let reg = self.state.dumps.lock().unwrap();
                reg.get(id).map(|r| serde_json::to_string_pretty(r).unwrap_or_default())
            }
            other if other.starts_with("heisenberg://captures/") => {
                let id = &other["heisenberg://captures/".len()..];
                let j = self.state.jobs.lock().unwrap();
                j.get(id).map(|job| serde_json::to_string_pretty(job).unwrap_or_default())
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
