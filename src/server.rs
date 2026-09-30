//! The MCP server surface. Phase 1 gave the foundation (`env.check`, policy view,
//! `gate.check`, resources). Phase 2 adds the safety spine's teeth: the change
//! ledger, audit journal, gate *enforcement*, and a first reversible tool
//! (`symbols.configure`) that exercises the whole path.

use std::sync::{Arc, Mutex};

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler};
use serde::Deserialize;
use serde_json::json;

use crate::audit::Audit;
use crate::envelope::{error, ErrorKind, Outcome};
use crate::ledger::{ChangeStatus, Ledger, RevertPlan};
use crate::policy::{base_gate, BoxClass, EffectTier, Policy};
use crate::store::Store;
use crate::{docs, env_probe, gate, regutil};

const SYMBOLS_TOKEN: &str = "set-symbol-path";
const SYMBOL_PATH_DOCS: &str =
    "https://learn.microsoft.com/windows-hardware/drivers/debugger/symbol-path";

/// Shared server state: the immutable policy plus the on-disk ledger and audit.
pub struct AppState {
    pub policy: Policy,
    #[allow(dead_code)] // used by artifact-producing tools in a later phase.
    pub store: Store,
    pub ledger: Mutex<Ledger>,
    pub audit: Audit,
}

impl AppState {
    pub fn new(policy: Policy) -> Self {
        let store = Store::discover();
        let ledger = Ledger::load(store.ledger_path());
        let audit = Audit::open(store.audit_path());
        AppState {
            policy,
            store,
            ledger: Mutex::new(ledger),
            audit,
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
