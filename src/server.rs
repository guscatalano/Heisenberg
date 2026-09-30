//! The MCP server surface. Phase 1 exposes the foundation: `env.check`, the
//! policy view, a `gate.check` that demonstrates the safety spine, and the
//! `heisenberg://` + `docs://` resources.

use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{schemars, tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler};
use serde::Deserialize;
use serde_json::json;

use crate::envelope::{error, ErrorKind, Outcome};
use crate::policy::{base_gate, BoxClass, EffectTier, Policy};
use crate::{docs, env_probe};

#[derive(Clone)]
pub struct Heisenberg {
    policy: Arc<Policy>,
    // Read by the generated ServerHandler (tool_handler macro); not seen by dead-code analysis.
    #[allow(dead_code)]
    tool_router: ToolRouter<Heisenberg>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GateCheckArgs {
    /// The tool to test, e.g. "gflags.set" or "kernel.forceBugcheck".
    pub tool: String,
    /// Effect tier: "read-only", "state-changing", or "machine-disrupting".
    pub tier: String,
}

fn parse_tier(s: &str) -> Option<EffectTier> {
    match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "read-only" | "readonly" | "ro" => Some(EffectTier::ReadOnly),
        "state-changing" | "statechanging" | "sc" => Some(EffectTier::StateChanging),
        "machine-disrupting" | "machinedisrupting" | "md" => Some(EffectTier::MachineDisrupting),
        _ => None,
    }
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
            let key = serde_json::to_value(t).unwrap();
            row.insert(
                key.as_str().unwrap_or("?").to_string(),
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
            policy: Arc::new(policy),
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
        let class = self.policy.effective_class();
        let data = json!({
            "declaredClass": self.policy.class,
            "effectiveClass": class,
            "source": self.policy.source,
            "overrides": self.policy.overrides,
            "gateMatrix": gate_matrix(),
        });
        Outcome::new(
            "policy.show",
            format!(
                "effective class: {:?} (source: {}, {:?})",
                class, self.policy.source.origin, self.policy.source.trust
            ),
        )
        .data(data)
        .to_value()
    }

    #[tool(
        name = "env.check",
        description = "Probe the machine: OS build/edition, architecture (incl. WOW64), integrity level, privileges (SeDebug/SeTcb), session id, and derived capabilities. Read-only."
    )]
    async fn env_check(&self) -> Result<CallToolResult, McpError> {
        let v = self.env_report_json();
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&v).unwrap_or_default(),
        )]))
    }

    #[tool(
        name = "policy.show",
        description = "Show the effective box class, its source and trust, per-tool overrides, and the full gate matrix (box class x effect tier). Read-only."
    )]
    async fn policy_show(&self) -> Result<CallToolResult, McpError> {
        let v = self.policy_json();
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&v).unwrap_or_default(),
        )]))
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
                let decision = self.policy.decide(&args.tool, tier);
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
        Ok(CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&v).unwrap_or_default(),
        )]))
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
             gate.check to see what a proposed action would require before attempting it."
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
        let text = match uri.as_str() {
            "heisenberg://env" => serde_json::to_string_pretty(&self.env_report_json()).ok(),
            "heisenberg://policy" => serde_json::to_string_pretty(&self.policy_json()).ok(),
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

        match text {
            Some(t) => Ok(ReadResourceResult::new(vec![ResourceContents::text(t, uri)]).into()),
            None => Err(McpError::resource_not_found(
                "resource_not_found",
                Some(json!({ "uri": uri })),
            )),
        }
    }
}
