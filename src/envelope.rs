//! The uniform result/error envelope every tool returns (see the plan's
//! "Tool & resource contracts"). Tools build one of these and hand back its JSON
//! so an agent can chain calls without special-casing each tool.
//!
//! Some builders and error kinds here are wired ahead of the tools that will use
//! them in later phases.
#![allow(dead_code)]

use serde::Serialize;
use serde_json::Value;

/// Current envelope schema version. Bumped on breaking shape changes.
pub const ENVELOPE_VERSION: u32 = 1;

/// A file produced by a tool, already registered as a resource.
#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    pub kind: String,
    pub path: String,
    pub bytes: u64,
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
}

/// Typed failure reasons. Kept in sync with the plan's error taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ErrorKind {
    RequiresElevation,
    AccessDenied,
    ToolNotInstalled,
    ToolInstallFailed,
    UnsupportedOnThisBuild,
    ArchMismatch,
    AmbiguousTarget,
    InvalidArgument,
    TargetNotFound,
    SessionNotFound,
    ProtectedProcess,
    SymbolsUnavailable,
    AnalysisFailed,
    InsufficientDiskSpace,
    RebootRequired,
    Timeout,
    CaptureInProgress,
    ConfirmationRequired,
    RequiresApproval,
    PolicyDenied,
    NotImplemented,
    Internal,
}

impl ErrorKind {
    /// Whether retrying the same call unchanged could plausibly succeed later.
    pub fn retryable(self) -> bool {
        use ErrorKind::*;
        matches!(
            self,
            SymbolsUnavailable | InsufficientDiskSpace | Timeout | CaptureInProgress | Internal
        )
    }
}

/// Builder for a success envelope.
pub struct Outcome {
    tool: String,
    summary: String,
    data: Value,
    artifacts: Vec<Artifact>,
    commands: Vec<String>,
    docs_url: Option<String>,
    warnings: Vec<String>,
}

impl Outcome {
    pub fn new(tool: impl Into<String>, summary: impl Into<String>) -> Self {
        Outcome {
            tool: tool.into(),
            summary: summary.into(),
            data: Value::Null,
            artifacts: Vec::new(),
            commands: Vec::new(),
            docs_url: None,
            warnings: Vec::new(),
        }
    }

    pub fn data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }

    pub fn command(mut self, cmd: impl Into<String>) -> Self {
        self.commands.push(cmd.into());
        self
    }

    pub fn docs(mut self, url: impl Into<String>) -> Self {
        self.docs_url = Some(url.into());
        self
    }

    pub fn warn(mut self, w: impl Into<String>) -> Self {
        self.warnings.push(w.into());
        self
    }

    pub fn artifact(mut self, a: Artifact) -> Self {
        self.artifacts.push(a);
        self
    }

    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "ok": true,
            "v": ENVELOPE_VERSION,
            "tool": self.tool,
            "summary": self.summary,
            "data": self.data,
            "artifacts": self.artifacts,
            "commands": self.commands,
            "docsUrl": self.docs_url,
            "warnings": self.warnings,
        })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.to_value()).unwrap_or_else(|e| {
            format!("{{\"ok\":false,\"error\":{{\"kind\":\"Internal\",\"message\":\"{e}\"}}}}")
        })
    }
}

/// Build an error envelope value.
pub fn error(
    tool: &str,
    kind: ErrorKind,
    message: impl Into<String>,
    remedy: impl Into<String>,
    docs_url: Option<&str>,
) -> Value {
    serde_json::json!({
        "ok": false,
        "v": ENVELOPE_VERSION,
        "tool": tool,
        "error": {
            "kind": kind,
            "retryable": kind.retryable(),
            "message": message.into(),
            "remedy": remedy.into(),
            "docsUrl": docs_url,
        }
    })
}

pub fn error_json(
    tool: &str,
    kind: ErrorKind,
    message: impl Into<String>,
    remedy: impl Into<String>,
    docs_url: Option<&str>,
) -> String {
    serde_json::to_string_pretty(&error(tool, kind, message, remedy, docs_url))
        .unwrap_or_else(|_| "{\"ok\":false}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_envelope_shape() {
        let v = Outcome::new("env.check", "probed the box")
            .data(serde_json::json!({"arch": "x64"}))
            .command("whoami /priv")
            .docs("https://learn.microsoft.com/")
            .to_value();
        assert_eq!(v["ok"], true);
        assert_eq!(v["tool"], "env.check");
        assert_eq!(v["data"]["arch"], "x64");
        assert_eq!(v["v"], ENVELOPE_VERSION);
    }

    #[test]
    fn error_envelope_marks_retryable() {
        let v = error(
            "dump.capture",
            ErrorKind::InsufficientDiskSpace,
            "not enough room",
            "free space or pick another drive",
            None,
        );
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"]["retryable"], true);
    }

    #[test]
    fn elevation_error_is_not_retryable() {
        assert!(!ErrorKind::RequiresElevation.retryable());
    }
}
