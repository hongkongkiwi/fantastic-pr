use std::path::PathBuf;
use std::process::Command;

use anyhow::Context;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ServerCapabilities, ServerInfo},
    schemars,
    schemars::JsonSchema,
    tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, JsonSchema, Default)]
struct ScanToolParams {
    config: Option<String>,
    base_ref: Option<String>,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    comprehensive: bool,
    output: Option<String>,
    output_file: Option<String>,
    fail_on: Option<String>,
    enable_llm: Option<bool>,
    post_inline: Option<bool>,
    #[serde(default)]
    set: Vec<String>,
    #[serde(default)]
    ingest: Vec<String>,
    baseline_file: Option<String>,
    baseline_enabled: Option<bool>,
    #[serde(default)]
    update_baseline: bool,
    emit_sarif: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, Default)]
struct ValidateConfigToolParams {
    config: Option<String>,
    #[serde(default)]
    set: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, Default)]
struct ProbeProviderToolParams {
    config: Option<String>,
    #[serde(default)]
    set: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema, Default)]
struct MigrateConfigToolParams {
    config: Option<String>,
    from: Option<String>,
    to: Option<String>,
}

#[derive(Debug, Serialize)]
struct CommandExecutionResult {
    command: Vec<String>,
    cwd: String,
    success: bool,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Clone)]
struct FantasticPrMcpServer {
    executable: PathBuf,
    cwd: PathBuf,
    tool_router: ToolRouter<Self>,
}

impl FantasticPrMcpServer {
    fn new() -> anyhow::Result<Self> {
        Ok(Self {
            executable: std::env::current_exe()
                .context("failed to discover current executable path for MCP mode")?,
            cwd: std::env::current_dir().context("failed to discover current working directory")?,
            tool_router: Self::tool_router(),
        })
    }

    fn execute_subcommand(
        &self,
        subcommand: &str,
        args: Vec<String>,
    ) -> Result<CallToolResult, McpError> {
        let mut command = Command::new(&self.executable);
        command.current_dir(&self.cwd).arg(subcommand).args(&args);

        let output = command.output().map_err(|err| {
            McpError::internal_error(
                format!("failed to execute fantastic-pr {subcommand}: {err}"),
                None,
            )
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let success = output.status.success();
        let exit_code = output.status.code();
        let command_line = std::iter::once(self.executable.display().to_string())
            .chain(std::iter::once(subcommand.to_string()))
            .chain(args)
            .collect::<Vec<_>>();
        let payload = serde_json::to_value(CommandExecutionResult {
            command: command_line,
            cwd: self.cwd.display().to_string(),
            success,
            exit_code,
            stdout: stdout.clone(),
            stderr: stderr.clone(),
        })
        .map_err(|err| {
            McpError::internal_error(format!("failed to serialize command result: {err}"), None)
        })?;

        let mut result = if success {
            CallToolResult::structured(payload)
        } else {
            CallToolResult::structured_error(payload)
        };

        let mut content = Vec::new();
        if success {
            content.push(rmcp::model::Content::text(format!(
                "`fantastic-pr {subcommand}` completed successfully."
            )));
        } else {
            content.push(rmcp::model::Content::text(format!(
                "`fantastic-pr {subcommand}` failed."
            )));
        }
        if !stdout.trim().is_empty() {
            content.push(rmcp::model::Content::text(format!("stdout:\n{stdout}")));
        }
        if !stderr.trim().is_empty() {
            content.push(rmcp::model::Content::text(format!("stderr:\n{stderr}")));
        }
        result.content = content;

        Ok(result)
    }
}

#[tool_router]
impl FantasticPrMcpServer {
    #[tool(
        name = "fantastic_pr_scan",
        description = "Run fantastic-pr scan mode and return stdout/stderr with structured metadata."
    )]
    fn fantastic_pr_scan(
        &self,
        Parameters(params): Parameters<ScanToolParams>,
    ) -> Result<CallToolResult, McpError> {
        self.execute_subcommand("scan", build_scan_args(&params))
    }

    #[tool(
        name = "fantastic_pr_validate_config",
        description = "Validate Fantastic PR config using the same logic as `fantastic-pr validate-config`."
    )]
    fn fantastic_pr_validate_config(
        &self,
        Parameters(params): Parameters<ValidateConfigToolParams>,
    ) -> Result<CallToolResult, McpError> {
        self.execute_subcommand("validate-config", build_validate_args(&params))
    }

    #[tool(
        name = "fantastic_pr_probe_provider",
        description = "Probe configured LLM provider wiring using `fantastic-pr probe-provider`."
    )]
    fn fantastic_pr_probe_provider(
        &self,
        Parameters(params): Parameters<ProbeProviderToolParams>,
    ) -> Result<CallToolResult, McpError> {
        self.execute_subcommand("probe-provider", build_probe_args(&params))
    }

    #[tool(
        name = "fantastic_pr_migrate_config",
        description = "Rewrite config file into normalized Fantastic PR YAML via `fantastic-pr migrate-config`."
    )]
    fn fantastic_pr_migrate_config(
        &self,
        Parameters(params): Parameters<MigrateConfigToolParams>,
    ) -> Result<CallToolResult, McpError> {
        self.execute_subcommand("migrate-config", build_migrate_args(&params))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for FantasticPrMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "Fantastic PR MCP server. Use scan/validate/probe/migrate tools to run the CLI via stdio transport."
                    .to_string(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

pub(crate) fn run_stdio_server() -> anyhow::Result<()> {
    run_stdio_server_with(|runtime| {
        runtime.block_on(async {
            let service = FantasticPrMcpServer::new()?
                .serve(stdio())
                .await
                .context("failed to start Fantastic PR MCP stdio server")?;
            service
                .waiting()
                .await
                .context("Fantastic PR MCP server task failed")?;
            Ok::<(), anyhow::Error>(())
        })
    })
}

fn run_stdio_server_with<F>(start: F) -> anyhow::Result<()>
where
    F: FnOnce(&tokio::runtime::Runtime) -> anyhow::Result<()>,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime for MCP mode")?;
    start(&runtime)
}

fn build_scan_args(params: &ScanToolParams) -> Vec<String> {
    let mut args = Vec::new();
    push_optional_flag_value(&mut args, "--config", params.config.as_ref());
    push_optional_flag_value(&mut args, "--base-ref", params.base_ref.as_ref());
    if params.dry_run {
        args.push("--dry-run".to_string());
    }
    if params.comprehensive {
        args.push("--comprehensive".to_string());
    }
    push_optional_flag_value(&mut args, "--output", params.output.as_ref());
    push_optional_flag_value(&mut args, "--output-file", params.output_file.as_ref());
    push_optional_flag_value(&mut args, "--fail-on", params.fail_on.as_ref());
    push_optional_bool_value(&mut args, "--enable-llm", params.enable_llm);
    push_optional_bool_value(&mut args, "--post-inline", params.post_inline);
    for set in &params.set {
        args.push("--set".to_string());
        args.push(set.clone());
    }
    for ingest in &params.ingest {
        args.push("--ingest".to_string());
        args.push(ingest.clone());
    }
    push_optional_flag_value(&mut args, "--baseline-file", params.baseline_file.as_ref());
    push_optional_bool_value(&mut args, "--baseline-enabled", params.baseline_enabled);
    if params.update_baseline {
        args.push("--update-baseline".to_string());
    }
    push_optional_flag_value(&mut args, "--emit-sarif", params.emit_sarif.as_ref());
    args
}

fn build_validate_args(params: &ValidateConfigToolParams) -> Vec<String> {
    let mut args = Vec::new();
    push_optional_flag_value(&mut args, "--config", params.config.as_ref());
    for set in &params.set {
        args.push("--set".to_string());
        args.push(set.clone());
    }
    args
}

fn build_probe_args(params: &ProbeProviderToolParams) -> Vec<String> {
    let mut args = Vec::new();
    push_optional_flag_value(&mut args, "--config", params.config.as_ref());
    for set in &params.set {
        args.push("--set".to_string());
        args.push(set.clone());
    }
    args
}

fn build_migrate_args(params: &MigrateConfigToolParams) -> Vec<String> {
    let mut args = Vec::new();
    push_optional_flag_value(&mut args, "--config", params.config.as_ref());
    push_optional_flag_value(&mut args, "--from", params.from.as_ref());
    push_optional_flag_value(&mut args, "--to", params.to.as_ref());
    args
}

fn push_optional_flag_value(args: &mut Vec<String>, flag: &str, value: Option<&String>) {
    if let Some(value) = value {
        args.push(flag.to_string());
        args.push(value.clone());
    }
}

fn push_optional_bool_value(args: &mut Vec<String>, flag: &str, value: Option<bool>) {
    if let Some(value) = value {
        args.push(format!("{flag}={value}"));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FantasticPrMcpServer, MigrateConfigToolParams, ProbeProviderToolParams, ScanToolParams,
        ValidateConfigToolParams, build_migrate_args, build_probe_args, build_scan_args,
        build_validate_args, run_stdio_server_with,
    };
    use anyhow::anyhow;
    use rmcp::model::RawContent;
    use serde_json::Value;
    use std::path::PathBuf;

    fn test_server(executable: PathBuf) -> FantasticPrMcpServer {
        FantasticPrMcpServer {
            executable,
            cwd: std::env::temp_dir(),
            tool_router: FantasticPrMcpServer::tool_router(),
        }
    }

    fn text_content(result: &rmcp::model::CallToolResult) -> Vec<String> {
        result
            .content
            .iter()
            .filter_map(|entry| match &entry.raw {
                RawContent::Text(text) => Some(text.text.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn build_scan_args_includes_requested_flags_and_lists() {
        let args = build_scan_args(&ScanToolParams {
            config: Some(".fantastic-pr.yaml".to_string()),
            base_ref: Some("origin/main".to_string()),
            dry_run: true,
            comprehensive: true,
            output: Some("json".to_string()),
            output_file: Some("out.json".to_string()),
            fail_on: Some("warning".to_string()),
            enable_llm: Some(true),
            post_inline: Some(false),
            set: vec!["checks.debug_statements=false".to_string()],
            ingest: vec!["checkov.json".to_string(), "gitleaks.json".to_string()],
            baseline_file: Some("baseline.json".to_string()),
            baseline_enabled: Some(true),
            update_baseline: true,
            emit_sarif: Some("report.sarif".to_string()),
        });

        assert!(args.contains(&"--config".to_string()));
        assert!(args.contains(&"origin/main".to_string()));
        assert!(args.contains(&"--dry-run".to_string()));
        assert!(args.contains(&"--comprehensive".to_string()));
        assert!(args.contains(&"--enable-llm=true".to_string()));
        assert!(args.contains(&"--post-inline=false".to_string()));
        assert!(args.contains(&"--update-baseline".to_string()));
        assert!(args.contains(&"checkov.json".to_string()));
        assert!(args.contains(&"gitleaks.json".to_string()));
    }

    #[test]
    fn build_validate_and_probe_args_include_config_and_overrides() {
        let validate = build_validate_args(&ValidateConfigToolParams {
            config: Some("cfg.yaml".to_string()),
            set: vec!["llm.enabled=true".to_string()],
        });
        let probe = build_probe_args(&ProbeProviderToolParams {
            config: Some("cfg.yaml".to_string()),
            set: vec!["llm.provider=openai-api".to_string()],
        });

        assert!(validate.contains(&"--config".to_string()));
        assert!(validate.contains(&"llm.enabled=true".to_string()));
        assert!(probe.contains(&"--config".to_string()));
        assert!(probe.contains(&"llm.provider=openai-api".to_string()));
    }

    #[test]
    fn build_migrate_args_includes_from_to_and_config() {
        let args = build_migrate_args(&MigrateConfigToolParams {
            config: Some("cfg.yaml".to_string()),
            from: Some("in.yaml".to_string()),
            to: Some("out.yaml".to_string()),
        });
        assert!(args.contains(&"--config".to_string()));
        assert!(args.contains(&"--from".to_string()));
        assert!(args.contains(&"--to".to_string()));
        assert!(args.contains(&"in.yaml".to_string()));
        assert!(args.contains(&"out.yaml".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn execute_subcommand_returns_structured_success_payload() {
        let server = test_server(PathBuf::from("sh"));
        let result = server
            .execute_subcommand(
                "-c",
                vec!["printf 'hello-out'; printf 'hello-err' >&2".to_string()],
            )
            .expect("subcommand should succeed");

        assert_eq!(result.is_error, Some(false));
        let payload = result
            .structured_content
            .as_ref()
            .expect("structured payload");
        assert_eq!(payload.get("success"), Some(&Value::Bool(true)));
        assert_eq!(payload.get("exit_code"), Some(&Value::from(0)));
        assert_eq!(
            payload.get("stdout"),
            Some(&Value::String("hello-out".to_string()))
        );
        assert_eq!(
            payload.get("stderr"),
            Some(&Value::String("hello-err".to_string()))
        );
        let command = payload["command"]
            .as_array()
            .expect("command payload should be an array");
        assert!(command.iter().any(|entry| entry.as_str() == Some("-c")));
        assert!(!payload["cwd"].as_str().unwrap_or_default().is_empty());

        let text = text_content(&result).join("\n");
        assert!(text.contains("completed successfully"));
        assert!(text.contains("stdout:\nhello-out"));
        assert!(text.contains("stderr:\nhello-err"));
    }

    #[cfg(unix)]
    #[test]
    fn execute_subcommand_returns_structured_error_payload() {
        let server = test_server(PathBuf::from("sh"));
        let result = server
            .execute_subcommand(
                "-c",
                vec!["echo bad-out; echo bad-err >&2; exit 7".to_string()],
            )
            .expect("subcommand should return a structured error");

        assert_eq!(result.is_error, Some(true));
        let payload = result
            .structured_content
            .as_ref()
            .expect("structured payload");
        assert_eq!(payload.get("success"), Some(&Value::Bool(false)));
        assert_eq!(payload.get("exit_code"), Some(&Value::from(7)));
        assert_eq!(
            payload.get("stdout"),
            Some(&Value::String("bad-out\n".to_string()))
        );
        assert_eq!(
            payload.get("stderr"),
            Some(&Value::String("bad-err\n".to_string()))
        );

        let text = text_content(&result).join("\n");
        assert!(text.contains("failed"));
        assert!(text.contains("stdout:\nbad-out"));
        assert!(text.contains("stderr:\nbad-err"));
    }

    #[test]
    fn execute_subcommand_returns_mcp_error_when_spawn_fails() {
        let server = test_server(PathBuf::from(
            "/this/path/does/not/exist/fantastic-pr-mcp-test-bin",
        ));
        let err = server
            .execute_subcommand("scan", Vec::new())
            .expect_err("missing binary should return mcp error");
        assert!(err.message.contains("failed to execute fantastic-pr scan"));
    }

    #[test]
    fn run_stdio_server_with_invokes_start_callback() {
        let mut invoked = false;
        run_stdio_server_with(|_| {
            invoked = true;
            Ok(())
        })
        .expect("wrapper should return callback result");
        assert!(invoked);
    }

    #[test]
    fn run_stdio_server_with_propagates_callback_error() {
        let err =
            run_stdio_server_with(|_| Err(anyhow!("forced startup failure"))).expect_err("error");
        assert!(err.to_string().contains("forced startup failure"));
    }
}
