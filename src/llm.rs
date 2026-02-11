use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use globset::{Glob, GlobSetBuilder};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::checks::{Finding, Severity};
use crate::config::{
    DebugConfig, LlmAgentConfig, LlmAgentMcpConfig, LlmConfig, LlmWorkflowStrategy,
    McpToolCallConfig, McpTransport, ReviewConfig,
};
use crate::diff::DiffData;

#[derive(Debug, Clone, Copy)]
pub enum ReviewMode {
    Pr,
    Scan,
}

#[derive(Debug, Clone)]
struct ProviderAttempt {
    provider: String,
    model: Option<String>,
}

#[derive(Debug, Clone)]
struct AgentRuntime {
    name: String,
    config: LlmConfig,
    instructions: String,
}

#[derive(Debug, Clone)]
struct AgentCandidate {
    agent_name: String,
    finding: LlmFinding,
}

#[derive(Debug, Clone)]
struct MergedCandidate {
    best: AgentCandidate,
    supporters: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct PromptPack {
    core_system: String,
    mode_pr: String,
    mode_scan: String,
    output_contract: String,
}

#[derive(Debug, Clone, Copy)]
struct FailedAttemptArtifact<'a> {
    attempt_index: usize,
    attempt: &'a ProviderAttempt,
    chunk: &'a str,
    prompts: &'a PromptPack,
    mode: ReviewMode,
    path_instruction_context: &'a str,
    agent_instruction_context: &'a str,
    error: &'a str,
}

#[derive(Debug, Clone)]
struct ModelRequest {
    model: String,
    system_prompt: String,
    user_prompt: String,
}

trait ModelClient {
    fn complete(&self, request: &ModelRequest) -> anyhow::Result<String>;
}

struct OpenAiApiClient {
    client: Client,
    base_url: String,
    api_key: String,
}

struct AnthropicApiClient {
    client: Client,
    base_url: String,
    api_key: String,
}

struct GeminiApiClient {
    client: Client,
    base_url: String,
    api_key: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiChatCompletionsResponse {
    choices: Vec<OpenAiChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    message: OpenAiAssistantMessage,
}

#[derive(Debug, Deserialize)]
struct OpenAiAssistantMessage {
    content: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicMessagesResponse {
    content: Vec<AnthropicContentBlock>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GeminiGenerateContentResponse {
    candidates: Option<Vec<GeminiCandidate>>,
}

#[derive(Debug, Deserialize)]
struct GeminiCandidate {
    content: Option<GeminiContent>,
}

#[derive(Debug, Deserialize)]
struct GeminiContent {
    parts: Option<Vec<GeminiPart>>,
}

#[derive(Debug, Deserialize)]
struct GeminiPart {
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LlmFindingsEnvelope {
    findings: Vec<LlmFinding>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct LlmFinding {
    rule: String,
    title: String,
    details: String,
    severity: String,
    file: Option<String>,
    line: Option<usize>,
    suggestion: Option<String>,
    confidence: Option<f64>,
    evidence: Option<Vec<String>>,
}

/// Maximum characters per diff line entry in LLM prompts.
/// Chosen to balance context window usage vs. providing sufficient code context.
const MAX_LINE_CHARS_PER_PROMPT_ENTRY: usize = 320;
const EMBEDDED_PROMPT_CORE_SYSTEM: &str = include_str!("../prompts/core_system.txt");
const EMBEDDED_PROMPT_MODE_PR: &str = include_str!("../prompts/mode_pr.txt");
const EMBEDDED_PROMPT_MODE_SCAN: &str = include_str!("../prompts/mode_scan.txt");
const EMBEDDED_PROMPT_OUTPUT_CONTRACT: &str = include_str!("../prompts/output_contract.json");
const EMBEDDED_PROMPT_AGENT_GENERAL: &str = include_str!("../prompts/agents/general.txt");
const EMBEDDED_PROMPT_AGENT_SECURITY: &str = include_str!("../prompts/agents/security.txt");
const EMBEDDED_PROMPT_AGENT_MAINTAINABILITY: &str =
    include_str!("../prompts/agents/maintainability.txt");
const EMBEDDED_PROMPT_WORKFLOW_JUDGE: &str = include_str!("../prompts/workflows/judge.txt");
const EMBEDDED_PROMPT_WORKFLOW_DEBATE: &str = include_str!("../prompts/workflows/debate.txt");
const EMBEDDED_PROMPT_WORKFLOW_CRITIQUE_REVISE: &str =
    include_str!("../prompts/workflows/critique_revise.txt");

impl OpenAiApiClient {
    fn new(config: &LlmConfig, provider: &str) -> anyhow::Result<Self> {
        let base_url = provider_base_url(config, provider);
        Ok(Self {
            client: http_client(config.provider_timeout_secs, Some(&base_url))?,
            base_url,
            api_key: provider_api_key(config, provider)?,
        })
    }
}

impl ModelClient for OpenAiApiClient {
    fn complete(&self, request: &ModelRequest) -> anyhow::Result<String> {
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));

        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&json!({
                "model": request.model,
                "temperature": 0.1,
                "messages": [
                    {
                        "role": "system",
                        "content": request.system_prompt
                    },
                    {
                        "role": "user",
                        "content": request.user_prompt
                    }
                ]
            }))
            .send()
            .context("failed to call OpenAI-compatible API")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!(
                "OpenAI-compatible API request failed: HTTP {} {}",
                status,
                truncate_text(&body, 300)
            );
        }

        let parsed: OpenAiChatCompletionsResponse = response
            .json()
            .context("failed to decode chat completions response")?;

        Ok(parsed
            .choices
            .first()
            .map(|c| c.message.content.clone())
            .unwrap_or_default())
    }
}

impl AnthropicApiClient {
    fn new(config: &LlmConfig, provider: &str) -> anyhow::Result<Self> {
        let base_url = provider_base_url(config, provider);
        Ok(Self {
            client: http_client(config.provider_timeout_secs, Some(&base_url))?,
            base_url,
            api_key: provider_api_key(config, provider)?,
        })
    }
}

impl ModelClient for AnthropicApiClient {
    fn complete(&self, request: &ModelRequest) -> anyhow::Result<String> {
        let url = format!("{}/messages", self.base_url.trim_end_matches('/'));

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-api-key",
            HeaderValue::from_str(&self.api_key).context("invalid anthropic api key header")?,
        );
        headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));

        let response = self
            .client
            .post(&url)
            .headers(headers)
            .json(&json!({
                "model": request.model,
                "system": request.system_prompt,
                "temperature": 0.1,
                "max_tokens": 1600,
                "messages": [
                    {"role": "user", "content": request.user_prompt}
                ]
            }))
            .send()
            .context("failed to call Anthropic Messages API")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!(
                "Anthropic API request failed: HTTP {} {}",
                status,
                truncate_text(&body, 300)
            );
        }

        let parsed: AnthropicMessagesResponse = response
            .json()
            .context("failed to decode Anthropic messages response")?;

        let text = parsed
            .content
            .into_iter()
            .filter(|c| c.kind == "text")
            .filter_map(|c| c.text)
            .collect::<Vec<_>>()
            .join("\n");

        if text.trim().is_empty() {
            bail!("Anthropic API returned no text content");
        }

        Ok(text)
    }
}

impl GeminiApiClient {
    fn new(config: &LlmConfig, provider: &str) -> anyhow::Result<Self> {
        let base_url = provider_base_url(config, provider);
        Ok(Self {
            client: http_client(config.provider_timeout_secs, Some(&base_url))?,
            base_url,
            api_key: provider_api_key(config, provider)?,
        })
    }
}

impl ModelClient for GeminiApiClient {
    fn complete(&self, request: &ModelRequest) -> anyhow::Result<String> {
        let url = format!(
            "{}/models/{}:generateContent?key={}",
            self.base_url.trim_end_matches('/'),
            request.model,
            self.api_key
        );

        let response = self
            .client
            .post(&url)
            .json(&json!({
                "systemInstruction": {
                    "parts": [
                        {"text": request.system_prompt}
                    ]
                },
                "contents": [
                    {
                        "role": "user",
                        "parts": [{"text": request.user_prompt}]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.1
                }
            }))
            .send()
            .context("failed to call Gemini API")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            bail!(
                "Gemini API request failed: HTTP {} {}",
                status,
                truncate_text(&body, 300)
            );
        }

        let parsed: GeminiGenerateContentResponse = response
            .json()
            .context("failed to decode Gemini response")?;

        let text = parsed
            .candidates
            .unwrap_or_default()
            .into_iter()
            .flat_map(|candidate| {
                candidate
                    .content
                    .and_then(|content| content.parts)
                    .unwrap_or_default()
            })
            .filter_map(|part| part.text)
            .collect::<Vec<_>>()
            .join("\n");

        if text.trim().is_empty() {
            bail!("Gemini API returned no text content");
        }

        Ok(text)
    }
}

pub fn run_llm_review(
    config: &LlmConfig,
    review_config: &ReviewConfig,
    debug: &DebugConfig,
    diff: &DiffData,
    mode: ReviewMode,
) -> anyhow::Result<Vec<Finding>> {
    if !config.enabled {
        return Ok(Vec::new());
    }

    let chunks = build_prompt_chunks(diff, config.max_prompt_chars, config.max_chunks);
    if chunks.is_empty() {
        return Ok(Vec::new());
    }

    let prompts = load_prompt_pack(config)?;
    let agent_runtimes = resolve_agent_runtimes(config)?;
    let changed_line_keys = build_changed_line_keys(diff);
    let path_instruction_context = build_path_instruction_context(review_config, diff)?;
    let include_agent_name_in_rule = !config.agents.is_empty();
    let mut merged: HashMap<String, MergedCandidate> = HashMap::new();
    let mut non_fatal_failures = Vec::new();
    let mut successful_envelopes = 0usize;

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        for (agent_idx, agent) in agent_runtimes.iter().enumerate() {
            let attempts = provider_attempts(&agent.config);
            let mut final_content = None;
            let mut errors = Vec::new();

            for (attempt_idx, attempt) in attempts.iter().enumerate() {
                match run_provider_attempt(
                    &agent.config,
                    &prompts,
                    mode,
                    chunk,
                    attempt,
                    &path_instruction_context,
                    &agent.instructions,
                ) {
                    Ok(content) => {
                        final_content = Some(content);
                        break;
                    }
                    Err(err) => {
                        if debug.upload_failed_provider_artifacts {
                            let artifact_idx = chunk_idx * 10_000 + agent_idx * 100 + attempt_idx;
                            let error_text = format!("agent={} error={err:#}", agent.name);
                            let _ = write_failed_attempt_artifacts(
                                debug,
                                &FailedAttemptArtifact {
                                    attempt_index: artifact_idx,
                                    attempt,
                                    chunk,
                                    prompts: &prompts,
                                    mode,
                                    path_instruction_context: &path_instruction_context,
                                    agent_instruction_context: &agent.instructions,
                                    error: &error_text,
                                },
                            );
                        }
                        errors.push(format!(
                            "{}:{} => {}",
                            attempt.provider,
                            attempt
                                .model
                                .clone()
                                .unwrap_or_else(|| "<default>".to_string()),
                            err
                        ));
                    }
                }
            }

            let Some(content) = final_content else {
                non_fatal_failures.push(format!(
                    "agent='{}' chunk={} attempts_failed={}",
                    agent.name,
                    chunk_idx,
                    errors.join(" | ")
                ));
                continue;
            };

            if content.trim().is_empty() {
                continue;
            }

            let envelope: LlmFindingsEnvelope = match parse_envelope(&content) {
                Ok(parsed) => parsed,
                Err(err) => {
                    non_fatal_failures.push(format!(
                        "agent='{}' chunk={} envelope_error={}",
                        agent.name, chunk_idx, err
                    ));
                    continue;
                }
            };
            successful_envelopes += 1;
            for finding in envelope.findings {
                if !should_keep_llm_finding(&agent.config, mode, &changed_line_keys, &finding) {
                    continue;
                }
                merge_agent_candidate(&mut merged, &agent.name, finding);
            }
        }
    }

    if successful_envelopes == 0 && !non_fatal_failures.is_empty() {
        bail!(
            "all llm provider attempts failed across chunks/agents: {}",
            truncate_text(&non_fatal_failures.join(" | "), 1600)
        );
    }
    if successful_envelopes > 0 && !non_fatal_failures.is_empty() {
        eprintln!(
            "LLM review completed with partial provider failures: {}",
            truncate_text(&non_fatal_failures.join(" | "), 1200)
        );
    }

    let merged = apply_workflow_strategy(config, &prompts, mode, &path_instruction_context, merged);

    Ok(render_merged_candidates(
        merged,
        config.max_findings,
        include_agent_name_in_rule,
    ))
}

pub fn probe_provider(config: &LlmConfig) -> anyhow::Result<()> {
    let prompts = load_prompt_pack(config)?;
    let probe_chunk =
        "Probe request: return a valid JSON envelope with findings (empty array is allowed).";

    let attempt = ProviderAttempt {
        provider: config.provider.clone(),
        model: Some(config.model.clone()),
    };
    let content = run_provider_attempt(
        config,
        &prompts,
        ReviewMode::Scan,
        probe_chunk,
        &attempt,
        "",
        "",
    )?;

    let _ = parse_envelope(&content).context(
        "provider probe output was not valid findings JSON; check provider/model and prompt contract",
    )?;

    Ok(())
}

fn resolve_agent_runtimes(config: &LlmConfig) -> anyhow::Result<Vec<AgentRuntime>> {
    let repo_skill_context = match build_repo_skill_context(config) {
        Ok(content) => content,
        Err(err) => {
            eprintln!("Repository skill context skipped: {err:#}");
            String::new()
        }
    };

    let enabled_agents = config
        .agents
        .iter()
        .filter(|agent| agent.enabled)
        .cloned()
        .collect::<Vec<_>>();

    if enabled_agents.is_empty() {
        return Ok(vec![AgentRuntime {
            name: "default".to_string(),
            config: config.clone(),
            instructions: repo_skill_context,
        }]);
    }

    let mut out = Vec::new();
    for agent in enabled_agents {
        let mut agent_cfg = config.clone();
        agent_cfg.agents.clear();
        if let Some(provider) = agent
            .provider
            .as_ref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
        {
            agent_cfg.provider = provider.to_string();
        }
        if let Some(model) = agent
            .model
            .as_ref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
        {
            agent_cfg.model = model.to_string();
        }
        if let Some(min_confidence) = agent.min_confidence {
            agent_cfg.min_confidence = min_confidence;
        }

        out.push(AgentRuntime {
            name: agent.name.trim().to_string(),
            config: agent_cfg,
            instructions: build_agent_instruction_context(&agent, &repo_skill_context)?,
        });
    }

    Ok(out)
}

fn build_agent_instruction_context(
    agent: &LlmAgentConfig,
    repo_skill_context: &str,
) -> anyhow::Result<String> {
    let mut parts = Vec::new();
    if !agent.focus.trim().is_empty() {
        parts.push(format!(
            "Agent '{}' focus: {}",
            agent.name,
            agent.focus.trim()
        ));
    }
    if let Some(prompt_file) = agent
        .prompt_file
        .as_ref()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        let content = read_prompt_file(prompt_file).with_context(|| {
            format!(
                "failed to read llm.agents['{}'].prompt_file '{}'",
                agent.name, prompt_file
            )
        })?;
        if !content.trim().is_empty() {
            parts.push(content);
        }
    }
    if !repo_skill_context.trim().is_empty() {
        parts.push(repo_skill_context.to_string());
    }

    let mcp_context = build_agent_mcp_context(agent);
    if !mcp_context.trim().is_empty() {
        parts.push(mcp_context);
    }

    Ok(parts.join("\n\n"))
}

fn build_repo_skill_context(config: &LlmConfig) -> anyhow::Result<String> {
    if !config.repo_skills.enabled {
        return Ok(String::new());
    }

    let root = Path::new("skills");
    if !root.exists() {
        return Ok(String::new());
    }

    let mut files = Vec::new();
    collect_skill_files(root, &mut files)?;
    files.sort();
    files.truncate(config.repo_skills.max_files);

    let mut sections = Vec::new();
    for file in files {
        let content = fs::read_to_string(&file)
            .with_context(|| format!("failed to read repository skill file {}", file.display()))?;
        if content.trim().is_empty() {
            continue;
        }
        sections.push(format!(
            "Skill file `{}`:\n{}",
            file.display(),
            truncate_text(&content, config.repo_skills.max_chars_per_file)
        ));
    }

    if sections.is_empty() {
        return Ok(String::new());
    }

    Ok(format!(
        "Repository skill context (local SKILL.md files):\n{}",
        sections.join("\n\n")
    ))
}

fn collect_skill_files(root: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in fs::read_dir(root)
        .with_context(|| format!("failed to read skills directory {}", root.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read skills entry in {}", root.display()))?;
        let file_type = entry.file_type().with_context(|| {
            format!("failed to inspect skills entry {}", entry.path().display())
        })?;
        if file_type.is_dir() {
            collect_skill_files(&entry.path(), out)?;
            continue;
        }
        if file_type.is_file() && entry.file_name() == "SKILL.md" {
            out.push(entry.path());
        }
    }
    Ok(())
}

fn build_agent_mcp_context(agent: &LlmAgentConfig) -> String {
    let mut sections = Vec::new();
    for mcp in agent.mcp.iter().filter(|cfg| cfg.enabled) {
        match collect_mcp_context_sync(agent, mcp) {
            Ok(content) => {
                if !content.trim().is_empty() {
                    sections.push(format!(
                        "MCP context from '{}' (transport={}):\n{}",
                        mcp.name,
                        mcp_transport_label(mcp.transport),
                        content
                    ));
                }
            }
            Err(err) => {
                eprintln!(
                    "LLM agent '{}' MCP context '{}' skipped: {err:#}",
                    agent.name, mcp.name
                );
            }
        }
    }
    sections.join("\n\n")
}

fn collect_mcp_context_sync(
    agent: &LlmAgentConfig,
    mcp: &LlmAgentMcpConfig,
) -> anyhow::Result<String> {
    let agent_name = agent.name.clone();
    let mcp_cfg = mcp.clone();
    run_on_tokio_thread(async move { collect_mcp_context_async(&agent_name, &mcp_cfg).await })
}

fn run_on_tokio_thread<F, T>(future: F) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let handle = std::thread::spawn(move || -> anyhow::Result<T> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to initialize Tokio runtime for MCP context")?;
        runtime.block_on(future)
    });

    match handle.join() {
        Ok(result) => result,
        Err(_) => bail!("MCP runtime thread panicked"),
    }
}

async fn collect_mcp_context_async(
    agent_name: &str,
    mcp: &LlmAgentMcpConfig,
) -> anyhow::Result<String> {
    use rmcp::{
        ServiceExt,
        transport::{
            StreamableHttpClientTransport, TokioChildProcess,
            streamable_http_client::StreamableHttpClientTransportConfig,
        },
    };

    match mcp.transport {
        McpTransport::Stdio => {
            let command = mcp
                .command
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .context("missing MCP stdio command")?;
            let mut child_command = tokio::process::Command::new(command);
            child_command.args(&mcp.args);
            let transport = TokioChildProcess::new(child_command).with_context(|| {
                format!(
                    "failed to spawn MCP stdio process '{}' for agent '{}'",
                    command, agent_name
                )
            })?;
            let service = ().serve(transport).await.with_context(|| {
                format!("failed to initialize MCP stdio transport for agent '{agent_name}'")
            })?;
            let output = execute_mcp_tool_calls(service.peer(), mcp).await;
            let _ = service.cancel().await;
            output
        }
        McpTransport::Http | McpTransport::Sse => {
            let url = mcp
                .url
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .context("missing MCP URL")?;
            let mut transport_cfg = StreamableHttpClientTransportConfig::with_uri(url.to_string());
            if let Some(auth_header_env) = mcp
                .auth_header_env
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                && let Ok(auth_header) = std::env::var(auth_header_env)
                && !auth_header.trim().is_empty()
            {
                transport_cfg = transport_cfg.auth_header(auth_header);
            }

            let transport = StreamableHttpClientTransport::from_config(transport_cfg);
            let service = ().serve(transport).await.with_context(|| {
                format!(
                    "failed to initialize MCP {} transport '{}' for agent '{}'",
                    mcp_transport_label(mcp.transport),
                    url,
                    agent_name
                )
            })?;
            let output = execute_mcp_tool_calls(service.peer(), mcp).await;
            let _ = service.cancel().await;
            output
        }
    }
}

async fn execute_mcp_tool_calls(
    peer: &rmcp::service::Peer<rmcp::RoleClient>,
    mcp: &LlmAgentMcpConfig,
) -> anyhow::Result<String> {
    let timeout = Duration::from_secs(mcp.timeout_secs.max(1));

    if mcp.tool_calls.is_empty() {
        let tools = tokio::time::timeout(timeout, peer.list_all_tools())
            .await
            .with_context(|| format!("MCP list_tools timed out after {}s", timeout.as_secs()))?
            .context("MCP list_tools failed")?;
        if tools.is_empty() {
            return Ok("No tools reported by MCP server.".to_string());
        }
        let mut names = tools.into_iter().map(|tool| tool.name).collect::<Vec<_>>();
        names.sort();
        return Ok(format!(
            "Available MCP tools: {}",
            names.into_iter().take(20).collect::<Vec<_>>().join(", ")
        ));
    }

    let mut sections = Vec::new();
    for call in &mcp.tool_calls {
        let params = mcp_call_params(call)?;
        let result = tokio::time::timeout(timeout, peer.call_tool(params))
            .await
            .with_context(|| {
                format!(
                    "MCP call_tool '{}' timed out after {}s",
                    call.name,
                    timeout.as_secs()
                )
            })?
            .with_context(|| format!("MCP call_tool '{}' failed", call.name))?;
        sections.push(format!(
            "Tool `{}` result:\n{}",
            call.name,
            render_mcp_tool_result(&result, mcp.max_tool_result_chars)
        ));
    }

    Ok(sections.join("\n\n"))
}

fn mcp_call_params(call: &McpToolCallConfig) -> anyhow::Result<rmcp::model::CallToolRequestParams> {
    let arguments = match &call.arguments {
        Value::Object(map) => Some(map.clone()),
        Value::Null => None,
        _ => bail!("MCP tool call arguments must be an object"),
    };

    Ok(rmcp::model::CallToolRequestParams {
        meta: None,
        name: call.name.clone().into(),
        arguments,
        task: None,
    })
}

fn render_mcp_tool_result(result: &rmcp::model::CallToolResult, max_chars: usize) -> String {
    let mut parts = Vec::new();
    for item in &result.content {
        match &item.raw {
            rmcp::model::RawContent::Text(text) => parts.push(text.text.clone()),
            other => {
                let rendered = serde_json::to_string(other)
                    .unwrap_or_else(|_| "[non-text MCP content]".to_string());
                parts.push(rendered);
            }
        }
    }
    if let Some(structured) = &result.structured_content {
        parts.push(structured.to_string());
    }
    let mut out = parts.join("\n");
    if out.trim().is_empty() {
        out = "[empty MCP tool result]".to_string();
    }
    if matches!(result.is_error, Some(true)) {
        out = format!("(tool reported error)\n{out}");
    }
    truncate_text(&out, max_chars)
}

fn mcp_transport_label(transport: McpTransport) -> &'static str {
    match transport {
        McpTransport::Stdio => "stdio",
        McpTransport::Http => "http",
        McpTransport::Sse => "sse",
    }
}

fn merge_agent_candidate(
    merged: &mut HashMap<String, MergedCandidate>,
    agent_name: &str,
    candidate: LlmFinding,
) {
    let key = llm_candidate_key(&candidate);
    if let Some(existing) = merged.get_mut(&key) {
        existing.supporters.insert(agent_name.to_string());
        if candidate_beats(&candidate, &existing.best.finding) {
            existing.best = AgentCandidate {
                agent_name: agent_name.to_string(),
                finding: candidate,
            };
        }
        return;
    }

    let mut supporters = BTreeSet::new();
    supporters.insert(agent_name.to_string());
    merged.insert(
        key,
        MergedCandidate {
            best: AgentCandidate {
                agent_name: agent_name.to_string(),
                finding: candidate,
            },
            supporters,
        },
    );
}

fn llm_candidate_key(candidate: &LlmFinding) -> String {
    let location = format!(
        "{}:{}",
        candidate
            .file
            .as_deref()
            .map(normalize_path_for_compare)
            .unwrap_or_default(),
        candidate.line.unwrap_or_default()
    );

    if !location.trim_matches(':').is_empty() {
        return format!(
            "loc:{}|title:{}",
            location,
            normalize_text_for_key(&candidate.title)
        );
    }

    format!(
        "global:{}|{}",
        normalize_text_for_key(&candidate.title),
        normalize_text_for_key(&candidate.details)
    )
}

fn normalize_text_for_key(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn candidate_beats(candidate: &LlmFinding, existing: &LlmFinding) -> bool {
    let lhs_severity = severity_rank(&candidate.severity);
    let rhs_severity = severity_rank(&existing.severity);
    if lhs_severity != rhs_severity {
        return lhs_severity > rhs_severity;
    }

    let lhs_confidence = candidate.confidence.unwrap_or(0.0);
    let rhs_confidence = existing.confidence.unwrap_or(0.0);
    lhs_confidence > rhs_confidence
}

fn severity_rank(label: &str) -> u8 {
    match label.to_ascii_lowercase().as_str() {
        "critical" | "high" => 4,
        "error" => 3,
        "warning" | "warn" => 2,
        _ => 1,
    }
}

fn render_merged_candidates(
    merged: HashMap<String, MergedCandidate>,
    max_findings: usize,
    include_agent_name_in_rule: bool,
) -> Vec<Finding> {
    let mut candidates = merged
        .into_values()
        .map(|candidate| candidate.best)
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| {
        severity_rank(&b.finding.severity)
            .cmp(&severity_rank(&a.finding.severity))
            .then_with(|| {
                b.finding
                    .confidence
                    .partial_cmp(&a.finding.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.finding.title.cmp(&b.finding.title))
    });

    let mut out = Vec::new();
    for candidate in candidates.into_iter().take(max_findings) {
        let finding = candidate.finding;
        let severity = Severity::from_label(&finding.severity).unwrap_or(Severity::Info);
        let base_rule = finding.rule.trim();
        let rule = if include_agent_name_in_rule {
            format!(
                "llm:{}:{}",
                sanitize(&candidate.agent_name).to_ascii_lowercase(),
                base_rule
            )
        } else {
            format!("llm:{base_rule}")
        };

        out.push(Finding {
            rule,
            title: finding.title,
            details: append_evidence(finding.details, finding.evidence),
            severity,
            file: finding.file,
            line: finding.line,
            suggestion: finding.suggestion,
        });
    }

    out
}

fn apply_workflow_strategy(
    config: &LlmConfig,
    prompts: &PromptPack,
    mode: ReviewMode,
    path_instruction_context: &str,
    merged: HashMap<String, MergedCandidate>,
) -> HashMap<String, MergedCandidate> {
    let mut current = merged;
    if matches!(
        config.workflow_strategy,
        LlmWorkflowStrategy::Consensus | LlmWorkflowStrategy::JudgeConsensus
    ) {
        current = filter_by_consensus_support(current, config.consensus_min_support);
    }
    match config.workflow_strategy {
        LlmWorkflowStrategy::Merge | LlmWorkflowStrategy::Consensus => current,
        LlmWorkflowStrategy::Judge | LlmWorkflowStrategy::JudgeConsensus => {
            apply_judge_selection(config, prompts, mode, path_instruction_context, current)
        }
        LlmWorkflowStrategy::Debate => {
            apply_debate_selection(config, prompts, mode, path_instruction_context, current)
        }
        LlmWorkflowStrategy::CritiqueRevise => apply_critique_revise_selection(
            config,
            prompts,
            mode,
            path_instruction_context,
            current,
        ),
    }
}

fn filter_by_consensus_support(
    merged: HashMap<String, MergedCandidate>,
    min_support: usize,
) -> HashMap<String, MergedCandidate> {
    if min_support <= 1 {
        return merged;
    }
    merged
        .into_iter()
        .filter(|(_, candidate)| candidate.supporters.len() >= min_support)
        .collect()
}

fn apply_judge_selection(
    config: &LlmConfig,
    prompts: &PromptPack,
    mode: ReviewMode,
    path_instruction_context: &str,
    merged: HashMap<String, MergedCandidate>,
) -> HashMap<String, MergedCandidate> {
    if merged.is_empty() {
        return merged;
    }

    let ranked = rank_candidates(config, &merged);

    let judge_instruction_context = match read_prompt_file(&config.judge_prompt_file) {
        Ok(content) => content,
        Err(err) => {
            eprintln!(
                "LLM judge workflow could not load llm.judge_prompt_file '{}': {err:#}; falling back to pre-judge findings",
                config.judge_prompt_file
            );
            return merged;
        }
    };

    let (judge_prompt, prompt_ranked) = build_judge_user_prompt(config, &ranked);
    match run_adjudication_pass(
        config,
        prompts,
        mode,
        path_instruction_context,
        &prompt_ranked,
        &judge_instruction_context,
        &judge_prompt,
    ) {
        Ok(selected_keys) => filter_merged_by_selected_keys(merged, &selected_keys),
        Err(err) => {
            eprintln!(
                "LLM judge workflow failed; falling back to pre-judge findings: {}",
                truncate_text(&format!("{err:#}"), 1200)
            );
            merged
        }
    }
}

fn apply_debate_selection(
    config: &LlmConfig,
    prompts: &PromptPack,
    mode: ReviewMode,
    path_instruction_context: &str,
    merged: HashMap<String, MergedCandidate>,
) -> HashMap<String, MergedCandidate> {
    if merged.is_empty() {
        return merged;
    }

    let ranked = rank_candidates(config, &merged);
    let judge_instruction_context = match read_prompt_file(&config.judge_prompt_file) {
        Ok(content) => content,
        Err(err) => {
            eprintln!(
                "LLM debate workflow could not load llm.judge_prompt_file '{}': {err:#}; falling back to pre-debate findings",
                config.judge_prompt_file
            );
            return merged;
        }
    };
    let debate_instruction_context = match read_prompt_file(&config.debate_prompt_file) {
        Ok(content) => content,
        Err(err) => {
            eprintln!(
                "LLM debate workflow could not load llm.debate_prompt_file '{}': {err:#}; falling back to pre-debate findings",
                config.debate_prompt_file
            );
            return merged;
        }
    };

    let (proposal_prompt, proposal_ranked) = build_judge_user_prompt(config, &ranked);
    let proposal_keys = match run_adjudication_pass(
        config,
        prompts,
        mode,
        path_instruction_context,
        &proposal_ranked,
        &judge_instruction_context,
        &proposal_prompt,
    ) {
        Ok(keys) => keys,
        Err(err) => {
            eprintln!(
                "LLM debate workflow failed in proposal phase; falling back to pre-debate findings: {}",
                truncate_text(&format!("{err:#}"), 1200)
            );
            return merged;
        }
    };

    let (debate_prompt, debate_ranked) =
        build_debate_user_prompt(config, &proposal_ranked, &proposal_keys);
    match run_adjudication_pass(
        config,
        prompts,
        mode,
        path_instruction_context,
        &debate_ranked,
        &debate_instruction_context,
        &debate_prompt,
    ) {
        Ok(keys) => filter_merged_by_selected_keys(merged, &keys),
        Err(err) => {
            eprintln!(
                "LLM debate workflow failed in challenge phase; falling back to proposal-phase findings: {}",
                truncate_text(&format!("{err:#}"), 1200)
            );
            filter_merged_by_selected_keys(merged, &proposal_keys)
        }
    }
}

fn apply_critique_revise_selection(
    config: &LlmConfig,
    prompts: &PromptPack,
    mode: ReviewMode,
    path_instruction_context: &str,
    merged: HashMap<String, MergedCandidate>,
) -> HashMap<String, MergedCandidate> {
    if merged.is_empty() {
        return merged;
    }

    let ranked = rank_candidates(config, &merged);
    let judge_instruction_context = match read_prompt_file(&config.judge_prompt_file) {
        Ok(content) => content,
        Err(err) => {
            eprintln!(
                "LLM critique-revise workflow could not load llm.judge_prompt_file '{}': {err:#}; falling back to pre-revision findings",
                config.judge_prompt_file
            );
            return merged;
        }
    };
    let revise_instruction_context = match read_prompt_file(&config.critique_revise_prompt_file) {
        Ok(content) => content,
        Err(err) => {
            eprintln!(
                "LLM critique-revise workflow could not load llm.critique_revise_prompt_file '{}': {err:#}; falling back to pre-revision findings",
                config.critique_revise_prompt_file
            );
            return merged;
        }
    };

    let (draft_prompt, draft_ranked) = build_judge_user_prompt(config, &ranked);
    let draft_keys = match run_adjudication_pass(
        config,
        prompts,
        mode,
        path_instruction_context,
        &draft_ranked,
        &judge_instruction_context,
        &draft_prompt,
    ) {
        Ok(keys) => keys,
        Err(err) => {
            eprintln!(
                "LLM critique-revise workflow failed in draft phase; falling back to pre-revision findings: {}",
                truncate_text(&format!("{err:#}"), 1200)
            );
            return merged;
        }
    };

    let (revise_prompt, revise_ranked) =
        build_critique_revise_user_prompt(config, &draft_ranked, &draft_keys);
    match run_adjudication_pass(
        config,
        prompts,
        mode,
        path_instruction_context,
        &revise_ranked,
        &revise_instruction_context,
        &revise_prompt,
    ) {
        Ok(keys) => filter_merged_by_selected_keys(merged, &keys),
        Err(err) => {
            eprintln!(
                "LLM critique-revise workflow failed in revise phase; falling back to draft-phase findings: {}",
                truncate_text(&format!("{err:#}"), 1200)
            );
            filter_merged_by_selected_keys(merged, &draft_keys)
        }
    }
}

fn run_adjudication_pass(
    config: &LlmConfig,
    prompts: &PromptPack,
    mode: ReviewMode,
    path_instruction_context: &str,
    ranked: &[(String, MergedCandidate)],
    instruction_context: &str,
    user_prompt: &str,
) -> anyhow::Result<HashSet<String>> {
    let mut judge_cfg = config.clone();
    judge_cfg.agents.clear();
    if let Some(model) = config
        .judge_model
        .as_ref()
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        judge_cfg.model = model.to_string();
    }

    let candidate_keys = ranked
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<HashSet<_>>();
    let mut match_lookup = HashMap::new();
    for (key, candidate) in ranked {
        match_lookup.insert(build_judge_match_key(&candidate.best.finding), key.clone());
    }

    let attempts = provider_attempts(&judge_cfg);
    let mut errors = Vec::new();
    for attempt in attempts {
        let content = match run_provider_attempt(
            &judge_cfg,
            prompts,
            mode,
            user_prompt,
            &attempt,
            path_instruction_context,
            instruction_context,
        ) {
            Ok(content) => content,
            Err(err) => {
                errors.push(format!(
                    "{}:{} => {}",
                    attempt.provider,
                    attempt
                        .model
                        .clone()
                        .unwrap_or_else(|| "<default>".to_string()),
                    err
                ));
                continue;
            }
        };

        let envelope = match parse_envelope(&content) {
            Ok(envelope) => envelope,
            Err(err) => {
                errors.push(format!(
                    "{}:{} => envelope_error={}",
                    attempt.provider,
                    attempt
                        .model
                        .clone()
                        .unwrap_or_else(|| "<default>".to_string()),
                    err
                ));
                continue;
            }
        };

        return Ok(match_findings_to_candidate_keys(
            envelope.findings,
            &candidate_keys,
            &match_lookup,
        ));
    }

    bail!(
        "all adjudication provider attempts failed: {}",
        truncate_text(&errors.join(" | "), 1200)
    )
}

fn match_findings_to_candidate_keys(
    findings: Vec<LlmFinding>,
    candidate_keys: &HashSet<String>,
    match_lookup: &HashMap<String, String>,
) -> HashSet<String> {
    let mut selected_keys = HashSet::new();
    for finding in findings {
        let exact = llm_candidate_key(&finding);
        if candidate_keys.contains(&exact) {
            selected_keys.insert(exact);
            continue;
        }
        if let Some(mapped) = match_lookup.get(&build_judge_match_key(&finding)) {
            selected_keys.insert(mapped.clone());
        }
    }
    selected_keys
}

fn rank_candidates(
    config: &LlmConfig,
    merged: &HashMap<String, MergedCandidate>,
) -> Vec<(String, MergedCandidate)> {
    let mut ranked = merged
        .iter()
        .map(|(key, candidate)| (key.clone(), candidate.clone()))
        .collect::<Vec<_>>();
    ranked.sort_by(|a, b| {
        severity_rank(&b.1.best.finding.severity)
            .cmp(&severity_rank(&a.1.best.finding.severity))
            .then_with(|| {
                b.1.best
                    .finding
                    .confidence
                    .partial_cmp(&a.1.best.finding.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.1.best.finding.title.cmp(&b.1.best.finding.title))
    });
    ranked.truncate(config.judge_max_candidates);
    ranked
}

fn filter_merged_by_selected_keys(
    merged: HashMap<String, MergedCandidate>,
    selected_keys: &HashSet<String>,
) -> HashMap<String, MergedCandidate> {
    merged
        .into_iter()
        .filter(|(key, _)| selected_keys.contains(key))
        .collect()
}

fn build_candidate_payload(ranked: &[(String, MergedCandidate)]) -> Vec<Value> {
    ranked
        .iter()
        .map(|(id, candidate)| {
            json!({
                "id": id,
                "support_count": candidate.supporters.len(),
                "supporting_agents": candidate.supporters.iter().cloned().collect::<Vec<_>>(),
                "selected_from_agent": candidate.best.agent_name,
                "finding": candidate.best.finding
            })
        })
        .collect::<Vec<_>>()
}

fn fit_ranked_prompt<F>(
    config: &LlmConfig,
    ranked: &[(String, MergedCandidate)],
    mut render: F,
) -> (String, Vec<(String, MergedCandidate)>)
where
    F: FnMut(&[(String, MergedCandidate)], bool) -> String,
{
    let mut keep = ranked.len();
    loop {
        let view = &ranked[..keep];
        let truncated = keep < ranked.len();
        let prompt = render(view, truncated);
        if prompt.len() <= config.max_prompt_chars {
            return (prompt, view.to_vec());
        }
        if keep == 0 {
            return (
                truncate_text(&prompt, config.max_prompt_chars.max(64)),
                Vec::new(),
            );
        }
        keep -= 1;
    }
}

fn build_selection_payload(
    ranked: &[(String, MergedCandidate)],
    selected_keys: &HashSet<String>,
) -> Vec<Value> {
    ranked
        .iter()
        .filter(|(id, _)| selected_keys.contains(id))
        .map(|(id, candidate)| {
            json!({
                "id": id,
                "support_count": candidate.supporters.len(),
                "selected_from_agent": candidate.best.agent_name,
                "finding": candidate.best.finding
            })
        })
        .collect::<Vec<_>>()
}

fn build_judge_user_prompt(
    config: &LlmConfig,
    ranked: &[(String, MergedCandidate)],
) -> (String, Vec<(String, MergedCandidate)>) {
    fit_ranked_prompt(config, ranked, |view, truncated| {
        let payload_json = serde_json::to_string_pretty(&build_candidate_payload(view))
            .unwrap_or_else(|_| "[]".to_string());
        let truncation_note = if truncated {
            "\nNote: candidate list was truncated to fit prompt budget."
        } else {
            ""
        };
        format!(
            "You are a final review adjudicator selecting high-signal findings for publication.\n\n\
Return ONLY a JSON envelope with top-level key `findings`.\n\
Choose only from the provided candidates and copy selected findings exactly (no rewrites).\n\
If no findings are strong enough, return {{\"findings\":[]}}.\n\n\
Current workflow strategy: {}\n\
Consensus threshold (if applied): {}\n\n\
Candidate findings:\n{}{}",
            workflow_strategy_label(config.workflow_strategy),
            config.consensus_min_support,
            payload_json,
            truncation_note
        )
    })
}

fn build_debate_user_prompt(
    config: &LlmConfig,
    ranked: &[(String, MergedCandidate)],
    proposal_keys: &HashSet<String>,
) -> (String, Vec<(String, MergedCandidate)>) {
    fit_ranked_prompt(config, ranked, |view, truncated| {
        let candidate_json = serde_json::to_string_pretty(&build_candidate_payload(view))
            .unwrap_or_else(|_| "[]".to_string());
        let proposal_json =
            serde_json::to_string_pretty(&build_selection_payload(view, proposal_keys))
                .unwrap_or_else(|_| "[]".to_string());
        let truncation_note = if truncated {
            "\nNote: candidate/proposal lists were truncated to fit prompt budget."
        } else {
            ""
        };
        format!(
            "You are running a structured debate adjudication pass.\n\n\
Return ONLY a JSON envelope with top-level key `findings`.\n\
Choose only from the provided candidate findings and copy selected findings exactly.\n\
Use the first-pass proposal as input, but you may keep, remove, or add candidate findings if justified.\n\n\
Current workflow strategy: {}\n\
Consensus threshold (if applied): {}\n\n\
Candidate findings:\n{}\n\n\
First-pass proposal:\n{}{}",
            workflow_strategy_label(config.workflow_strategy),
            config.consensus_min_support,
            candidate_json,
            proposal_json,
            truncation_note
        )
    })
}

fn build_critique_revise_user_prompt(
    config: &LlmConfig,
    ranked: &[(String, MergedCandidate)],
    draft_keys: &HashSet<String>,
) -> (String, Vec<(String, MergedCandidate)>) {
    fit_ranked_prompt(config, ranked, |view, truncated| {
        let candidate_json = serde_json::to_string_pretty(&build_candidate_payload(view))
            .unwrap_or_else(|_| "[]".to_string());
        let draft_json = serde_json::to_string_pretty(&build_selection_payload(view, draft_keys))
            .unwrap_or_else(|_| "[]".to_string());
        let truncation_note = if truncated {
            "\nNote: candidate/draft lists were truncated to fit prompt budget."
        } else {
            ""
        };
        format!(
            "You are running a critique-and-revise adjudication pass.\n\n\
Return ONLY a JSON envelope with top-level key `findings`.\n\
Choose only from the provided candidate findings and copy selected findings exactly.\n\
Critique the draft selection for false positives, duplicates, and missing high-signal issues, then revise it.\n\n\
Current workflow strategy: {}\n\
Consensus threshold (if applied): {}\n\n\
Candidate findings:\n{}\n\n\
Draft selection:\n{}{}",
            workflow_strategy_label(config.workflow_strategy),
            config.consensus_min_support,
            candidate_json,
            draft_json,
            truncation_note
        )
    })
}

fn workflow_strategy_label(strategy: LlmWorkflowStrategy) -> &'static str {
    match strategy {
        LlmWorkflowStrategy::Merge => "merge",
        LlmWorkflowStrategy::Consensus => "consensus",
        LlmWorkflowStrategy::Judge => "judge",
        LlmWorkflowStrategy::JudgeConsensus => "judge-consensus",
        LlmWorkflowStrategy::Debate => "debate",
        LlmWorkflowStrategy::CritiqueRevise => "critique-revise",
    }
}

fn build_judge_match_key(candidate: &LlmFinding) -> String {
    format!(
        "{}:{}|{}",
        candidate
            .file
            .as_deref()
            .map(normalize_path_for_compare)
            .unwrap_or_default(),
        candidate.line.unwrap_or_default(),
        normalize_text_for_key(&candidate.title)
    )
}

fn provider_attempts(config: &LlmConfig) -> Vec<ProviderAttempt> {
    let mut out = vec![ProviderAttempt {
        provider: config.provider.clone(),
        model: Some(config.model.clone()),
    }];

    for model in &config.fallback_models {
        out.push(ProviderAttempt {
            provider: config.provider.clone(),
            model: Some(model.clone()),
        });
    }

    for item in &config.fallback_providers {
        let (provider, model) = if let Some((p, m)) = item.split_once(':') {
            (p.trim().to_string(), Some(m.trim().to_string()))
        } else {
            (item.trim().to_string(), None)
        };

        if provider.is_empty() {
            continue;
        }

        out.push(ProviderAttempt { provider, model });
    }

    out
}

fn run_provider_attempt(
    config: &LlmConfig,
    prompts: &PromptPack,
    mode: ReviewMode,
    chunk: &str,
    attempt: &ProviderAttempt,
    path_instruction_context: &str,
    agent_instruction_context: &str,
) -> anyhow::Result<String> {
    let request = ModelRequest {
        model: attempt
            .model
            .as_ref()
            .cloned()
            .unwrap_or_else(|| config.model.clone()),
        system_prompt: build_system_prompt(
            prompts,
            mode,
            path_instruction_context,
            agent_instruction_context,
        ),
        user_prompt: chunk.to_string(),
    };

    match attempt.provider.as_str() {
        "openai-api" | "openai-compatible" => {
            OpenAiApiClient::new(config, attempt.provider.as_str())?.complete(&request)
        }
        "anthropic-api" => {
            AnthropicApiClient::new(config, attempt.provider.as_str())?.complete(&request)
        }
        "gemini-api" => GeminiApiClient::new(config, attempt.provider.as_str())?.complete(&request),
        other => bail!(
            "unsupported llm.provider '{}'; expected openai-api, anthropic-api, gemini-api, or openai-compatible",
            other
        ),
    }
}

fn provider_base_url(config: &LlmConfig, provider: &str) -> String {
    let configured = config.base_url.trim();
    let default_openai = "https://api.openai.com/v1";
    match provider {
        "openai-api" | "openai-compatible" => {
            if configured.is_empty() {
                default_openai.to_string()
            } else {
                configured.to_string()
            }
        }
        "anthropic-api" => {
            if provider == config.provider && !configured.is_empty() {
                configured.to_string()
            } else {
                "https://api.anthropic.com/v1".to_string()
            }
        }
        "gemini-api" => {
            if provider == config.provider && !configured.is_empty() {
                configured.to_string()
            } else {
                "https://generativelanguage.googleapis.com/v1beta".to_string()
            }
        }
        _ => {
            if configured.is_empty() {
                default_openai.to_string()
            } else {
                configured.to_string()
            }
        }
    }
}

fn provider_api_key(config: &LlmConfig, provider: &str) -> anyhow::Result<String> {
    let key_env = if provider == config.provider {
        config.api_key_env.as_str()
    } else {
        match provider {
            "openai-api" | "openai-compatible" => "OPENAI_API_KEY",
            "anthropic-api" => "ANTHROPIC_API_KEY",
            "gemini-api" => "GEMINI_API_KEY",
            _ => config.api_key_env.as_str(),
        }
    };

    std::env::var(key_env)
        .with_context(|| format!("{key_env} is required for provider '{provider}'"))
}

fn is_loopback_base_url(base_url: &str) -> bool {
    base_url.contains("://127.0.0.1")
        || base_url.contains("://localhost")
        || base_url.contains("://[::1]")
}

fn http_client(timeout_secs: u64, base_url: Option<&str>) -> anyhow::Result<Client> {
    let mut builder = Client::builder().timeout(Duration::from_secs(timeout_secs.max(1)));
    if base_url.is_some_and(is_loopback_base_url) {
        builder = builder.no_proxy();
    }
    builder
        .build()
        .context("failed to build provider HTTP client")
}

fn build_system_prompt(
    prompts: &PromptPack,
    mode: ReviewMode,
    path_instruction_context: &str,
    agent_instruction_context: &str,
) -> String {
    let mode_prompt = match mode {
        ReviewMode::Pr => &prompts.mode_pr,
        ReviewMode::Scan => &prompts.mode_scan,
    };

    let mut sections = vec![prompts.core_system.clone(), mode_prompt.clone()];
    if !path_instruction_context.trim().is_empty() {
        sections.push(format!(
            "Path-specific review instructions:\n{}",
            path_instruction_context
        ));
    }
    if !agent_instruction_context.trim().is_empty() {
        sections.push(format!(
            "Agent-specific review instructions:\n{}",
            agent_instruction_context
        ));
    }
    sections.push(prompts.output_contract.clone());
    sections.join("\n\n")
}

fn load_prompt_pack(config: &LlmConfig) -> anyhow::Result<PromptPack> {
    Ok(PromptPack {
        core_system: read_prompt_file(&config.prompt_core_file)?,
        mode_pr: read_prompt_file(&config.prompt_pr_file)?,
        mode_scan: read_prompt_file(&config.prompt_scan_file)?,
        output_contract: read_prompt_file(&config.prompt_output_contract_file)?,
    })
}

fn read_prompt_file(path: &str) -> anyhow::Result<String> {
    match fs::read_to_string(Path::new(path)) {
        Ok(content) => Ok(content),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound
                && let Some(embedded) = embedded_prompt_for_path(path)
            {
                return Ok(embedded.to_string());
            }
            Err(err).with_context(|| format!("failed to read prompt file '{}'", path))
        }
    }
}

fn embedded_prompt_for_path(path: &str) -> Option<&'static str> {
    let normalized = path.trim().replace('\\', "/");
    let mut key = normalized.as_str();
    while let Some(stripped) = key.strip_prefix("./") {
        key = stripped;
    }

    match key {
        "prompts/core_system.txt" => Some(EMBEDDED_PROMPT_CORE_SYSTEM),
        "prompts/mode_pr.txt" => Some(EMBEDDED_PROMPT_MODE_PR),
        "prompts/mode_scan.txt" => Some(EMBEDDED_PROMPT_MODE_SCAN),
        "prompts/output_contract.json" => Some(EMBEDDED_PROMPT_OUTPUT_CONTRACT),
        "prompts/agents/general.txt" => Some(EMBEDDED_PROMPT_AGENT_GENERAL),
        "prompts/agents/security.txt" => Some(EMBEDDED_PROMPT_AGENT_SECURITY),
        "prompts/agents/maintainability.txt" => Some(EMBEDDED_PROMPT_AGENT_MAINTAINABILITY),
        "prompts/workflows/judge.txt" => Some(EMBEDDED_PROMPT_WORKFLOW_JUDGE),
        "prompts/workflows/debate.txt" => Some(EMBEDDED_PROMPT_WORKFLOW_DEBATE),
        "prompts/workflows/critique_revise.txt" => Some(EMBEDDED_PROMPT_WORKFLOW_CRITIQUE_REVISE),
        _ => None,
    }
}

fn append_evidence(details: String, evidence: Option<Vec<String>>) -> String {
    let Some(evidence) = evidence else {
        return details;
    };

    if evidence.is_empty() {
        return details;
    }

    format!("{}\n\nEvidence: {}", details, evidence.join("; "))
}

fn build_path_instruction_context(
    review_config: &ReviewConfig,
    diff: &DiffData,
) -> anyhow::Result<String> {
    if review_config.path_instructions.is_empty() {
        return Ok(String::new());
    }

    let changed_files = diff
        .files
        .keys()
        .map(|p| normalize_path_for_compare(p))
        .collect::<BTreeSet<_>>();

    let mut selected = Vec::new();
    for item in &review_config.path_instructions {
        if item.instructions.trim().is_empty() || item.paths.is_empty() {
            continue;
        }

        let mut builder = GlobSetBuilder::new();
        let mut has_pattern = false;
        for pattern in &item.paths {
            let trimmed = pattern.trim();
            if trimmed.is_empty() {
                continue;
            }
            builder.add(
                Glob::new(trimmed).with_context(|| {
                    format!("invalid reviews.path_instructions glob '{trimmed}'")
                })?,
            );
            has_pattern = true;
        }
        if !has_pattern {
            continue;
        }

        let set = builder
            .build()
            .context("failed to compile reviews.path_instructions glob set")?;
        if changed_files.iter().any(|path| set.is_match(path)) {
            let label = item.name.clone().unwrap_or_else(|| item.paths.join(", "));
            selected.push(format!("- {}: {}", label, item.instructions.trim()));
        }
    }

    Ok(selected.join("\n"))
}

fn build_changed_line_keys(diff: &DiffData) -> HashSet<(String, usize)> {
    diff.added_lines
        .iter()
        .map(|line| (normalize_path_for_compare(&line.file), line.line))
        .collect()
}

fn normalize_path_for_compare(path: &str) -> String {
    let mut normalized = path.trim().replace('\\', "/");
    normalized = normalized.trim_start_matches("./").to_string();
    normalized = normalized.trim_start_matches("a/").to_string();
    normalized = normalized.trim_start_matches("b/").to_string();
    normalized
}

fn should_keep_llm_finding(
    config: &LlmConfig,
    mode: ReviewMode,
    changed_line_keys: &HashSet<(String, usize)>,
    finding: &LlmFinding,
) -> bool {
    let Some(confidence) = finding.confidence else {
        return false;
    };
    if confidence < config.min_confidence {
        return false;
    }

    if !matches!(mode, ReviewMode::Pr) || !config.pr_changed_lines_only {
        return true;
    }

    let (Some(file), Some(line)) = (finding.file.as_deref(), finding.line) else {
        return false;
    };
    let normalized = normalize_path_for_compare(file);
    if normalized.is_empty() {
        return false;
    }

    changed_line_keys.contains(&(normalized, line))
}

fn write_failed_attempt_artifacts(
    debug: &DebugConfig,
    artifact: &FailedAttemptArtifact<'_>,
) -> anyhow::Result<()> {
    let dir = PathBuf::from(&debug.artifact_dir);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create debug artifact dir {}", dir.display()))?;

    let base = format!(
        "attempt-{}-{}-{}",
        artifact.attempt_index,
        sanitize(&artifact.attempt.provider),
        sanitize(artifact.attempt.model.as_deref().unwrap_or("default"))
    );

    fs::write(
        dir.join(format!("{}.error.txt", base)),
        format!(
            "provider={:?}\nerror={}\n",
            artifact.attempt, artifact.error
        ),
    )?;
    fs::write(dir.join(format!("{}.chunk.txt", base)), artifact.chunk)?;
    fs::write(
        dir.join(format!("{}.prompt.txt", base)),
        build_system_prompt(
            artifact.prompts,
            artifact.mode,
            artifact.path_instruction_context,
            artifact.agent_instruction_context,
        ),
    )?;

    Ok(())
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn truncate_text(value: &str, max_len: usize) -> String {
    if max_len == 0 {
        return String::new();
    }

    if value.chars().count() <= max_len {
        return value.to_string();
    }

    let mut out = value
        .chars()
        .take(max_len.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}

fn truncate_prompt_line(value: &str, max_len: usize) -> String {
    truncate_text(&value.replace('\t', "    "), max_len.max(8))
}

fn build_prompt_chunks(diff: &DiffData, max_chars: usize, max_chunks: usize) -> Vec<String> {
    if max_chunks == 0 || max_chars < 512 {
        return Vec::new();
    }

    if diff.added_lines.is_empty() {
        return Vec::new();
    }

    let mut grouped: Vec<(String, Vec<(usize, String)>)> = Vec::new();
    let mut grouped_idx: HashMap<String, usize> = HashMap::new();
    for line in &diff.added_lines {
        if let Some(idx) = grouped_idx.get(&line.file).copied() {
            grouped[idx].1.push((line.line, line.content.clone()));
        } else {
            grouped_idx.insert(line.file.clone(), grouped.len());
            grouped.push((line.file.clone(), vec![(line.line, line.content.clone())]));
        }
    }

    let mut chunks = Vec::new();
    let base_header = base_prompt_header(diff);
    let mut current = base_header.clone();
    let mut has_entries = false;
    let mut current_file: Option<String> = None;

    for (file, lines) in grouped {
        for (line_no, content) in lines {
            let mut entry = String::new();
            if current_file.as_deref() != Some(file.as_str()) {
                entry.push_str(&format!("\nFile: {}\n", file));
            }
            entry.push_str(&format!(
                "L{} | +{}\n",
                line_no,
                truncate_prompt_line(&content, MAX_LINE_CHARS_PER_PROMPT_ENTRY)
            ));

            if current.len() + entry.len() > max_chars {
                if has_entries {
                    current.push_str("... (truncated to fit prompt budget)\n");
                    chunks.push(current);
                    if chunks.len() >= max_chunks {
                        return chunks;
                    }
                }
                current = base_header.clone();
                has_entries = false;
                current_file = None;

                let mut retry = format!("\nFile: {}\nL{} | +", file, line_no);
                let budget = max_chars.saturating_sub(current.len() + retry.len() + 1);
                retry.push_str(&truncate_prompt_line(&content, budget.max(16)));
                retry.push('\n');
                if current.len() + retry.len() > max_chars {
                    continue;
                }
                current.push_str(&retry);
                has_entries = true;
                current_file = Some(file.clone());
                continue;
            }

            current.push_str(&entry);
            has_entries = true;
            current_file = Some(file.clone());
        }
    }

    if has_entries && chunks.len() < max_chunks {
        chunks.push(current);
    }

    chunks
}

fn base_prompt_header(diff: &DiffData) -> String {
    let mut payload = String::new();
    payload.push_str("Review this diff chunk.\n");
    payload.push_str(&format!(
        "Diff stats: added={}, removed={}, files_changed={}\n\n",
        diff.total_added,
        diff.total_removed,
        diff.files.len()
    ));
    payload.push_str("Changed lines (added only):\n");

    payload
}

fn parse_envelope(content: &str) -> anyhow::Result<LlmFindingsEnvelope> {
    let json_text = extract_json_object(content)?;
    let value: Value = serde_json::from_str(json_text).context("failed to parse LLM JSON")?;
    validate_envelope_schema(&value)?;
    serde_json::from_value(value).context("failed to decode LLM findings envelope")
}

fn extract_json_object(content: &str) -> anyhow::Result<&str> {
    if serde_json::from_str::<Value>(content).is_ok() {
        return Ok(content);
    }

    let start = content
        .find('{')
        .context("llm response did not include JSON object")?;
    let end = content
        .rfind('}')
        .context("llm response did not include JSON object end")?;

    Ok(&content[start..=end])
}

fn validate_envelope_schema(value: &Value) -> anyhow::Result<()> {
    let obj = value
        .as_object()
        .context("llm envelope must be a JSON object")?;

    let expected_top = BTreeSet::from(["findings"]);
    let actual_top = obj.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_top != expected_top {
        bail!(
            "llm envelope must contain only the 'findings' key; got {:?}",
            actual_top
        );
    }

    let findings = obj
        .get("findings")
        .and_then(Value::as_array)
        .context("'findings' must be an array")?;

    for (idx, finding) in findings.iter().enumerate() {
        validate_finding_schema(idx, finding)?;
    }

    Ok(())
}

fn validate_finding_schema(index: usize, value: &Value) -> anyhow::Result<()> {
    let finding = value
        .as_object()
        .with_context(|| format!("finding[{index}] must be a JSON object"))?;

    let expected_keys = BTreeSet::from([
        "rule",
        "severity",
        "title",
        "details",
        "file",
        "line",
        "confidence",
        "suggestion",
        "evidence",
    ]);
    let actual_keys = finding.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_keys != expected_keys {
        bail!(
            "finding[{index}] keys mismatch; expected {:?}, got {:?}",
            expected_keys,
            actual_keys
        );
    }

    let rule = finding
        .get("rule")
        .and_then(Value::as_str)
        .with_context(|| format!("finding[{index}].rule must be a string"))?;
    if rule.trim().is_empty() {
        bail!("finding[{index}].rule must be non-empty");
    }

    let severity = finding
        .get("severity")
        .and_then(Value::as_str)
        .with_context(|| format!("finding[{index}].severity must be a string"))?
        .to_ascii_lowercase();
    if !matches!(
        severity.as_str(),
        "info" | "warning" | "warn" | "error" | "critical" | "high"
    ) {
        bail!("finding[{index}].severity must be one of info|warning|error|critical");
    }

    for key in ["title", "details"] {
        let raw = finding
            .get(key)
            .and_then(Value::as_str)
            .with_context(|| format!("finding[{index}].{key} must be a string"))?;
        if raw.trim().is_empty() {
            bail!("finding[{index}].{key} must be non-empty");
        }
    }

    let file = finding.get("file").context("missing file key")?;
    if !file.is_null()
        && file
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .is_none()
    {
        bail!("finding[{index}].file must be null or non-empty string");
    }

    let line = finding.get("line").context("missing line key")?;
    if !line.is_null() {
        let number = line
            .as_u64()
            .with_context(|| format!("finding[{index}].line must be null or integer"))?;
        if number == 0 {
            bail!("finding[{index}].line must be >= 1");
        }
        if file.is_null() {
            bail!("finding[{index}] cannot set line without file");
        }
    }

    let confidence = finding
        .get("confidence")
        .context("missing confidence key")?;
    let value = confidence
        .as_f64()
        .with_context(|| format!("finding[{index}].confidence must be a number"))?;
    if !(0.0..=1.0).contains(&value) {
        bail!("finding[{index}].confidence must be between 0.0 and 1.0");
    }

    let suggestion = finding
        .get("suggestion")
        .context("missing suggestion key")?;
    if !suggestion.is_null() && suggestion.as_str().is_none() {
        bail!("finding[{index}].suggestion must be null or string");
    }

    let evidence = finding
        .get("evidence")
        .and_then(Value::as_array)
        .with_context(|| format!("finding[{index}].evidence must be an array"))?;
    if evidence.is_empty() {
        bail!("finding[{index}].evidence must contain at least one entry");
    }
    for (ev_idx, ev) in evidence.iter().enumerate() {
        let text = ev
            .as_str()
            .with_context(|| format!("finding[{index}].evidence[{ev_idx}] must be a string"))?;
        if text.trim().is_empty() {
            bail!("finding[{index}].evidence[{ev_idx}] cannot be empty");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use mockito::{Matcher, Server};

    use super::{
        AgentCandidate, AnthropicApiClient, FailedAttemptArtifact, GeminiApiClient, LlmFinding,
        MergedCandidate, ModelClient, ModelRequest, OpenAiApiClient, PromptPack, ProviderAttempt,
        ReviewMode, append_evidence, build_changed_line_keys, build_judge_user_prompt,
        build_path_instruction_context, build_prompt_chunks, build_system_prompt, candidate_beats,
        filter_by_consensus_support, llm_candidate_key, merge_agent_candidate,
        normalize_path_for_compare, parse_envelope, probe_provider, provider_api_key,
        provider_attempts, provider_base_url, read_prompt_file, render_merged_candidates,
        resolve_agent_runtimes, run_llm_review, run_provider_attempt, should_keep_llm_finding,
        validate_envelope_schema, write_failed_attempt_artifacts,
    };
    use crate::config::{
        DebugConfig, LlmAgentConfig, LlmConfig, LlmWorkflowStrategy, PathInstruction, ReviewConfig,
    };
    use crate::diff::parse_unified_diff;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_file(name: &str, extension: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "fantastic-pr-llm-{name}-{}-{nanos}.{extension}",
            std::process::id()
        ))
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "fantastic-pr-llm-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn write_prompt_files(name: &str) -> (PathBuf, LlmConfig) {
        let dir = unique_temp_dir(name);
        std::fs::create_dir_all(&dir).expect("create prompt dir");

        let core = dir.join("core.txt");
        let pr = dir.join("pr.txt");
        let scan = dir.join("scan.txt");
        let output = dir.join("output.json");
        std::fs::write(&core, "core prompt").expect("write core");
        std::fs::write(&pr, "pr prompt").expect("write pr");
        std::fs::write(&scan, "scan prompt").expect("write scan");
        std::fs::write(&output, "output contract").expect("write output");

        let cfg = LlmConfig {
            prompt_core_file: core.to_string_lossy().to_string(),
            prompt_pr_file: pr.to_string_lossy().to_string(),
            prompt_scan_file: scan.to_string_lossy().to_string(),
            prompt_output_contract_file: output.to_string_lossy().to_string(),
            ..LlmConfig::default()
        };

        (dir, cfg)
    }

    fn sample_request() -> ModelRequest {
        ModelRequest {
            model: "model-x".to_string(),
            system_prompt: "system prompt".to_string(),
            user_prompt: "user prompt".to_string(),
        }
    }

    struct EnvGuard {
        key: String,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self {
                key: key.to_string(),
                previous,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(prev) = &self.previous {
                unsafe { std::env::set_var(&self.key, prev) };
            } else {
                unsafe { std::env::remove_var(&self.key) };
            }
        }
    }

    #[test]
    fn parses_wrapped_json() {
        let content = "```json\n{\"findings\":[{\"rule\":\"x\",\"title\":\"t\",\"details\":\"d\",\"severity\":\"critical\",\"file\":\"src/a.rs\",\"line\":1,\"confidence\":0.8,\"suggestion\":null,\"evidence\":[\"line uses unwrap\"]}]}\n```";
        let parsed = parse_envelope(content).expect("should parse json in fence");
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].rule, "x");
        assert_eq!(parsed.findings[0].severity, "critical");
    }

    #[test]
    fn embedded_prompt_fallback_supports_default_prompt_pack_paths() {
        let cases = [
            (
                "prompts\\core_system.txt",
                include_str!("../prompts/core_system.txt"),
            ),
            (
                "prompts\\mode_pr.txt",
                include_str!("../prompts/mode_pr.txt"),
            ),
            (
                "prompts\\mode_scan.txt",
                include_str!("../prompts/mode_scan.txt"),
            ),
            (
                "prompts\\output_contract.json",
                include_str!("../prompts/output_contract.json"),
            ),
            (
                "prompts\\agents\\general.txt",
                include_str!("../prompts/agents/general.txt"),
            ),
            (
                "prompts\\agents\\security.txt",
                include_str!("../prompts/agents/security.txt"),
            ),
            (
                "prompts\\agents\\maintainability.txt",
                include_str!("../prompts/agents/maintainability.txt"),
            ),
            (
                "prompts\\workflows\\judge.txt",
                include_str!("../prompts/workflows/judge.txt"),
            ),
            (
                "prompts\\workflows\\debate.txt",
                include_str!("../prompts/workflows/debate.txt"),
            ),
            (
                "prompts\\workflows\\critique_revise.txt",
                include_str!("../prompts/workflows/critique_revise.txt"),
            ),
        ];

        for (path, expected) in cases {
            let content = read_prompt_file(path).expect("embedded prompt should load");
            assert_eq!(content, expected);
        }
    }

    #[test]
    fn read_prompt_file_returns_error_for_unknown_missing_path() {
        let err = read_prompt_file("prompts\\does-not-exist.txt")
            .expect_err("unknown missing prompt path should fail");
        assert!(err.to_string().contains("failed to read prompt file"));
    }

    #[test]
    fn rejects_invalid_envelope_extra_key() {
        let value = serde_json::json!({
            "findings": [],
            "extra": true
        });
        let err = validate_envelope_schema(&value).expect_err("should reject extra key");
        assert!(err.to_string().contains("contain only the 'findings' key"));
    }

    #[test]
    fn rejects_line_without_file() {
        let content = r#"{
          "findings": [
            {
              "rule": "x",
              "severity": "warning",
              "title": "t",
              "details": "d",
              "file": null,
              "line": 3,
              "confidence": 0.7,
              "suggestion": null,
              "evidence": ["e1"]
            }
          ]
        }"#;

        let err = parse_envelope(content).expect_err("line without file should fail");
        assert!(err.to_string().contains("cannot set line without file"));
    }

    #[test]
    fn rejects_null_confidence() {
        let content = r#"{
          "findings": [
            {
              "rule": "x",
              "severity": "warning",
              "title": "t",
              "details": "d",
              "file": "src/lib.rs",
              "line": 1,
              "confidence": null,
              "suggestion": null,
              "evidence": ["e1"]
            }
          ]
        }"#;
        let err = parse_envelope(content).expect_err("null confidence should fail");
        assert!(err.to_string().contains("confidence must be a number"));
    }

    #[test]
    fn chunks_prompt_by_budget() {
        let mut diff = String::from(
            "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1,60 @@\n",
        );
        for i in 0..60 {
            diff.push_str(&format!(
                "+let v{} = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";\n",
                i
            ));
        }

        let parsed = parse_unified_diff(&diff).expect("parse ok");
        let chunks = build_prompt_chunks(&parsed, 900, 10);
        assert!(chunks.len() >= 2);
    }

    #[test]
    fn chunks_include_file_headers() {
        let diff = r#"diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -1 +1 @@
+let a = 1;
diff --git a/src/b.rs b/src/b.rs
--- a/src/b.rs
+++ b/src/b.rs
@@ -1 +1 @@
+let b = 2;
"#;
        let parsed = parse_unified_diff(diff).expect("parse ok");
        let chunks = build_prompt_chunks(&parsed, 10000, 2);
        let joined = chunks.join("\n");
        assert!(joined.contains("File: src/a.rs"));
        assert!(joined.contains("File: src/b.rs"));
    }

    #[test]
    fn provider_attempts_include_fallbacks() {
        let cfg = LlmConfig {
            fallback_models: vec!["m1".to_string(), "m2".to_string()],
            fallback_providers: vec![
                "anthropic-api".to_string(),
                "gemini-api:gemini-2.5-pro".to_string(),
            ],
            ..LlmConfig::default()
        };

        let attempts = provider_attempts(&cfg);
        assert!(attempts.len() >= 5);
        assert_eq!(attempts[0].provider, "openai-api");
        assert_eq!(attempts[1].model.as_deref(), Some("m1"));
        assert_eq!(attempts[2].model.as_deref(), Some("m2"));
        assert_eq!(attempts[3].provider, "anthropic-api");
        assert_eq!(attempts[4].provider, "gemini-api");
        assert_eq!(attempts[4].model.as_deref(), Some("gemini-2.5-pro"));
    }

    #[test]
    fn provider_base_url_does_not_leak_to_other_fallback_provider() {
        let cfg = LlmConfig {
            provider: "openai-api".to_string(),
            base_url: "https://gateway.example.com/v1".to_string(),
            ..LlmConfig::default()
        };

        let openai_url = provider_base_url(&cfg, "openai-api");
        let anthropic_url = provider_base_url(&cfg, "anthropic-api");

        assert_eq!(openai_url, "https://gateway.example.com/v1");
        assert_eq!(anthropic_url, "https://api.anthropic.com/v1");
    }

    #[test]
    fn resolves_enabled_agent_runtimes() {
        let cfg = LlmConfig {
            agents: vec![
                LlmAgentConfig {
                    name: "general".to_string(),
                    enabled: true,
                    focus: "correctness".to_string(),
                    prompt_file: None,
                    provider: None,
                    model: None,
                    min_confidence: None,
                    mcp: Vec::new(),
                },
                LlmAgentConfig {
                    name: "off".to_string(),
                    enabled: false,
                    focus: "x".to_string(),
                    prompt_file: None,
                    provider: None,
                    model: None,
                    min_confidence: None,
                    mcp: Vec::new(),
                },
            ],
            ..LlmConfig::default()
        };
        let runtimes = resolve_agent_runtimes(&cfg).expect("agent runtime resolution");
        assert_eq!(runtimes.len(), 1);
        assert_eq!(runtimes[0].name, "general");
    }

    #[test]
    fn candidate_merge_prefers_higher_severity_then_confidence() {
        let mut merged = std::collections::HashMap::new();
        let warning = LlmFinding {
            rule: "r1".to_string(),
            title: "same".to_string(),
            details: "d".to_string(),
            severity: "warning".to_string(),
            file: Some("src/lib.rs".to_string()),
            line: Some(1),
            suggestion: None,
            confidence: Some(0.9),
            evidence: Some(vec!["e".to_string()]),
        };
        let error = LlmFinding {
            severity: "error".to_string(),
            confidence: Some(0.6),
            ..warning.clone()
        };

        merge_agent_candidate(&mut merged, "a", warning);
        merge_agent_candidate(&mut merged, "b", error);
        let findings = render_merged_candidates(merged, 10, true);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].rule.starts_with("llm:b:"));
        assert!(matches!(
            findings[0].severity,
            crate::checks::Severity::Error
        ));
    }

    #[test]
    fn consensus_filter_keeps_only_supported_candidates() {
        let mut merged = std::collections::HashMap::new();
        let finding_a = LlmFinding {
            rule: "r1".to_string(),
            title: "A".to_string(),
            details: "d".to_string(),
            severity: "warning".to_string(),
            file: Some("src/lib.rs".to_string()),
            line: Some(1),
            suggestion: None,
            confidence: Some(0.8),
            evidence: Some(vec!["e".to_string()]),
        };
        let finding_b = LlmFinding {
            title: "B".to_string(),
            ..finding_a.clone()
        };
        merged.insert(
            "k1".to_string(),
            MergedCandidate {
                best: AgentCandidate {
                    agent_name: "general".to_string(),
                    finding: finding_a,
                },
                supporters: ["general".to_string(), "security".to_string()]
                    .into_iter()
                    .collect(),
            },
        );
        merged.insert(
            "k2".to_string(),
            MergedCandidate {
                best: AgentCandidate {
                    agent_name: "general".to_string(),
                    finding: finding_b,
                },
                supporters: ["general".to_string()].into_iter().collect(),
            },
        );

        let filtered = filter_by_consensus_support(merged, 2);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key("k1"));
    }

    #[test]
    fn candidate_key_uses_location_when_present() {
        let finding = LlmFinding {
            rule: "r".to_string(),
            title: "title".to_string(),
            details: "details".to_string(),
            severity: "warning".to_string(),
            file: Some("b/src/lib.rs".to_string()),
            line: Some(3),
            suggestion: None,
            confidence: Some(0.8),
            evidence: Some(vec!["e".to_string()]),
        };
        let key = llm_candidate_key(&finding);
        assert!(key.contains("src/lib.rs:3"));
    }

    #[test]
    fn candidate_beats_uses_confidence_when_severity_equal() {
        let low = LlmFinding {
            rule: "r".to_string(),
            title: "t".to_string(),
            details: "d".to_string(),
            severity: "warning".to_string(),
            file: Some("src/lib.rs".to_string()),
            line: Some(1),
            suggestion: None,
            confidence: Some(0.5),
            evidence: Some(vec!["e".to_string()]),
        };
        let high = LlmFinding {
            confidence: Some(0.9),
            ..low.clone()
        };
        assert!(candidate_beats(&high, &low));
        assert!(!candidate_beats(&low, &high));
    }

    #[test]
    fn pr_mode_drops_findings_outside_changed_lines() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+let x = 1;
"#;
        let parsed = parse_unified_diff(diff).expect("parse ok");
        let changed = build_changed_line_keys(&parsed);

        let finding = LlmFinding {
            rule: "x".to_string(),
            title: "title".to_string(),
            details: "details".to_string(),
            severity: "warning".to_string(),
            file: Some("src/lib.rs".to_string()),
            line: Some(9),
            suggestion: None,
            confidence: Some(0.9),
            evidence: Some(vec!["snippet".to_string()]),
        };

        assert!(!should_keep_llm_finding(
            &LlmConfig::default(),
            ReviewMode::Pr,
            &changed,
            &finding
        ));
    }

    #[test]
    fn confidence_gate_applies_to_llm_findings() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+let x = 1;
"#;
        let parsed = parse_unified_diff(diff).expect("parse ok");
        let changed = build_changed_line_keys(&parsed);
        let cfg = LlmConfig {
            min_confidence: 0.8,
            ..LlmConfig::default()
        };

        let finding = LlmFinding {
            rule: "x".to_string(),
            title: "title".to_string(),
            details: "details".to_string(),
            severity: "warning".to_string(),
            file: Some("src/lib.rs".to_string()),
            line: Some(1),
            suggestion: None,
            confidence: Some(0.4),
            evidence: Some(vec!["snippet".to_string()]),
        };

        assert!(!should_keep_llm_finding(
            &cfg,
            ReviewMode::Scan,
            &changed,
            &finding
        ));
    }

    #[test]
    fn normalizes_diff_paths_for_matching() {
        assert_eq!(normalize_path_for_compare("./src/lib.rs"), "src/lib.rs");
        assert_eq!(normalize_path_for_compare("b/src/lib.rs"), "src/lib.rs");
        assert_eq!(normalize_path_for_compare("a/src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn enables_path_instruction_when_changed_file_matches() {
        let diff = r#"diff --git a/infra/main.tf b/infra/main.tf
--- a/infra/main.tf
+++ b/infra/main.tf
@@ -1 +1 @@
+resource "x" "y" {}
"#;
        let parsed = parse_unified_diff(diff).expect("parse ok");
        let mut review = ReviewConfig::default();
        review.path_instructions.push(PathInstruction {
            name: Some("infra".to_string()),
            paths: vec!["**/*.tf".to_string()],
            instructions: "focus on exposure".to_string(),
        });

        let ctx = build_path_instruction_context(&review, &parsed).expect("context build");
        assert!(ctx.contains("infra"));
        assert!(ctx.contains("focus on exposure"));
    }

    #[test]
    fn builds_system_prompt_with_optional_context_sections() {
        let pack = PromptPack {
            core_system: "core".to_string(),
            mode_pr: "pr mode".to_string(),
            mode_scan: "scan mode".to_string(),
            output_contract: "contract".to_string(),
        };

        let with_context =
            build_system_prompt(&pack, ReviewMode::Pr, "- src/**: focus", "agent: security");
        assert!(with_context.contains("core"));
        assert!(with_context.contains("pr mode"));
        assert!(with_context.contains("Path-specific review instructions"));
        assert!(with_context.contains("Agent-specific review instructions"));
        assert!(with_context.contains("contract"));

        let no_context = build_system_prompt(&pack, ReviewMode::Scan, "", "");
        assert!(!no_context.contains("Path-specific review instructions"));
        assert!(!no_context.contains("Agent-specific review instructions"));
        assert!(no_context.contains("scan mode"));
    }

    #[test]
    fn append_evidence_only_when_non_empty() {
        assert_eq!(append_evidence("d".to_string(), None), "d");
        assert_eq!(append_evidence("d".to_string(), Some(vec![])), "d");
        assert_eq!(
            append_evidence(
                "d".to_string(),
                Some(vec!["e1".to_string(), "e2".to_string()])
            ),
            "d\n\nEvidence: e1; e2"
        );
    }

    #[test]
    fn parse_envelope_fails_when_json_missing() {
        let err =
            parse_envelope("plain output with no json").expect_err("missing json should fail");
        assert!(err.to_string().contains("did not include JSON object"));
    }

    #[test]
    fn resolve_agent_runtimes_returns_default_when_no_agents_enabled() {
        let mut cfg = LlmConfig::default();
        for agent in &mut cfg.agents {
            agent.enabled = false;
        }
        let runtimes = resolve_agent_runtimes(&cfg).expect("runtime resolution");
        assert_eq!(runtimes.len(), 1);
        assert_eq!(runtimes[0].name, "default");
    }

    #[test]
    fn resolve_agent_runtimes_loads_agent_prompt_file_and_overrides_provider() {
        let prompt_file = unique_temp_file("agent-prompt", "md");
        std::fs::write(&prompt_file, "custom agent instructions").expect("write prompt file");

        let cfg = LlmConfig {
            provider: "openai-api".to_string(),
            model: "gpt-5".to_string(),
            agents: vec![LlmAgentConfig {
                name: "security".to_string(),
                enabled: true,
                focus: "security focus".to_string(),
                prompt_file: Some(prompt_file.to_string_lossy().to_string()),
                provider: Some("gemini-api".to_string()),
                model: Some("gemini-2.5-pro".to_string()),
                min_confidence: Some(0.9),
                mcp: Vec::new(),
            }],
            ..LlmConfig::default()
        };

        let runtimes = resolve_agent_runtimes(&cfg).expect("runtime resolution");
        let _ = std::fs::remove_file(&prompt_file);

        assert_eq!(runtimes.len(), 1);
        assert_eq!(runtimes[0].config.provider, "gemini-api");
        assert_eq!(runtimes[0].config.model, "gemini-2.5-pro");
        assert!(
            runtimes[0]
                .instructions
                .contains("custom agent instructions")
        );
        assert!(runtimes[0].instructions.contains("security focus"));
    }

    #[test]
    fn path_instruction_context_rejects_invalid_glob() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+let x = 1;
"#;
        let parsed = parse_unified_diff(diff).expect("parse ok");
        let mut review = ReviewConfig::default();
        review.path_instructions.push(PathInstruction {
            name: Some("bad".to_string()),
            paths: vec!["[".to_string()],
            instructions: "x".to_string(),
        });

        let err = build_path_instruction_context(&review, &parsed)
            .expect_err("invalid glob should return an error");
        assert!(
            err.to_string()
                .contains("invalid reviews.path_instructions glob")
        );
    }

    #[test]
    fn prompt_chunk_builder_handles_small_budget_and_marks_truncation() {
        let mut diff = String::from(
            "diff --git a/src/lib.rs b/src/lib.rs\n--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1,40 @@\n",
        );
        for i in 0..40 {
            diff.push_str(&format!("+let v{} = \"{}\";\n", i, "a".repeat(40)));
        }
        let parsed = parse_unified_diff(&diff).expect("parse ok");

        assert!(build_prompt_chunks(&parsed, 400, 5).is_empty());
        assert!(build_prompt_chunks(&parsed, 900, 0).is_empty());

        let chunks = build_prompt_chunks(&parsed, 600, 1);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].contains("truncated to fit prompt budget"));
    }

    #[test]
    fn provider_api_key_resolves_active_and_missing_env() {
        let mut cfg = LlmConfig {
            provider: "openai-api".to_string(),
            api_key_env: "PATH".to_string(),
            ..LlmConfig::default()
        };
        let key = provider_api_key(&cfg, "openai-api").expect("PATH should exist");
        assert!(!key.is_empty());

        cfg.api_key_env = "__FANTASTIC_PR_MISSING_ENV__".to_string();
        let err = provider_api_key(&cfg, "openai-api").expect_err("missing env should fail");
        assert!(err.to_string().contains("required for provider"));
    }

    #[test]
    fn run_provider_attempt_rejects_unsupported_provider() {
        let cfg = LlmConfig::default();
        let prompts = PromptPack {
            core_system: "core".to_string(),
            mode_pr: "pr".to_string(),
            mode_scan: "scan".to_string(),
            output_contract: "contract".to_string(),
        };
        let attempt = ProviderAttempt {
            provider: "not-real-provider".to_string(),
            model: Some("x".to_string()),
        };

        let err = run_provider_attempt(&cfg, &prompts, ReviewMode::Scan, "chunk", &attempt, "", "")
            .expect_err("unsupported provider should fail");
        assert!(err.to_string().contains("unsupported llm.provider"));
    }

    #[test]
    fn writes_failed_attempt_artifacts_files() {
        let dir = unique_temp_file("artifact-dir", "tmp");
        let debug = DebugConfig {
            upload_failed_provider_artifacts: true,
            artifact_dir: dir.to_string_lossy().to_string(),
        };
        let prompts = PromptPack {
            core_system: "core".to_string(),
            mode_pr: "pr".to_string(),
            mode_scan: "scan".to_string(),
            output_contract: "contract".to_string(),
        };
        let attempt = ProviderAttempt {
            provider: "openai-api".to_string(),
            model: Some("gpt".to_string()),
        };

        write_failed_attempt_artifacts(
            &debug,
            &FailedAttemptArtifact {
                attempt_index: 3,
                attempt: &attempt,
                chunk: "chunk",
                prompts: &prompts,
                mode: ReviewMode::Pr,
                path_instruction_context: "path ctx",
                agent_instruction_context: "agent ctx",
                error: "boom",
            },
        )
        .expect("artifact write should succeed");

        let entries = std::fs::read_dir(&dir)
            .expect("artifact dir should exist")
            .count();
        assert!(entries >= 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_envelope_rejects_invalid_field_shapes() {
        let bad_severity = r#"{
          "findings": [
            {
              "rule": "x",
              "severity": "fatal",
              "title": "t",
              "details": "d",
              "file": "src/lib.rs",
              "line": 1,
              "confidence": 0.5,
              "suggestion": null,
              "evidence": ["e1"]
            }
          ]
        }"#;
        assert!(parse_envelope(bad_severity).is_err());

        let empty_evidence = r#"{
          "findings": [
            {
              "rule": "x",
              "severity": "warning",
              "title": "t",
              "details": "d",
              "file": "src/lib.rs",
              "line": 1,
              "confidence": 0.5,
              "suggestion": null,
              "evidence": []
            }
          ]
        }"#;
        let err = parse_envelope(empty_evidence).expect_err("empty evidence should fail");
        assert!(err.to_string().contains("must contain at least one entry"));
    }

    #[test]
    fn parse_envelope_rejects_confidence_and_key_mismatch() {
        let out_of_range_confidence = r#"{
          "findings": [
            {
              "rule": "x",
              "severity": "warning",
              "title": "t",
              "details": "d",
              "file": "src/lib.rs",
              "line": 1,
              "confidence": 1.5,
              "suggestion": null,
              "evidence": ["e1"]
            }
          ]
        }"#;
        let err =
            parse_envelope(out_of_range_confidence).expect_err("confidence range should fail");
        assert!(err.to_string().contains("between 0.0 and 1.0"));

        let key_mismatch = r#"{
          "findings": [
            {
              "rule": "x",
              "severity": "warning",
              "title": "t",
              "details": "d",
              "file": "src/lib.rs",
              "line": 1,
              "confidence": 0.5,
              "suggestion": null,
              "evidence": ["e1"],
              "extra": true
            }
          ]
        }"#;
        let err = parse_envelope(key_mismatch).expect_err("extra finding key should fail");
        assert!(err.to_string().contains("keys mismatch"));
    }

    #[test]
    fn openai_client_complete_handles_success_and_http_failure() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _no_proxy = EnvGuard::set("NO_PROXY", "*");
        let _http_proxy = EnvGuard::set("HTTP_PROXY", "");
        let _https_proxy = EnvGuard::set("HTTPS_PROXY", "");
        let mut server = Server::new();

        let cfg = LlmConfig {
            provider: "openai-api".to_string(),
            base_url: server.url(),
            api_key_env: "PATH".to_string(),
            provider_timeout_secs: 2,
            ..LlmConfig::default()
        };

        let ok_mock = server
            .mock("POST", "/chat/completions")
            .expect(1)
            .with_status(200)
            .with_body(r#"{"choices":[{"message":{"content":"ok-content"}}]}"#)
            .create();

        let client = OpenAiApiClient::new(&cfg, "openai-api").expect("openai client");
        let out = client
            .complete(&sample_request())
            .expect("openai completion");
        ok_mock.assert();
        assert_eq!(out, "ok-content");

        let _err_mock = server
            .mock("POST", "/chat/completions")
            .expect(1)
            .match_body(Matcher::Regex("\"model\":\"model-x\"".to_string()))
            .with_status(500)
            .with_body("boom")
            .create();

        let err = client
            .complete(&sample_request())
            .expect_err("openai http error should fail");
        assert!(
            err.to_string()
                .contains("OpenAI-compatible API request failed")
        );
    }

    #[test]
    fn anthropic_client_complete_handles_success_and_empty_text() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _no_proxy = EnvGuard::set("NO_PROXY", "*");
        let _http_proxy = EnvGuard::set("HTTP_PROXY", "");
        let _https_proxy = EnvGuard::set("HTTPS_PROXY", "");
        let mut server = Server::new();

        let cfg = LlmConfig {
            provider: "anthropic-api".to_string(),
            base_url: server.url(),
            api_key_env: "PATH".to_string(),
            provider_timeout_secs: 2,
            ..LlmConfig::default()
        };

        let success = server
            .mock("POST", "/messages")
            .expect(1)
            .with_status(200)
            .with_body(r#"{"content":[{"type":"text","text":"anthropic-text"}]}"#)
            .create();

        let client = AnthropicApiClient::new(&cfg, "anthropic-api").expect("anthropic client");
        let out = client
            .complete(&sample_request())
            .expect("anthropic completion");
        success.assert();
        assert_eq!(out, "anthropic-text");

        let _empty = server
            .mock("POST", "/messages")
            .expect(1)
            .with_status(200)
            .with_body(r#"{"content":[{"type":"text","text":""}]}"#)
            .create();
        let err = client
            .complete(&sample_request())
            .expect_err("empty anthropic text should fail");
        assert!(err.to_string().contains("returned no text content"));
    }

    #[test]
    fn gemini_client_complete_handles_success_and_failure() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _no_proxy = EnvGuard::set("NO_PROXY", "*");
        let _http_proxy = EnvGuard::set("HTTP_PROXY", "");
        let _https_proxy = EnvGuard::set("HTTPS_PROXY", "");
        let mut server = Server::new();

        let cfg = LlmConfig {
            provider: "gemini-api".to_string(),
            base_url: server.url(),
            api_key_env: "PATH".to_string(),
            provider_timeout_secs: 2,
            ..LlmConfig::default()
        };

        let success = server
            .mock("POST", "/models/model-x:generateContent")
            .match_query(mockito::Matcher::Any)
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"candidates":[{"content":{"parts":[{"text":"g-part-1"},{"text":"g-part-2"}]}}]}"#,
            )
            .create();

        let client = GeminiApiClient::new(&cfg, "gemini-api").expect("gemini client");
        let out = client
            .complete(&sample_request())
            .expect("gemini completion");
        success.assert();
        assert_eq!(out, "g-part-1\ng-part-2");

        let _fail = server
            .mock("POST", "/models/model-x:generateContent")
            .match_query(mockito::Matcher::Any)
            .expect(1)
            .with_status(500)
            .with_body("bad")
            .create();
        let err = client
            .complete(&sample_request())
            .expect_err("gemini http error should fail");
        assert!(err.to_string().contains("Gemini API request failed"));
    }

    #[test]
    fn run_llm_review_supports_judge_workflow_strategy() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _no_proxy = EnvGuard::set("NO_PROXY", "*");
        let _http_proxy = EnvGuard::set("HTTP_PROXY", "");
        let _https_proxy = EnvGuard::set("HTTPS_PROXY", "");
        let mut server = Server::new();

        let (dir, mut cfg) = write_prompt_files("judge-workflow");
        cfg.enabled = true;
        cfg.provider = "openai-api".to_string();
        cfg.base_url = server.url();
        cfg.api_key_env = "PATH".to_string();
        cfg.provider_timeout_secs = 2;
        cfg.max_prompt_chars = 10_000;
        cfg.max_chunks = 1;
        cfg.agents.clear();
        cfg.workflow_strategy = LlmWorkflowStrategy::Judge;
        let judge_prompt = dir.join("judge.txt");
        std::fs::write(&judge_prompt, "adjudicate findings").expect("write judge prompt");
        cfg.judge_prompt_file = judge_prompt.to_string_lossy().to_string();
        let _initial = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex("File: src/lib.rs".to_string()))
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"choices":[{"message":{"content":"{\"findings\":[{\"rule\":\"r1\",\"severity\":\"warning\",\"title\":\"keep\",\"details\":\"d1\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e1\"]},{\"rule\":\"r2\",\"severity\":\"warning\",\"title\":\"drop\",\"details\":\"d2\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e2\"]}]}"}}]}"#,
            )
            .create();
        let _judge = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex("final review adjudicator".to_string()))
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"choices":[{"message":{"content":"{\"findings\":[{\"rule\":\"r1\",\"severity\":\"warning\",\"title\":\"keep\",\"details\":\"d1\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e1\"]}]}"}}]}"#,
            )
            .create();

        let diff = parse_unified_diff(
            r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+pub fn a() {}
"#,
        )
        .expect("parse diff");

        let findings = run_llm_review(
            &cfg,
            &ReviewConfig::default(),
            &DebugConfig::default(),
            &diff,
            ReviewMode::Pr,
        )
        .expect("judge workflow should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "llm:r1");
        assert_eq!(findings[0].title, "keep");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_llm_review_supports_debate_workflow_strategy() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _no_proxy = EnvGuard::set("NO_PROXY", "*");
        let _http_proxy = EnvGuard::set("HTTP_PROXY", "");
        let _https_proxy = EnvGuard::set("HTTPS_PROXY", "");
        let mut server = Server::new();

        let (dir, mut cfg) = write_prompt_files("debate-workflow");
        cfg.enabled = true;
        cfg.provider = "openai-api".to_string();
        cfg.base_url = server.url();
        cfg.api_key_env = "PATH".to_string();
        cfg.provider_timeout_secs = 2;
        cfg.max_prompt_chars = 10_000;
        cfg.max_chunks = 1;
        cfg.agents.clear();
        cfg.workflow_strategy = LlmWorkflowStrategy::Debate;
        let judge_prompt = dir.join("judge.txt");
        let debate_prompt = dir.join("debate.txt");
        std::fs::write(&judge_prompt, "judge phase prompt").expect("write judge prompt");
        std::fs::write(&debate_prompt, "debate phase prompt").expect("write debate prompt");
        cfg.judge_prompt_file = judge_prompt.to_string_lossy().to_string();
        cfg.debate_prompt_file = debate_prompt.to_string_lossy().to_string();
        let _initial = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex("File: src/lib.rs".to_string()))
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"choices":[{"message":{"content":"{\"findings\":[{\"rule\":\"r1\",\"severity\":\"warning\",\"title\":\"proposal-pick\",\"details\":\"d1\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e1\"]},{\"rule\":\"r2\",\"severity\":\"warning\",\"title\":\"challenger-pick\",\"details\":\"d2\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e2\"]}]}"}}]}"#,
            )
            .create();
        let _judge = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex("final review adjudicator".to_string()))
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"choices":[{"message":{"content":"{\"findings\":[{\"rule\":\"r1\",\"severity\":\"warning\",\"title\":\"proposal-pick\",\"details\":\"d1\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e1\"]}]}"}}]}"#,
            )
            .create();
        let _debate = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex(
                "structured debate adjudication pass".to_string(),
            ))
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"choices":[{"message":{"content":"{\"findings\":[{\"rule\":\"r2\",\"severity\":\"warning\",\"title\":\"challenger-pick\",\"details\":\"d2\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e2\"]}]}"}}]}"#,
            )
            .create();

        let diff = parse_unified_diff(
            r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+pub fn a() {}
"#,
        )
        .expect("parse diff");

        let findings = run_llm_review(
            &cfg,
            &ReviewConfig::default(),
            &DebugConfig::default(),
            &diff,
            ReviewMode::Pr,
        )
        .expect("debate workflow should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "llm:r2");
        assert_eq!(findings[0].title, "challenger-pick");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_llm_review_supports_critique_revise_workflow_strategy() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _no_proxy = EnvGuard::set("NO_PROXY", "*");
        let _http_proxy = EnvGuard::set("HTTP_PROXY", "");
        let _https_proxy = EnvGuard::set("HTTPS_PROXY", "");
        let mut server = Server::new();

        let (dir, mut cfg) = write_prompt_files("critique-revise-workflow");
        cfg.enabled = true;
        cfg.provider = "openai-api".to_string();
        cfg.base_url = server.url();
        cfg.api_key_env = "PATH".to_string();
        cfg.provider_timeout_secs = 2;
        cfg.max_prompt_chars = 10_000;
        cfg.max_chunks = 1;
        cfg.agents.clear();
        cfg.workflow_strategy = LlmWorkflowStrategy::CritiqueRevise;
        let judge_prompt = dir.join("judge.txt");
        let revise_prompt = dir.join("critique_revise.txt");
        std::fs::write(&judge_prompt, "judge phase prompt").expect("write judge prompt");
        std::fs::write(&revise_prompt, "revise phase prompt").expect("write revise prompt");
        cfg.judge_prompt_file = judge_prompt.to_string_lossy().to_string();
        cfg.critique_revise_prompt_file = revise_prompt.to_string_lossy().to_string();
        let _initial = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex("File: src/lib.rs".to_string()))
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"choices":[{"message":{"content":"{\"findings\":[{\"rule\":\"r1\",\"severity\":\"warning\",\"title\":\"draft-pick\",\"details\":\"d1\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e1\"]},{\"rule\":\"r2\",\"severity\":\"warning\",\"title\":\"revised-pick\",\"details\":\"d2\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e2\"]}]}"}}]}"#,
            )
            .create();
        let _judge = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex("final review adjudicator".to_string()))
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"choices":[{"message":{"content":"{\"findings\":[{\"rule\":\"r1\",\"severity\":\"warning\",\"title\":\"draft-pick\",\"details\":\"d1\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e1\"]}]}"}}]}"#,
            )
            .create();
        let _critique = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex(
                "critique-and-revise adjudication pass".to_string(),
            ))
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"choices":[{"message":{"content":"{\"findings\":[{\"rule\":\"r2\",\"severity\":\"warning\",\"title\":\"revised-pick\",\"details\":\"d2\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e2\"]}]}"}}]}"#,
            )
            .create();

        let diff = parse_unified_diff(
            r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+pub fn a() {}
"#,
        )
        .expect("parse diff");

        let findings = run_llm_review(
            &cfg,
            &ReviewConfig::default(),
            &DebugConfig::default(),
            &diff,
            ReviewMode::Pr,
        )
        .expect("critique-revise workflow should succeed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "llm:r2");
        assert_eq!(findings[0].title, "revised-pick");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn debate_second_pass_failure_preserves_first_pass_even_when_empty() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _no_proxy = EnvGuard::set("NO_PROXY", "*");
        let _http_proxy = EnvGuard::set("HTTP_PROXY", "");
        let _https_proxy = EnvGuard::set("HTTPS_PROXY", "");
        let mut server = Server::new();

        let (dir, mut cfg) = write_prompt_files("debate-empty-first-pass");
        cfg.enabled = true;
        cfg.provider = "openai-api".to_string();
        cfg.base_url = server.url();
        cfg.api_key_env = "PATH".to_string();
        cfg.provider_timeout_secs = 2;
        cfg.max_prompt_chars = 10_000;
        cfg.max_chunks = 1;
        cfg.agents.clear();
        cfg.workflow_strategy = LlmWorkflowStrategy::Debate;
        let judge_prompt = dir.join("judge.txt");
        let debate_prompt = dir.join("debate.txt");
        std::fs::write(&judge_prompt, "judge phase prompt").expect("write judge prompt");
        std::fs::write(&debate_prompt, "debate phase prompt").expect("write debate prompt");
        cfg.judge_prompt_file = judge_prompt.to_string_lossy().to_string();
        cfg.debate_prompt_file = debate_prompt.to_string_lossy().to_string();
        let _initial = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex("File: src/lib.rs".to_string()))
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"choices":[{"message":{"content":"{\"findings\":[{\"rule\":\"r1\",\"severity\":\"warning\",\"title\":\"base-1\",\"details\":\"d1\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e1\"]},{\"rule\":\"r2\",\"severity\":\"warning\",\"title\":\"base-2\",\"details\":\"d2\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e2\"]}]}"}}]}"#,
            )
            .create();
        let _judge = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex("final review adjudicator".to_string()))
            .expect(1)
            .with_status(200)
            .with_body(r#"{"choices":[{"message":{"content":"{\"findings\":[]}"}}]}"#)
            .create();
        let _debate = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex(
                "structured debate adjudication pass".to_string(),
            ))
            .expect(1)
            .with_status(200)
            .with_body(r#"{"choices":[{"message":{"content":"not-json"}}]}"#)
            .create();

        let diff = parse_unified_diff(
            r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+pub fn a() {}
"#,
        )
        .expect("parse diff");

        let findings = run_llm_review(
            &cfg,
            &ReviewConfig::default(),
            &DebugConfig::default(),
            &diff,
            ReviewMode::Pr,
        )
        .expect("debate workflow should preserve first-pass output");
        assert!(findings.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adjudication_prompt_is_bounded_by_llm_max_prompt_chars() {
        let cfg = LlmConfig {
            max_prompt_chars: 1200,
            ..LlmConfig::default()
        };
        let ranked = (0..12usize)
            .map(|idx| {
                let finding = LlmFinding {
                    rule: format!("r{idx}"),
                    title: format!("t{idx}"),
                    details: "x".repeat(240),
                    severity: "warning".to_string(),
                    file: Some("src/lib.rs".to_string()),
                    line: Some(1),
                    suggestion: None,
                    confidence: Some(0.9),
                    evidence: Some(vec!["y".repeat(180)]),
                };
                (
                    format!("k{idx}"),
                    MergedCandidate {
                        best: AgentCandidate {
                            agent_name: "general".to_string(),
                            finding,
                        },
                        supporters: ["general".to_string()].into_iter().collect(),
                    },
                )
            })
            .collect::<Vec<_>>();

        let (prompt, bounded) = build_judge_user_prompt(&cfg, &ranked);
        assert!(prompt.len() <= cfg.max_prompt_chars);
        assert!(bounded.len() < ranked.len());
    }

    #[test]
    fn run_llm_review_and_probe_provider_cover_success_and_failure_modes() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _no_proxy = EnvGuard::set("NO_PROXY", "*");
        let _http_proxy = EnvGuard::set("HTTP_PROXY", "");
        let _https_proxy = EnvGuard::set("HTTPS_PROXY", "");
        let mut server = Server::new();

        let (dir, mut cfg) = write_prompt_files("run-llm-review");
        cfg.enabled = true;
        cfg.provider = "openai-api".to_string();
        cfg.base_url = server.url();
        cfg.api_key_env = "PATH".to_string();
        cfg.provider_timeout_secs = 2;
        cfg.max_prompt_chars = 10_000;
        cfg.max_chunks = 1;
        cfg.agents.clear();
        let _review_ok = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex("File: src/lib.rs".to_string()))
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"choices":[{"message":{"content":"{\"findings\":[{\"rule\":\"r\",\"severity\":\"warning\",\"title\":\"t\",\"details\":\"d\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e\"]}]}"}}]}"#,
            )
            .create();
        let _probe_ok = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex(
                "Probe request: return a valid JSON envelope".to_string(),
            ))
            .expect(1)
            .with_status(200)
            .with_body(r#"{"choices":[{"message":{"content":"{\"findings\":[]}"}}]}"#)
            .create();
        let _probe_bad = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex(
                "Probe request: return a valid JSON envelope".to_string(),
            ))
            .expect(1)
            .with_status(200)
            .with_body(r#"{"choices":[{"message":{"content":"not-json"}}]}"#)
            .create();
        let _partial_ok = server
            .mock("POST", "/chat/completions")
            .match_body(Matcher::Regex("File: src/lib.rs".to_string()))
            .expect(1)
            .with_status(200)
            .with_body(
                r#"{"choices":[{"message":{"content":"{\"findings\":[{\"rule\":\"bad\",\"severity\":\"warning\",\"title\":\"x\",\"details\":\"y\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"e\"]}]}"}}]}"#,
            )
            .create();

        let diff = parse_unified_diff(
            r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1,2 @@
+pub fn a() {}
"#,
        )
        .expect("parse diff");

        let findings = run_llm_review(
            &cfg,
            &ReviewConfig::default(),
            &DebugConfig::default(),
            &diff,
            ReviewMode::Pr,
        )
        .expect("llm review success");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "llm:r");

        probe_provider(&cfg).expect("probe should succeed");

        let err = probe_provider(&cfg).expect_err("invalid probe response should fail");
        assert!(
            err.to_string()
                .contains("provider probe output was not valid findings JSON")
        );
        cfg.agents = vec![
            LlmAgentConfig {
                name: "bad-agent".to_string(),
                enabled: true,
                focus: "x".to_string(),
                prompt_file: None,
                provider: Some("not-supported".to_string()),
                model: None,
                min_confidence: None,
                mcp: Vec::new(),
            },
            LlmAgentConfig {
                name: "good-agent".to_string(),
                enabled: true,
                focus: "x".to_string(),
                prompt_file: None,
                provider: Some("openai-api".to_string()),
                model: None,
                min_confidence: None,
                mcp: Vec::new(),
            },
        ];

        let partial = run_llm_review(
            &cfg,
            &ReviewConfig::default(),
            &DebugConfig::default(),
            &diff,
            ReviewMode::Pr,
        )
        .expect("partial failure should still return findings");
        assert!(!partial.is_empty());

        cfg.agents = vec![LlmAgentConfig {
            name: "only-bad".to_string(),
            enabled: true,
            focus: "x".to_string(),
            prompt_file: None,
            provider: Some("not-supported".to_string()),
            model: None,
            min_confidence: None,
            mcp: Vec::new(),
        }];
        let err = run_llm_review(
            &cfg,
            &ReviewConfig::default(),
            &DebugConfig::default(),
            &diff,
            ReviewMode::Pr,
        )
        .expect_err("all attempts failure should bubble");
        assert!(
            err.to_string()
                .contains("all llm provider attempts failed across chunks/agents")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
