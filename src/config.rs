use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use globset::Glob;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const DEFAULT_CONFIG_PATH: &str = ".fantastic-pr.yaml";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub profile: String,
    pub inheritance: bool,
    pub extends: Option<String>,
    pub max_reported_findings: usize,
    pub max_examples_per_rule: usize,
    pub max_inline_comments: usize,
    pub large_pr_added_lines_threshold: usize,
    pub missing_tests_added_lines_threshold: usize,
    pub checks: CheckToggles,
    pub pre_merge_checks: PreMergeChecksConfig,
    pub llm: LlmConfig,
    pub reviews: ReviewConfig,
    pub tools: ToolRegistryConfig,
    pub filters: FilterConfig,
    pub baseline: BaselineConfig,
    pub scope: ScopeConfig,
    pub debug: DebugConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct CheckToggles {
    pub todo_comments: bool,
    pub debug_statements: bool,
    pub secret_patterns: bool,
    pub large_pr: bool,
    pub missing_tests: bool,
    pub unsafe_rust: bool,
    pub unwrap_usage: bool,
    pub iac_misconfig: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct LlmConfig {
    pub enabled: bool,
    pub provider: String,

    pub base_url: String,
    pub model: String,
    pub api_key_env: String,

    pub cli_command: String,
    pub cli_args: Vec<String>,

    pub fallback_models: Vec<String>,
    pub fallback_providers: Vec<String>,
    pub agents: Vec<LlmAgentConfig>,

    pub prompt_core_file: String,
    pub prompt_pr_file: String,
    pub prompt_scan_file: String,
    pub prompt_output_contract_file: String,

    pub max_prompt_chars: usize,
    pub max_findings: usize,
    pub max_chunks: usize,
    pub provider_timeout_secs: u64,
    pub min_confidence: f64,
    pub pr_changed_lines_only: bool,
    pub workflow_strategy: LlmWorkflowStrategy,
    pub consensus_min_support: usize,
    pub judge_model: Option<String>,
    pub judge_prompt_file: String,
    pub judge_max_candidates: usize,
    pub debate_prompt_file: String,
    pub critique_revise_prompt_file: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LlmWorkflowStrategy {
    Merge,
    Consensus,
    Judge,
    JudgeConsensus,
    Debate,
    CritiqueRevise,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct LlmAgentConfig {
    pub name: String,
    pub enabled: bool,
    pub focus: String,
    pub prompt_file: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub min_confidence: Option<f64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ReviewConfig {
    pub auto_review: AutoReviewConfig,
    pub path_instructions: Vec<PathInstruction>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct AutoReviewConfig {
    pub enabled: bool,
    pub include_drafts: bool,
    pub labels: Vec<String>,
    pub exclude_labels: Vec<String>,
    pub title_keywords: Vec<String>,
    pub base_branches: Vec<String>,
    pub ignore_usernames: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct PathInstruction {
    pub name: Option<String>,
    pub paths: Vec<String>,
    pub instructions: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckMode {
    Off,
    Warning,
    Error,
    Inherit,
}

impl Default for CheckMode {
    fn default() -> Self {
        Self::Inherit
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct PreMergeChecksConfig {
    pub todo_comments: CheckMode,
    pub debug_statements: CheckMode,
    pub secret_patterns: CheckMode,
    pub large_pr: CheckMode,
    pub missing_tests: CheckMode,
    pub unsafe_rust: CheckMode,
    pub unwrap_usage: CheckMode,
    pub iac_misconfig: CheckMode,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ToolInputConfig {
    pub enabled: bool,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ToolRegistryConfig {
    pub sarif: ToolInputConfig,
    pub eslint: ToolInputConfig,
    pub semgrep: ToolInputConfig,
    pub checkov: ToolInputConfig,
    pub gitleaks: ToolInputConfig,
    pub clippy: ToolInputConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct FilterConfig {
    pub include_globs: Vec<String>,
    pub exclude_globs: Vec<String>,
    pub ignore_file: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct BaselineConfig {
    pub enabled: bool,
    pub file: String,
    pub update: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ScopeConfig {
    pub initial_pr_scope: String,
    pub sync_scope: String,
    pub manual_scope: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct DebugConfig {
    pub upload_failed_provider_artifacts: bool,
    pub artifact_dir: String,
}

impl Default for CheckToggles {
    fn default() -> Self {
        Self {
            todo_comments: true,
            debug_statements: true,
            secret_patterns: true,
            large_pr: true,
            missing_tests: true,
            unsafe_rust: true,
            unwrap_usage: true,
            iac_misconfig: false,
        }
    }
}

impl Default for PreMergeChecksConfig {
    fn default() -> Self {
        Self {
            todo_comments: CheckMode::Inherit,
            debug_statements: CheckMode::Inherit,
            secret_patterns: CheckMode::Inherit,
            large_pr: CheckMode::Inherit,
            missing_tests: CheckMode::Inherit,
            unsafe_rust: CheckMode::Inherit,
            unwrap_usage: CheckMode::Inherit,
            iac_misconfig: CheckMode::Inherit,
        }
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "openai-api".to_string(),

            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4.1-mini".to_string(),
            api_key_env: "OPENAI_API_KEY".to_string(),

            cli_command: String::new(),
            cli_args: Vec::new(),

            fallback_models: Vec::new(),
            fallback_providers: Vec::new(),
            agents: vec![
                LlmAgentConfig {
                    name: "general".to_string(),
                    enabled: true,
                    focus: "Find concrete correctness, reliability, and regression risks in changed code."
                        .to_string(),
                    prompt_file: Some("prompts/agents/general.txt".to_string()),
                    provider: None,
                    model: None,
                    min_confidence: None,
                },
                LlmAgentConfig {
                    name: "security".to_string(),
                    enabled: true,
                    focus:
                        "Focus on secrets, auth boundaries, injection, data exposure, and insecure defaults."
                            .to_string(),
                    prompt_file: Some("prompts/agents/security.txt".to_string()),
                    provider: None,
                    model: None,
                    min_confidence: Some(0.75),
                },
                LlmAgentConfig {
                    name: "maintainability".to_string(),
                    enabled: true,
                    focus:
                        "Focus on testability, complexity risks, brittle abstractions, and long-term maintenance hazards."
                            .to_string(),
                    prompt_file: Some("prompts/agents/maintainability.txt".to_string()),
                    provider: None,
                    model: None,
                    min_confidence: None,
                },
            ],

            prompt_core_file: "prompts/core_system.txt".to_string(),
            prompt_pr_file: "prompts/mode_pr.txt".to_string(),
            prompt_scan_file: "prompts/mode_scan.txt".to_string(),
            prompt_output_contract_file: "prompts/output_contract.json".to_string(),

            max_prompt_chars: 24_000,
            max_findings: 20,
            max_chunks: 4,
            provider_timeout_secs: 90,
            min_confidence: 0.65,
            pr_changed_lines_only: true,
            workflow_strategy: LlmWorkflowStrategy::Merge,
            consensus_min_support: 1,
            judge_model: None,
            judge_prompt_file: "prompts/workflows/judge.txt".to_string(),
            judge_max_candidates: 40,
            debate_prompt_file: "prompts/workflows/debate.txt".to_string(),
            critique_revise_prompt_file: "prompts/workflows/critique_revise.txt".to_string(),
        }
    }
}

impl Default for LlmWorkflowStrategy {
    fn default() -> Self {
        Self::Merge
    }
}

impl Default for LlmAgentConfig {
    fn default() -> Self {
        Self {
            name: "general".to_string(),
            enabled: true,
            focus: String::new(),
            prompt_file: None,
            provider: None,
            model: None,
            min_confidence: None,
        }
    }
}

impl Default for AutoReviewConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            include_drafts: false,
            labels: Vec::new(),
            exclude_labels: Vec::new(),
            title_keywords: Vec::new(),
            base_branches: Vec::new(),
            ignore_usernames: Vec::new(),
        }
    }
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            include_globs: Vec::new(),
            exclude_globs: Vec::new(),
            ignore_file: ".fantastic-prignore".to_string(),
        }
    }
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            file: ".fantastic-pr-baseline.json".to_string(),
            update: false,
        }
    }
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            initial_pr_scope: "expanded".to_string(),
            sync_scope: "diff".to_string(),
            manual_scope: "expanded".to_string(),
        }
    }
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            upload_failed_provider_artifacts: false,
            artifact_dir: "fantastic-pr-debug".to_string(),
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            inheritance: false,
            extends: None,
            max_reported_findings: 80,
            max_examples_per_rule: 20,
            max_inline_comments: 25,
            large_pr_added_lines_threshold: 500,
            missing_tests_added_lines_threshold: 120,
            checks: CheckToggles::default(),
            pre_merge_checks: PreMergeChecksConfig::default(),
            llm: LlmConfig::default(),
            reviews: ReviewConfig::default(),
            tools: ToolRegistryConfig::default(),
            filters: FilterConfig::default(),
            baseline: BaselineConfig::default(),
            scope: ScopeConfig::default(),
            debug: DebugConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn load_with_overrides(
        config_path: &Path,
        cli_overrides: &[String],
    ) -> anyhow::Result<Self> {
        let mut cfg = if config_path.exists() {
            load_file(config_path)?
        } else {
            Self::default()
        };

        let mut env_overrides = env::vars()
            .filter_map(|(k, v)| {
                k.strip_prefix("FANTASTIC_PR_CFG_").map(|suffix| {
                    let key = suffix.to_lowercase().replace("__", ".");
                    (key, v)
                })
            })
            .collect::<Vec<_>>();
        env_overrides.sort_by(|a, b| a.0.cmp(&b.0));

        if let Some((_, value)) = env_overrides.iter().rev().find(|(key, _)| key == "profile") {
            apply_override(&mut cfg, "profile", value)
                .context("invalid env override FANTASTIC_PR_CFG_PROFILE")?;
            apply_profile_override_defaults(&mut cfg);
        }

        for (key, value) in env_overrides
            .into_iter()
            .filter(|(key, _)| key != "profile")
        {
            apply_override(&mut cfg, &key, &value).with_context(|| {
                format!(
                    "invalid env override FANTASTIC_PR_CFG_{}",
                    key.replace('.', "__").to_uppercase()
                )
            })?;
        }

        let mut parsed_cli_overrides = Vec::new();
        for raw in cli_overrides {
            let (key, value) = raw
                .split_once('=')
                .with_context(|| format!("invalid --set override '{raw}', expected key=value"))?;

            parsed_cli_overrides.push((
                raw.as_str(),
                key.trim().to_string(),
                value.trim().to_string(),
            ));
        }

        if let Some((raw, _, value)) = parsed_cli_overrides
            .iter()
            .rev()
            .find(|(_, key, _)| key == "profile")
        {
            apply_override(&mut cfg, "profile", value)
                .with_context(|| format!("invalid --set override '{raw}'"))?;
            apply_profile_override_defaults(&mut cfg);
        }

        for (raw, key, value) in parsed_cli_overrides
            .into_iter()
            .filter(|(_, key, _)| key != "profile")
        {
            apply_override(&mut cfg, &key, &value)
                .with_context(|| format!("invalid --set override '{raw}'"))?;
        }

        cfg.normalize();
        cfg.validate_semantics()?;
        Ok(cfg)
    }

    pub fn load_from_file(path: &Path) -> anyhow::Result<Self> {
        let mut cfg = load_file(path)?;
        cfg.normalize();
        cfg.validate_semantics()?;
        Ok(cfg)
    }

    pub fn write_yaml(&self, path: &Path) -> anyhow::Result<()> {
        let mut out = self.clone();
        out.normalize();
        let text = serde_yaml::to_string(&out).context("failed to render YAML config")?;
        fs::write(path, text)
            .with_context(|| format!("failed to write YAML config {}", path.display()))
    }

    pub fn configured_ingest_paths(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for input in [
            &self.tools.sarif,
            &self.tools.eslint,
            &self.tools.semgrep,
            &self.tools.checkov,
            &self.tools.gitleaks,
            &self.tools.clippy,
        ] {
            if !input.enabled {
                continue;
            }
            for path in &input.paths {
                out.push(PathBuf::from(path));
            }
        }
        out.sort();
        out.dedup();
        out
    }

    fn normalize(&mut self) {
        normalize_pre_merge_modes(self);
    }

    fn validate_semantics(&self) -> anyhow::Result<()> {
        if self.max_reported_findings < 1 {
            bail!("max_reported_findings must be >= 1");
        }
        if self.max_examples_per_rule < 1 {
            bail!("max_examples_per_rule must be >= 1");
        }
        if self.max_inline_comments < 1 {
            bail!("max_inline_comments must be >= 1");
        }
        if self.large_pr_added_lines_threshold < 1 {
            bail!("large_pr_added_lines_threshold must be >= 1");
        }
        if self.missing_tests_added_lines_threshold < 1 {
            bail!("missing_tests_added_lines_threshold must be >= 1");
        }
        if self.llm.max_prompt_chars < 512 {
            bail!("llm.max_prompt_chars must be >= 512");
        }
        if self.llm.max_findings < 1 {
            bail!("llm.max_findings must be >= 1");
        }
        if self.llm.max_chunks < 1 {
            bail!("llm.max_chunks must be >= 1");
        }
        if self.llm.provider_timeout_secs < 1 {
            bail!("llm.provider_timeout_secs must be >= 1");
        }
        if !(0.0..=1.0).contains(&self.llm.min_confidence) {
            bail!("llm.min_confidence must be between 0.0 and 1.0");
        }
        if self.llm.consensus_min_support < 1 {
            bail!("llm.consensus_min_support must be >= 1");
        }
        if self.llm.judge_max_candidates < 1 {
            bail!("llm.judge_max_candidates must be >= 1");
        }
        if self.llm.judge_prompt_file.trim().is_empty() {
            bail!("llm.judge_prompt_file must be non-empty");
        }
        if self.llm.debate_prompt_file.trim().is_empty() {
            bail!("llm.debate_prompt_file must be non-empty");
        }
        if self.llm.critique_revise_prompt_file.trim().is_empty() {
            bail!("llm.critique_revise_prompt_file must be non-empty");
        }
        if let Some(model) = &self.llm.judge_model
            && model.trim().is_empty()
        {
            bail!("llm.judge_model must be non-empty when set");
        }
        let mut seen_agent_names = std::collections::BTreeSet::new();
        for (idx, agent) in self.llm.agents.iter().enumerate() {
            if agent.name.trim().is_empty() {
                bail!("llm.agents[{idx}].name must be non-empty");
            }
            let key = agent.name.to_ascii_lowercase();
            if !seen_agent_names.insert(key) {
                bail!(
                    "llm.agents[{idx}] has duplicate name '{}'; agent names must be unique",
                    agent.name
                );
            }
            if let Some(value) = agent.min_confidence
                && !(0.0..=1.0).contains(&value)
            {
                bail!("llm.agents[{idx}].min_confidence must be between 0.0 and 1.0");
            }
            if let Some(provider) = &agent.provider
                && provider.trim().is_empty()
            {
                bail!("llm.agents[{idx}].provider must be non-empty when set");
            }
            if let Some(model) = &agent.model
                && model.trim().is_empty()
            {
                bail!("llm.agents[{idx}].model must be non-empty when set");
            }
        }
        for (idx, entry) in self.reviews.path_instructions.iter().enumerate() {
            if entry.paths.is_empty() {
                bail!("reviews.path_instructions[{idx}].paths must contain at least one glob");
            }
            if entry.instructions.trim().is_empty() {
                bail!("reviews.path_instructions[{idx}].instructions must be non-empty");
            }
            for pattern in &entry.paths {
                Glob::new(pattern).with_context(|| {
                    format!("invalid reviews.path_instructions[{idx}] glob '{pattern}'")
                })?;
            }
        }
        if matches!(
            self.llm.workflow_strategy,
            LlmWorkflowStrategy::Consensus | LlmWorkflowStrategy::JudgeConsensus
        ) {
            let enabled_agents = self.llm.agents.iter().filter(|a| a.enabled).count();
            let effective_agents = if enabled_agents == 0 {
                1
            } else {
                enabled_agents
            };
            if self.llm.consensus_min_support > effective_agents {
                bail!(
                    "llm.consensus_min_support ({}) cannot exceed active reviewer count ({effective_agents})",
                    self.llm.consensus_min_support
                );
            }
        }
        Ok(())
    }
}

fn load_file(path: &Path) -> anyhow::Result<AppConfig> {
    let mut visiting = Vec::new();
    let merged = apply_profile_preset_layer(load_merged_value(path, &mut visiting)?);
    let mut cfg: AppConfig = serde_json::from_value(merged)
        .with_context(|| format!("failed to decode merged config from {}", path.display()))?;
    cfg.normalize();
    Ok(cfg)
}

fn load_merged_value(path: &Path, visiting: &mut Vec<PathBuf>) -> anyhow::Result<Value> {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if visiting.contains(&canonical) {
        bail!(
            "cyclic config inheritance detected at {}",
            canonical.display()
        );
    }
    visiting.push(canonical);

    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    let mut child = parse_config_value(path, &text)?;

    let inheritance_enabled = child
        .get("inheritance")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if inheritance_enabled && let Some(parent_raw) = child.get("extends").and_then(Value::as_str) {
        let parent_path = resolve_parent_config_path(path, parent_raw);
        let parent = load_merged_value(&parent_path, visiting)?;
        child = merge_config_values(parent, child);
    }

    visiting.pop();
    Ok(child)
}

fn resolve_parent_config_path(current_path: &Path, parent_raw: &str) -> PathBuf {
    let parent = PathBuf::from(parent_raw);
    if parent.is_absolute() {
        parent
    } else {
        current_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(parent)
    }
}

fn parse_config_value(path: &Path, text: &str) -> anyhow::Result<Value> {
    let ext = path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    let as_yaml = || -> anyhow::Result<Value> {
        let parsed: serde_yaml::Value = serde_yaml::from_str(text)
            .with_context(|| format!("failed to parse YAML in {}", path.display()))?;
        serde_json::to_value(parsed).context("failed to convert YAML to JSON value")
    };
    let as_toml = || -> anyhow::Result<Value> {
        let parsed: toml::Value = toml::from_str(text)
            .with_context(|| format!("failed to parse TOML in {}", path.display()))?;
        serde_json::to_value(parsed).context("failed to convert TOML to JSON value")
    };

    match ext.as_str() {
        "yaml" | "yml" => as_yaml(),
        "toml" => as_toml(),
        _ => as_yaml().or_else(|_| as_toml()).with_context(|| {
            format!(
                "failed to parse config {}; expected YAML or TOML",
                path.display()
            )
        }),
    }
}

fn merge_config_values(parent: Value, child: Value) -> Value {
    match (parent, child) {
        (Value::Object(mut p), Value::Object(c)) => {
            for (k, cv) in c {
                let merged = if let Some(pv) = p.remove(&k) {
                    merge_config_values(pv, cv)
                } else {
                    cv
                };
                p.insert(k, merged);
            }
            Value::Object(p)
        }
        (Value::Array(p), Value::Array(c)) => {
            let mut out = c;
            for item in p {
                if !out.iter().any(|existing| existing == &item) {
                    out.push(item);
                }
            }
            Value::Array(out)
        }
        (_, c) => c,
    }
}

fn apply_profile_preset_layer(child: Value) -> Value {
    let profile = child
        .get("profile")
        .and_then(Value::as_str)
        .unwrap_or("default");
    if let Some(preset) = profile_preset_value(profile) {
        merge_config_values(preset, child)
    } else {
        child
    }
}

fn profile_preset_value(profile: &str) -> Option<Value> {
    match profile.to_ascii_lowercase().as_str() {
        "iac" | "security-iac" => Some(json!({
            "checks": {
                "secret_patterns": true,
                "iac_misconfig": true,
                "large_pr": false,
                "missing_tests": false
            }
        })),
        "council" => Some(json!({
            "checks": {
                "secret_patterns": true,
                "iac_misconfig": true,
                "unsafe_rust": true,
                "unwrap_usage": true,
                "debug_statements": true,
                "missing_tests": true,
                "large_pr": false
            },
            "pre_merge_checks": {
                "secret_patterns": "error",
                "iac_misconfig": "error",
                "unsafe_rust": "error",
                "unwrap_usage": "warning",
                "debug_statements": "warning",
                "missing_tests": "warning"
            },
            "llm": {
                "min_confidence": 0.75
            }
        })),
        _ => None,
    }
}

fn apply_profile_override_defaults(cfg: &mut AppConfig) {
    match cfg.profile.to_ascii_lowercase().as_str() {
        "iac" | "security-iac" => {
            cfg.checks.secret_patterns = true;
            cfg.checks.iac_misconfig = true;
            cfg.checks.large_pr = false;
            cfg.checks.missing_tests = false;
        }
        "council" => {
            cfg.checks.secret_patterns = true;
            cfg.checks.iac_misconfig = true;
            cfg.checks.unsafe_rust = true;
            cfg.checks.unwrap_usage = true;
            cfg.checks.debug_statements = true;
            cfg.checks.missing_tests = true;
            cfg.checks.large_pr = false;

            cfg.pre_merge_checks.secret_patterns = CheckMode::Error;
            cfg.pre_merge_checks.iac_misconfig = CheckMode::Error;
            cfg.pre_merge_checks.unsafe_rust = CheckMode::Error;
            cfg.pre_merge_checks.unwrap_usage = CheckMode::Warning;
            cfg.pre_merge_checks.debug_statements = CheckMode::Warning;
            cfg.pre_merge_checks.missing_tests = CheckMode::Warning;

            if cfg.llm.min_confidence < 0.75 {
                cfg.llm.min_confidence = 0.75;
            }
        }
        _ => {}
    }
}

fn normalize_pre_merge_modes(cfg: &mut AppConfig) {
    apply_mode_to_toggle(
        cfg.pre_merge_checks.todo_comments,
        &mut cfg.checks.todo_comments,
    );
    apply_mode_to_toggle(
        cfg.pre_merge_checks.debug_statements,
        &mut cfg.checks.debug_statements,
    );
    apply_mode_to_toggle(
        cfg.pre_merge_checks.secret_patterns,
        &mut cfg.checks.secret_patterns,
    );
    apply_mode_to_toggle(cfg.pre_merge_checks.large_pr, &mut cfg.checks.large_pr);
    apply_mode_to_toggle(
        cfg.pre_merge_checks.missing_tests,
        &mut cfg.checks.missing_tests,
    );
    apply_mode_to_toggle(
        cfg.pre_merge_checks.unsafe_rust,
        &mut cfg.checks.unsafe_rust,
    );
    apply_mode_to_toggle(
        cfg.pre_merge_checks.unwrap_usage,
        &mut cfg.checks.unwrap_usage,
    );
    apply_mode_to_toggle(
        cfg.pre_merge_checks.iac_misconfig,
        &mut cfg.checks.iac_misconfig,
    );
}

fn apply_mode_to_toggle(mode: CheckMode, toggle: &mut bool) {
    match mode {
        CheckMode::Off => *toggle = false,
        CheckMode::Warning | CheckMode::Error => *toggle = true,
        CheckMode::Inherit => {}
    }
}

pub fn effective_mode_for_rule(cfg: &PreMergeChecksConfig, rule: &str) -> CheckMode {
    match rule {
        "todo-comments" => cfg.todo_comments,
        "debug-statements" => cfg.debug_statements,
        "secret-patterns" | "secret-patterns-comprehensive" => cfg.secret_patterns,
        "large-pr" => cfg.large_pr,
        "missing-tests" => cfg.missing_tests,
        "unsafe-rust" => cfg.unsafe_rust,
        "unwrap-usage" => cfg.unwrap_usage,
        "iac-open-network" | "iac-privileged-workload" | "iac-unpinned-image" => cfg.iac_misconfig,
        _ => CheckMode::Inherit,
    }
}

fn parse_bool(key: &str, value: &str) -> anyhow::Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("{key} must be a boolean, got '{value}'"),
    }
}

fn parse_check_mode(key: &str, value: &str) -> anyhow::Result<CheckMode> {
    match value.to_ascii_lowercase().as_str() {
        "off" => Ok(CheckMode::Off),
        "warning" | "warn" => Ok(CheckMode::Warning),
        "error" => Ok(CheckMode::Error),
        "inherit" => Ok(CheckMode::Inherit),
        _ => bail!("{key} must be off|warning|error|inherit, got '{value}'"),
    }
}

fn parse_usize(key: &str, value: &str) -> anyhow::Result<usize> {
    value
        .parse::<usize>()
        .with_context(|| format!("{key} must be a positive integer, got '{value}'"))
}

fn parse_u64(key: &str, value: &str) -> anyhow::Result<u64> {
    value
        .parse::<u64>()
        .with_context(|| format!("{key} must be a positive integer, got '{value}'"))
}

fn parse_f64(key: &str, value: &str) -> anyhow::Result<f64> {
    value
        .parse::<f64>()
        .with_context(|| format!("{key} must be a number, got '{value}'"))
}

fn parse_llm_workflow_strategy(key: &str, value: &str) -> anyhow::Result<LlmWorkflowStrategy> {
    match value.to_ascii_lowercase().as_str() {
        "merge" | "dedupe" => Ok(LlmWorkflowStrategy::Merge),
        "consensus" => Ok(LlmWorkflowStrategy::Consensus),
        "judge" => Ok(LlmWorkflowStrategy::Judge),
        "judge-consensus" | "judge_consensus" => Ok(LlmWorkflowStrategy::JudgeConsensus),
        "debate" => Ok(LlmWorkflowStrategy::Debate),
        "critique-revise" | "critique_revise" => Ok(LlmWorkflowStrategy::CritiqueRevise),
        _ => bail!(
            "{key} must be merge|consensus|judge|judge-consensus|debate|critique-revise, got '{value}'"
        ),
    }
}

fn parse_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn apply_override(cfg: &mut AppConfig, key: &str, value: &str) -> anyhow::Result<()> {
    match key {
        "profile" => cfg.profile = value.to_string(),
        "inheritance" => cfg.inheritance = parse_bool(key, value)?,
        "extends" => cfg.extends = Some(value.to_string()),
        "max_reported_findings" => cfg.max_reported_findings = parse_usize(key, value)?,
        "max_examples_per_rule" => cfg.max_examples_per_rule = parse_usize(key, value)?,
        "max_inline_comments" => cfg.max_inline_comments = parse_usize(key, value)?,
        "large_pr_added_lines_threshold" => {
            cfg.large_pr_added_lines_threshold = parse_usize(key, value)?
        }
        "missing_tests_added_lines_threshold" => {
            cfg.missing_tests_added_lines_threshold = parse_usize(key, value)?
        }
        "checks.todo_comments" => cfg.checks.todo_comments = parse_bool(key, value)?,
        "checks.debug_statements" => cfg.checks.debug_statements = parse_bool(key, value)?,
        "checks.secret_patterns" => cfg.checks.secret_patterns = parse_bool(key, value)?,
        "checks.large_pr" => cfg.checks.large_pr = parse_bool(key, value)?,
        "checks.missing_tests" => cfg.checks.missing_tests = parse_bool(key, value)?,
        "checks.unsafe_rust" => cfg.checks.unsafe_rust = parse_bool(key, value)?,
        "checks.unwrap_usage" => cfg.checks.unwrap_usage = parse_bool(key, value)?,
        "checks.iac_misconfig" => cfg.checks.iac_misconfig = parse_bool(key, value)?,

        "pre_merge_checks.todo_comments" => {
            cfg.pre_merge_checks.todo_comments = parse_check_mode(key, value)?
        }
        "pre_merge_checks.debug_statements" => {
            cfg.pre_merge_checks.debug_statements = parse_check_mode(key, value)?
        }
        "pre_merge_checks.secret_patterns" => {
            cfg.pre_merge_checks.secret_patterns = parse_check_mode(key, value)?
        }
        "pre_merge_checks.large_pr" => {
            cfg.pre_merge_checks.large_pr = parse_check_mode(key, value)?
        }
        "pre_merge_checks.missing_tests" => {
            cfg.pre_merge_checks.missing_tests = parse_check_mode(key, value)?
        }
        "pre_merge_checks.unsafe_rust" => {
            cfg.pre_merge_checks.unsafe_rust = parse_check_mode(key, value)?
        }
        "pre_merge_checks.unwrap_usage" => {
            cfg.pre_merge_checks.unwrap_usage = parse_check_mode(key, value)?
        }
        "pre_merge_checks.iac_misconfig" => {
            cfg.pre_merge_checks.iac_misconfig = parse_check_mode(key, value)?
        }

        "llm.enabled" => cfg.llm.enabled = parse_bool(key, value)?,
        "llm.provider" => cfg.llm.provider = value.to_string(),
        "llm.base_url" => cfg.llm.base_url = value.to_string(),
        "llm.model" => cfg.llm.model = value.to_string(),
        "llm.api_key_env" => cfg.llm.api_key_env = value.to_string(),
        "llm.cli_command" => cfg.llm.cli_command = value.to_string(),
        "llm.cli_args" => cfg.llm.cli_args = parse_csv(value),
        "llm.fallback_models" => cfg.llm.fallback_models = parse_csv(value),
        "llm.fallback_providers" => cfg.llm.fallback_providers = parse_csv(value),
        "llm.prompt_core_file" => cfg.llm.prompt_core_file = value.to_string(),
        "llm.prompt_pr_file" => cfg.llm.prompt_pr_file = value.to_string(),
        "llm.prompt_scan_file" => cfg.llm.prompt_scan_file = value.to_string(),
        "llm.prompt_output_contract_file" => {
            cfg.llm.prompt_output_contract_file = value.to_string()
        }
        "llm.max_prompt_chars" => cfg.llm.max_prompt_chars = parse_usize(key, value)?,
        "llm.max_findings" => cfg.llm.max_findings = parse_usize(key, value)?,
        "llm.max_chunks" => cfg.llm.max_chunks = parse_usize(key, value)?,
        "llm.provider_timeout_secs" => cfg.llm.provider_timeout_secs = parse_u64(key, value)?,
        "llm.min_confidence" => cfg.llm.min_confidence = parse_f64(key, value)?,
        "llm.pr_changed_lines_only" => cfg.llm.pr_changed_lines_only = parse_bool(key, value)?,
        "llm.workflow_strategy" => {
            cfg.llm.workflow_strategy = parse_llm_workflow_strategy(key, value)?
        }
        "llm.consensus_min_support" => cfg.llm.consensus_min_support = parse_usize(key, value)?,
        "llm.judge_model" => {
            cfg.llm.judge_model = if value.trim().is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }
        "llm.judge_prompt_file" => cfg.llm.judge_prompt_file = value.to_string(),
        "llm.judge_max_candidates" => cfg.llm.judge_max_candidates = parse_usize(key, value)?,
        "llm.debate_prompt_file" => cfg.llm.debate_prompt_file = value.to_string(),
        "llm.critique_revise_prompt_file" => {
            cfg.llm.critique_revise_prompt_file = value.to_string()
        }

        "reviews.auto_review.enabled" => cfg.reviews.auto_review.enabled = parse_bool(key, value)?,
        "reviews.auto_review.include_drafts" => {
            cfg.reviews.auto_review.include_drafts = parse_bool(key, value)?
        }
        "reviews.auto_review.labels" => cfg.reviews.auto_review.labels = parse_csv(value),
        "reviews.auto_review.exclude_labels" => {
            cfg.reviews.auto_review.exclude_labels = parse_csv(value)
        }
        "reviews.auto_review.title_keywords" => {
            cfg.reviews.auto_review.title_keywords = parse_csv(value)
        }
        "reviews.auto_review.base_branches" => {
            cfg.reviews.auto_review.base_branches = parse_csv(value)
        }
        "reviews.auto_review.ignore_usernames" => {
            cfg.reviews.auto_review.ignore_usernames = parse_csv(value)
        }

        "tools.sarif.enabled" => cfg.tools.sarif.enabled = parse_bool(key, value)?,
        "tools.sarif.paths" => cfg.tools.sarif.paths = parse_csv(value),
        "tools.eslint.enabled" => cfg.tools.eslint.enabled = parse_bool(key, value)?,
        "tools.eslint.paths" => cfg.tools.eslint.paths = parse_csv(value),
        "tools.semgrep.enabled" => cfg.tools.semgrep.enabled = parse_bool(key, value)?,
        "tools.semgrep.paths" => cfg.tools.semgrep.paths = parse_csv(value),
        "tools.checkov.enabled" => cfg.tools.checkov.enabled = parse_bool(key, value)?,
        "tools.checkov.paths" => cfg.tools.checkov.paths = parse_csv(value),
        "tools.gitleaks.enabled" => cfg.tools.gitleaks.enabled = parse_bool(key, value)?,
        "tools.gitleaks.paths" => cfg.tools.gitleaks.paths = parse_csv(value),
        "tools.clippy.enabled" => cfg.tools.clippy.enabled = parse_bool(key, value)?,
        "tools.clippy.paths" => cfg.tools.clippy.paths = parse_csv(value),

        "filters.include_globs" => cfg.filters.include_globs = parse_csv(value),
        "filters.exclude_globs" => cfg.filters.exclude_globs = parse_csv(value),
        "filters.ignore_file" => cfg.filters.ignore_file = value.to_string(),
        "baseline.enabled" => cfg.baseline.enabled = parse_bool(key, value)?,
        "baseline.file" => cfg.baseline.file = value.to_string(),
        "baseline.update" => cfg.baseline.update = parse_bool(key, value)?,
        "scope.initial_pr_scope" => cfg.scope.initial_pr_scope = value.to_string(),
        "scope.sync_scope" => cfg.scope.sync_scope = value.to_string(),
        "scope.manual_scope" => cfg.scope.manual_scope = value.to_string(),
        "debug.upload_failed_provider_artifacts" => {
            cfg.debug.upload_failed_provider_artifacts = parse_bool(key, value)?
        }
        "debug.artifact_dir" => cfg.debug.artifact_dir = value.to_string(),
        _ => bail!("unsupported override key '{key}'"),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        AppConfig, CheckMode, LlmAgentConfig, LlmWorkflowStrategy, apply_override,
        effective_mode_for_rule,
    };

    fn unique_temp_file(name: &str, extension: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "fantastic-pr-config-{name}-{}-{nanos}.{extension}",
            std::process::id()
        ))
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "fantastic-pr-config-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn applies_nested_overrides() {
        let mut cfg = AppConfig::default();
        apply_override(&mut cfg, "profile", "iac").expect("profile override should work");
        apply_override(&mut cfg, "checks.unwrap_usage", "false")
            .expect("bool override should work");
        apply_override(&mut cfg, "llm.max_chunks", "8").expect("usize override should work");
        apply_override(&mut cfg, "llm.provider_timeout_secs", "120")
            .expect("timeout override should work");
        apply_override(&mut cfg, "llm.min_confidence", "0.8").expect("f64 override should work");
        apply_override(&mut cfg, "llm.pr_changed_lines_only", "false")
            .expect("bool override should work");
        apply_override(&mut cfg, "llm.workflow_strategy", "judge-consensus")
            .expect("strategy override should work");
        apply_override(&mut cfg, "llm.consensus_min_support", "2")
            .expect("consensus override should work");
        apply_override(&mut cfg, "llm.judge_model", "gpt-4.1")
            .expect("judge model override should work");
        apply_override(&mut cfg, "llm.judge_max_candidates", "25")
            .expect("judge cap override should work");
        apply_override(
            &mut cfg,
            "llm.debate_prompt_file",
            "prompts/workflows/debate-alt.txt",
        )
        .expect("debate prompt override should work");
        apply_override(
            &mut cfg,
            "llm.critique_revise_prompt_file",
            "prompts/workflows/revise-alt.txt",
        )
        .expect("critique revise prompt override should work");
        apply_override(&mut cfg, "pre_merge_checks.unwrap_usage", "error")
            .expect("mode override should work");
        apply_override(&mut cfg, "baseline.enabled", "true").expect("baseline bool");
        apply_override(&mut cfg, "llm.provider", "gemini-cli").expect("provider set");
        apply_override(&mut cfg, "scope.sync_scope", "expanded").expect("scope set");
        apply_override(&mut cfg, "llm.fallback_models", "gpt-4.1-mini,gpt-4o-mini")
            .expect("fallback models set");

        cfg.normalize();
        assert_eq!(cfg.profile, "iac");
        assert!(cfg.checks.unwrap_usage);
        assert_eq!(cfg.pre_merge_checks.unwrap_usage, CheckMode::Error);
        assert_eq!(cfg.llm.max_chunks, 8);
        assert_eq!(cfg.llm.provider_timeout_secs, 120);
        assert_eq!(cfg.llm.min_confidence, 0.8);
        assert!(!cfg.llm.pr_changed_lines_only);
        assert_eq!(
            cfg.llm.workflow_strategy,
            LlmWorkflowStrategy::JudgeConsensus
        );
        assert_eq!(cfg.llm.consensus_min_support, 2);
        assert_eq!(cfg.llm.judge_model.as_deref(), Some("gpt-4.1"));
        assert_eq!(cfg.llm.judge_max_candidates, 25);
        assert_eq!(
            cfg.llm.debate_prompt_file,
            "prompts/workflows/debate-alt.txt"
        );
        assert_eq!(
            cfg.llm.critique_revise_prompt_file,
            "prompts/workflows/revise-alt.txt"
        );
        assert!(cfg.baseline.enabled);
        assert_eq!(cfg.llm.provider, "gemini-cli");
        assert_eq!(cfg.scope.sync_scope, "expanded");
        assert_eq!(cfg.llm.fallback_models.len(), 2);
    }

    #[test]
    fn loads_yaml_and_writes_back() {
        let path = unique_temp_file("load-yaml", "yaml");
        let yaml = r#"
profile: default
reviews:
  auto_review:
    enabled: true
    include_drafts: false
pre_merge_checks:
  unwrap_usage: error
"#;
        std::fs::write(&path, yaml).expect("write test yaml");
        let cfg = AppConfig::load_from_file(&path).expect("load yaml");
        assert_eq!(cfg.pre_merge_checks.unwrap_usage, CheckMode::Error);
        assert!(cfg.checks.unwrap_usage);
        cfg.write_yaml(&path).expect("write yaml");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn supports_inheritance_and_array_merge() {
        let dir = PathBuf::from(format!("/tmp/fantastic-pr-inherit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create dir");
        let parent = dir.join("parent.yaml");
        let child = dir.join("child.yaml");

        std::fs::write(
            &parent,
            r#"
llm:
  max_chunks: 3
reviews:
  auto_review:
    labels: [security, backend]
"#,
        )
        .expect("write parent");

        std::fs::write(
            &child,
            r#"
inheritance: true
extends: parent.yaml
reviews:
  auto_review:
    labels: [backend, urgent]
"#,
        )
        .expect("write child");

        let cfg = AppConfig::load_from_file(&child).expect("load inherited");
        assert_eq!(cfg.llm.max_chunks, 3);
        assert_eq!(
            cfg.reviews.auto_review.labels,
            vec![
                "backend".to_string(),
                "urgent".to_string(),
                "security".to_string()
            ]
        );
        let _ = std::fs::remove_file(&parent);
        let _ = std::fs::remove_file(&child);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn configured_ingest_paths_include_missing_paths() {
        let mut cfg = AppConfig::default();
        cfg.tools.checkov.enabled = true;
        cfg.tools.checkov.paths = vec!["/tmp/does-not-exist-checkov.json".to_string()];
        let paths = cfg.configured_ingest_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], PathBuf::from("/tmp/does-not-exist-checkov.json"));
    }

    #[test]
    fn rejects_duplicate_llm_agent_names() {
        let path = unique_temp_file("agents-dup", "yaml");
        let yaml = r#"
llm:
  agents:
    - name: general
      enabled: true
      focus: a
    - name: general
      enabled: true
      focus: b
"#;
        std::fs::write(&path, yaml).expect("write yaml");
        let err = AppConfig::load_from_file(&path).expect_err("duplicate agents must fail");
        let _ = std::fs::remove_file(&path);
        assert!(err.to_string().contains("duplicate name"));
    }

    #[test]
    fn rejects_invalid_agent_min_confidence() {
        let mut cfg = AppConfig::default();
        cfg.llm.agents = vec![LlmAgentConfig {
            name: "security".to_string(),
            enabled: true,
            focus: "x".to_string(),
            prompt_file: None,
            provider: None,
            model: None,
            min_confidence: Some(1.1),
        }];
        let path = unique_temp_file("agent-conf", "yaml");
        cfg.write_yaml(&path).expect("write yaml");
        let err = AppConfig::load_from_file(&path).expect_err("invalid confidence must fail");
        let _ = std::fs::remove_file(&path);
        assert!(err.to_string().contains("min_confidence"));
    }

    #[test]
    fn applies_more_override_key_paths() {
        let mut cfg = AppConfig::default();
        apply_override(&mut cfg, "tools.sarif.enabled", "true").expect("sarif enabled");
        apply_override(&mut cfg, "tools.sarif.paths", "a.sarif,b.sarif").expect("sarif paths");
        apply_override(&mut cfg, "tools.eslint.enabled", "true").expect("eslint enabled");
        apply_override(&mut cfg, "tools.eslint.paths", "a.json").expect("eslint paths");
        apply_override(&mut cfg, "reviews.auto_review.labels", "security,backend").expect("labels");
        apply_override(&mut cfg, "reviews.auto_review.exclude_labels", "skip-ai")
            .expect("exclude labels");
        apply_override(
            &mut cfg,
            "reviews.auto_review.base_branches",
            "main,develop",
        )
        .expect("base branches");
        apply_override(
            &mut cfg,
            "reviews.auto_review.title_keywords",
            "security,urgent",
        )
        .expect("title keywords");
        apply_override(
            &mut cfg,
            "reviews.auto_review.ignore_usernames",
            "bot1,bot2",
        )
        .expect("ignore usernames");
        apply_override(&mut cfg, "filters.include_globs", "src/**,tests/**")
            .expect("include globs");
        apply_override(&mut cfg, "filters.exclude_globs", "dist/**,vendor/**")
            .expect("exclude globs");
        apply_override(&mut cfg, "filters.ignore_file", ".custom-ignore").expect("ignore file");
        apply_override(&mut cfg, "scope.initial_pr_scope", "diff").expect("scope initial");
        apply_override(&mut cfg, "scope.manual_scope", "full").expect("scope manual");
        apply_override(&mut cfg, "debug.upload_failed_provider_artifacts", "true")
            .expect("debug upload");
        apply_override(&mut cfg, "debug.artifact_dir", "tmp-artifacts").expect("artifact dir");

        assert!(cfg.tools.sarif.enabled);
        assert_eq!(cfg.tools.sarif.paths, vec!["a.sarif", "b.sarif"]);
        assert!(cfg.tools.eslint.enabled);
        assert_eq!(cfg.reviews.auto_review.labels, vec!["security", "backend"]);
        assert_eq!(cfg.reviews.auto_review.exclude_labels, vec!["skip-ai"]);
        assert_eq!(
            cfg.reviews.auto_review.base_branches,
            vec!["main", "develop"]
        );
        assert_eq!(
            cfg.reviews.auto_review.title_keywords,
            vec!["security", "urgent"]
        );
        assert_eq!(
            cfg.reviews.auto_review.ignore_usernames,
            vec!["bot1", "bot2"]
        );
        assert_eq!(cfg.filters.include_globs, vec!["src/**", "tests/**"]);
        assert_eq!(cfg.filters.exclude_globs, vec!["dist/**", "vendor/**"]);
        assert_eq!(cfg.filters.ignore_file, ".custom-ignore");
        assert_eq!(cfg.scope.initial_pr_scope, "diff");
        assert_eq!(cfg.scope.manual_scope, "full");
        assert!(cfg.debug.upload_failed_provider_artifacts);
        assert_eq!(cfg.debug.artifact_dir, "tmp-artifacts");
    }

    #[test]
    fn rejects_invalid_override_values_and_unknown_key() {
        let mut cfg = AppConfig::default();
        assert!(apply_override(&mut cfg, "checks.todo_comments", "maybe").is_err());
        assert!(apply_override(&mut cfg, "pre_merge_checks.unwrap_usage", "badmode").is_err());
        assert!(apply_override(&mut cfg, "llm.max_chunks", "NaN").is_err());
        assert!(apply_override(&mut cfg, "llm.provider_timeout_secs", "-1").is_err());
        assert!(apply_override(&mut cfg, "llm.min_confidence", "not-a-number").is_err());
        assert!(apply_override(&mut cfg, "llm.workflow_strategy", "not-a-mode").is_err());
        assert!(apply_override(&mut cfg, "does.not.exist", "x").is_err());
    }

    #[test]
    fn rejects_consensus_support_above_effective_agent_count() {
        let mut cfg = AppConfig::default();
        cfg.llm.workflow_strategy = LlmWorkflowStrategy::Consensus;
        cfg.llm.consensus_min_support = 4;
        let path = unique_temp_file("bad-consensus-support", "yaml");
        cfg.write_yaml(&path).expect("write yaml");
        let err = AppConfig::load_from_file(&path).expect_err("invalid support should fail");
        let _ = std::fs::remove_file(&path);
        assert!(err.to_string().contains("consensus_min_support"));
    }

    #[test]
    fn accepts_new_llm_workflow_strategy_values() {
        let mut cfg = AppConfig::default();
        apply_override(&mut cfg, "llm.workflow_strategy", "debate")
            .expect("debate strategy override should work");
        assert_eq!(cfg.llm.workflow_strategy, LlmWorkflowStrategy::Debate);

        apply_override(&mut cfg, "llm.workflow_strategy", "critique-revise")
            .expect("critique-revise strategy override should work");
        assert_eq!(
            cfg.llm.workflow_strategy,
            LlmWorkflowStrategy::CritiqueRevise
        );
    }

    #[test]
    fn loads_toml_and_unknown_extension_files() {
        let toml_path = unique_temp_file("load-toml", "toml");
        std::fs::write(
            &toml_path,
            r#"
profile = "iac"
[llm]
max_chunks = 7
"#,
        )
        .expect("write toml");

        let cfg = AppConfig::load_from_file(&toml_path).expect("load toml");
        let _ = std::fs::remove_file(&toml_path);
        assert_eq!(cfg.profile, "iac");
        assert_eq!(cfg.llm.max_chunks, 7);

        let conf_path = unique_temp_file("load-conf", "conf");
        std::fs::write(
            &conf_path,
            r#"
profile: security
llm:
  max_chunks: 5
"#,
        )
        .expect("write conf");

        let cfg = AppConfig::load_from_file(&conf_path).expect("load fallback yaml");
        let _ = std::fs::remove_file(&conf_path);
        assert_eq!(cfg.profile, "security");
        assert_eq!(cfg.llm.max_chunks, 5);
    }

    #[test]
    fn profile_preset_keeps_explicit_file_overrides() {
        let path = unique_temp_file("profile-explicit", "yaml");
        std::fs::write(
            &path,
            r#"
profile: iac
checks:
  large_pr: true
"#,
        )
        .expect("write yaml");

        let cfg = AppConfig::load_from_file(&path).expect("load config");
        let _ = std::fs::remove_file(&path);
        assert!(cfg.checks.large_pr);
        assert!(cfg.checks.iac_misconfig);
        assert!(cfg.checks.secret_patterns);
    }

    #[test]
    fn cli_profile_override_applies_profile_defaults() {
        let path = unique_temp_file("profile-cli-default", "yaml");
        let _ = std::fs::remove_file(&path);
        let cfg = AppConfig::load_with_overrides(&path, &["profile=iac".to_string()])
            .expect("load config with cli profile override");
        assert!(!cfg.checks.large_pr);
        assert!(!cfg.checks.missing_tests);
        assert!(cfg.checks.iac_misconfig);
    }

    #[test]
    fn cli_profile_override_runs_before_other_cli_overrides() {
        let path = unique_temp_file("profile-cli-order", "yaml");
        std::fs::write(&path, "profile: default\n").expect("write yaml");

        let cfg = AppConfig::load_with_overrides(
            &path,
            &[
                "profile=iac".to_string(),
                "checks.large_pr=true".to_string(),
            ],
        )
        .expect("load config with overrides");
        let _ = std::fs::remove_file(&path);

        assert!(cfg.checks.large_pr);
        assert!(cfg.checks.iac_misconfig);
    }

    #[test]
    fn fails_for_invalid_unknown_extension_content() {
        let bad = unique_temp_file("bad-config", "conf");
        std::fs::write(&bad, "{ profile: [ }").expect("write bad config");
        let err = AppConfig::load_from_file(&bad).expect_err("invalid config should fail");
        let _ = std::fs::remove_file(&bad);
        assert!(err.to_string().contains("failed to parse config"));
    }

    #[test]
    fn rejects_zero_values_for_schema_minimum_fields() {
        let path = unique_temp_file("invalid-minimums", "yaml");
        std::fs::write(
            &path,
            r#"
max_inline_comments: 0
"#,
        )
        .expect("write yaml");

        let err = AppConfig::load_from_file(&path).expect_err("invalid minimum should fail");
        let _ = std::fs::remove_file(&path);
        assert!(err.to_string().contains("max_inline_comments must be >= 1"));
    }

    #[test]
    fn rejects_unknown_top_level_keys() {
        let path = unique_temp_file("unknown-top-level", "yaml");
        std::fs::write(
            &path,
            r#"
profile: default
not_a_real_key: true
"#,
        )
        .expect("write yaml");

        let err = AppConfig::load_from_file(&path).expect_err("unknown key should fail");
        let _ = std::fs::remove_file(&path);
        let text = format!("{err:#}");
        assert!(text.contains("unknown field"));
        assert!(text.contains("not_a_real_key"));
    }

    #[test]
    fn rejects_unknown_nested_keys() {
        let path = unique_temp_file("unknown-nested", "yaml");
        std::fs::write(
            &path,
            r#"
llm:
  enabled: true
  imaginary_flag: true
"#,
        )
        .expect("write yaml");

        let err = AppConfig::load_from_file(&path).expect_err("unknown nested key should fail");
        let _ = std::fs::remove_file(&path);
        let text = format!("{err:#}");
        assert!(text.contains("unknown field"));
        assert!(text.contains("imaginary_flag"));
    }

    #[test]
    fn detects_cyclic_inheritance() {
        let dir = unique_temp_dir("cycle");
        std::fs::create_dir_all(&dir).expect("create dir");
        let a = dir.join("a.yaml");
        let b = dir.join("b.yaml");

        std::fs::write(
            &a,
            r#"
inheritance: true
extends: b.yaml
profile: a
"#,
        )
        .expect("write a");
        std::fs::write(
            &b,
            r#"
inheritance: true
extends: a.yaml
profile: b
"#,
        )
        .expect("write b");

        let err = AppConfig::load_from_file(&a).expect_err("cycle should fail");
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
        let _ = std::fs::remove_dir(&dir);
        assert!(err.to_string().contains("cyclic config inheritance"));
    }

    #[test]
    fn validates_agent_provider_model_and_path_globs() {
        let path = unique_temp_file("invalid-agent-provider", "yaml");
        std::fs::write(
            &path,
            r#"
llm:
  agents:
    - name: security
      enabled: true
      focus: x
      provider: "   "
reviews:
  path_instructions:
    - name: bad
      paths: ["["]
      instructions: x
"#,
        )
        .expect("write yaml");

        let err = AppConfig::load_from_file(&path).expect_err("invalid semantics should fail");
        let _ = std::fs::remove_file(&path);
        let text = err.to_string();
        assert!(
            text.contains("provider must be non-empty")
                || text.contains("invalid reviews.path_instructions")
        );

        let path = unique_temp_file("invalid-agent-model", "yaml");
        std::fs::write(
            &path,
            r#"
llm:
  agents:
    - name: security
      enabled: true
      focus: x
      model: "   "
"#,
        )
        .expect("write yaml");
        let err = AppConfig::load_from_file(&path).expect_err("invalid model should fail");
        let _ = std::fs::remove_file(&path);
        assert!(err.to_string().contains("model must be non-empty"));
    }

    #[test]
    fn effective_mode_maps_alias_rules() {
        let mut cfg = AppConfig::default();
        cfg.pre_merge_checks.secret_patterns = CheckMode::Error;
        cfg.pre_merge_checks.iac_misconfig = CheckMode::Warning;
        assert_eq!(
            effective_mode_for_rule(&cfg.pre_merge_checks, "secret-patterns-comprehensive"),
            CheckMode::Error
        );
        assert_eq!(
            effective_mode_for_rule(&cfg.pre_merge_checks, "iac-open-network"),
            CheckMode::Warning
        );
        assert_eq!(
            effective_mode_for_rule(&cfg.pre_merge_checks, "unknown-rule"),
            CheckMode::Inherit
        );
    }
}
