mod baseline;
mod checks;
mod config;
mod diff;
mod filtering;
mod github;
mod ingest;
mod llm;
mod mcp;
mod sarif;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};

use crate::baseline::{apply_baseline, write_baseline};
use crate::checks::{
    InlineComment, as_inline_comments, format_json, format_markdown, format_skill_markdown,
    run_checks, run_comprehensive_checks,
};
use crate::config::{AppConfig, CheckMode, DEFAULT_CONFIG_PATH, effective_mode_for_rule};
use crate::diff::{collect_diff, guess_base_ref, read_changed_files};
use crate::filtering::FileFilter;
use crate::github::{
    REPORT_MARKER, build_inline_output_key, publish_inline_comments_once, read_pr_context,
    upsert_comment,
};
use crate::ingest::ingest_external_findings;
use crate::llm::{ReviewMode, probe_provider, run_llm_review};
use crate::sarif::findings_to_sarif;

#[cfg(test)]
pub(crate) fn test_global_lock() -> &'static std::sync::Mutex<()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
enum Mode {
    Auto,
    Pr,
    Scan,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    Markdown,
    Json,
    Both,
    Skill,
    Sarif,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
enum FailOn {
    None,
    Warning,
    Error,
    High,
    Critical,
}

#[derive(Debug, Clone, Subcommand)]
enum CliCommand {
    /// Auto-select PR mode in GitHub Actions, otherwise local scan mode
    Auto,
    /// Review pull request changes and publish GitHub PR comments
    Pr,
    /// Run local diff scan and print findings
    Scan,
    /// Validate merged configuration and exit
    ValidateConfig,
    /// Rewrite configuration into normalized Fantastic PR YAML
    MigrateConfig {
        /// Source config path (defaults to --config)
        #[arg(long, value_name = "PATH")]
        from: Option<PathBuf>,
        /// Destination config path (defaults to .fantastic-pr.yaml)
        #[arg(long, value_name = "PATH")]
        to: Option<PathBuf>,
    },
    /// Probe the configured LLM provider and exit
    ProbeProvider,
    /// Run Fantastic PR as an MCP stdio server
    Mcp,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum CliAction {
    Run(Mode),
    ValidateConfig,
    MigrateConfig {
        from: Option<PathBuf>,
        to: Option<PathBuf>,
    },
    ProbeProvider,
    Mcp,
}

#[derive(Debug, Parser)]
#[command(
    name = "fantastic-pr",
    version,
    about = "PR scanner with GitHub PR mode and local comprehensive CLI mode",
    subcommand_value_name = "COMMAND"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,

    #[arg(long, env = "FANTASTIC_PR_CONFIG", default_value = DEFAULT_CONFIG_PATH, global = true)]
    config: PathBuf,

    #[arg(long, env = "FANTASTIC_PR_BASE_REF", global = true)]
    base_ref: Option<String>,

    #[arg(
        long,
        env = "FANTASTIC_PR_DRY_RUN",
        default_value_t = false,
        global = true
    )]
    dry_run: bool,

    #[arg(
        long,
        env = "FANTASTIC_PR_COMPREHENSIVE",
        default_value_t = false,
        global = true
    )]
    comprehensive: bool,

    #[arg(
        long,
        env = "FANTASTIC_PR_OUTPUT",
        default_value = "markdown",
        global = true
    )]
    output: OutputFormat,

    #[arg(long, env = "FANTASTIC_PR_OUTPUT_FILE", global = true)]
    output_file: Option<PathBuf>,

    #[arg(
        long,
        env = "FANTASTIC_PR_FAIL_ON",
        default_value = "none",
        global = true
    )]
    fail_on: FailOn,

    #[arg(long, env = "FANTASTIC_PR_ENABLE_LLM", global = true)]
    enable_llm: Option<bool>,

    #[arg(
        long,
        env = "FANTASTIC_PR_POST_INLINE",
        global = true,
        action = ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        value_parser = clap::builder::BoolishValueParser::new()
    )]
    post_inline: Option<bool>,

    #[arg(long = "set", value_name = "KEY=VALUE", global = true)]
    set: Vec<String>,

    #[arg(long, env = "FANTASTIC_PR_INGEST", global = true)]
    ingest: Vec<PathBuf>,

    #[arg(long, env = "FANTASTIC_PR_BASELINE_FILE", global = true)]
    baseline_file: Option<PathBuf>,

    #[arg(long, env = "FANTASTIC_PR_BASELINE_ENABLED", global = true)]
    baseline_enabled: Option<bool>,

    #[arg(
        long,
        env = "FANTASTIC_PR_UPDATE_BASELINE",
        default_value_t = false,
        global = true
    )]
    update_baseline: bool,

    #[arg(long, env = "FANTASTIC_PR_EMIT_SARIF", global = true)]
    emit_sarif: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let action = resolve_cli_action(&cli)?;

    if matches!(action, CliAction::Mcp) {
        return mcp::run_stdio_server();
    }

    if let CliAction::MigrateConfig { from, to } = &action {
        let from = from.clone().unwrap_or_else(|| cli.config.clone());
        let to = to
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
        let cfg = AppConfig::load_from_file(&from)?;
        cfg.write_yaml(&to)?;
        println!("Migrated config {} -> {}", from.display(), to.display());
        return Ok(());
    }

    let config = AppConfig::load_with_overrides(&cli.config, &cli.set)?;
    if matches!(action, CliAction::ValidateConfig) {
        println!("Config valid: {}", cli.config.display());
        return Ok(());
    }
    let filter = FileFilter::from_config(&config.filters)?;
    let llm_enabled = cli.enable_llm.unwrap_or(config.llm.enabled);

    if matches!(action, CliAction::ProbeProvider) {
        probe_provider(&config.llm)?;
        println!(
            "LLM provider probe succeeded for '{}'.",
            config.llm.provider
        );
        return Ok(());
    }

    let mode = match action {
        CliAction::Run(mode) => resolve_mode(mode),
        CliAction::ValidateConfig
        | CliAction::MigrateConfig { .. }
        | CliAction::ProbeProvider
        | CliAction::Mcp => {
            unreachable!("non-run action should have returned early")
        }
    };

    match mode {
        Mode::Pr => run_pr_mode(&cli, &config, &filter, llm_enabled),
        Mode::Scan => run_scan_mode(&cli, &config, &filter, llm_enabled),
        Mode::Auto => unreachable!(),
    }
}

fn resolve_cli_action(cli: &Cli) -> anyhow::Result<CliAction> {
    Ok(cli
        .command
        .as_ref()
        .map(CliAction::from_command)
        .unwrap_or(CliAction::Run(Mode::Auto)))
}

impl CliAction {
    fn from_command(command: &CliCommand) -> Self {
        match command {
            CliCommand::Auto => Self::Run(Mode::Auto),
            CliCommand::Pr => Self::Run(Mode::Pr),
            CliCommand::Scan => Self::Run(Mode::Scan),
            CliCommand::ValidateConfig => Self::ValidateConfig,
            CliCommand::MigrateConfig { from, to } => Self::MigrateConfig {
                from: from.clone(),
                to: to.clone(),
            },
            CliCommand::ProbeProvider => Self::ProbeProvider,
            CliCommand::Mcp => Self::Mcp,
        }
    }
}

fn resolve_mode(mode: Mode) -> Mode {
    if matches!(mode, Mode::Auto) {
        let has_gh = std::env::var("GITHUB_EVENT_PATH").is_ok()
            && std::env::var("GITHUB_REPOSITORY").is_ok()
            && std::env::var("GITHUB_TOKEN").is_ok();

        if has_gh { Mode::Pr } else { Mode::Scan }
    } else {
        mode
    }
}

fn post_inline_enabled(cli: &Cli) -> bool {
    cli.post_inline.unwrap_or(true)
}

#[derive(Debug, Clone, Copy)]
struct GatherContext<'a> {
    llm_enabled: bool,
    base_ref: &'a str,
    review_mode: ReviewMode,
    comprehensive: bool,
}

fn run_pr_mode(
    cli: &Cli,
    config: &AppConfig,
    filter: &FileFilter,
    llm_enabled: bool,
) -> anyhow::Result<()> {
    let event_path =
        std::env::var("GITHUB_EVENT_PATH").context("GITHUB_EVENT_PATH is required in PR mode")?;
    let repo =
        std::env::var("GITHUB_REPOSITORY").context("GITHUB_REPOSITORY is required in PR mode")?;
    let token = std::env::var("GITHUB_TOKEN").context("GITHUB_TOKEN is required in PR mode")?;

    let pr_ctx = read_pr_context(&event_path, &repo)?;
    if let Some(reason) = should_skip_pr_review(config, &pr_ctx) {
        let skip_markdown = format_skip_report(&reason);
        let skip_publish = pr_ctx.action.eq_ignore_ascii_case("closed");
        if cli.dry_run || pr_ctx.is_fork || skip_publish {
            println!("{skip_markdown}");
            if skip_publish {
                println!(
                    "PR is closed (action='{}'); skipping GitHub comment upsert.",
                    pr_ctx.action
                );
            }
        } else if let Err(err) = upsert_comment(&token, &pr_ctx, &skip_markdown) {
            eprintln!("Failed to publish skip report comment: {err}");
        }
        println!("PR review skipped by config policy: {reason}");
        return Ok(());
    }
    let base_ref = cli
        .base_ref
        .clone()
        .unwrap_or_else(|| pr_ctx.base_ref.clone());

    let diff = collect_diff(&base_ref)?;
    let review_mode = ReviewMode::Pr;
    let comprehensive = cli.comprehensive || is_pr_scope_expanded(config, &pr_ctx.action);
    let findings_raw = gather_findings(
        cli,
        config,
        filter,
        &diff,
        GatherContext {
            llm_enabled,
            base_ref: &base_ref,
            review_mode,
            comprehensive,
        },
    )?;
    let findings = apply_baseline_policy(cli, config, &findings_raw)?;

    emit_sarif_if_requested(cli, &findings)?;

    let markdown = format_markdown(&findings, &diff, REPORT_MARKER);

    let effective_dry_run = cli.dry_run || pr_ctx.is_fork;
    if effective_dry_run {
        if pr_ctx.is_fork {
            println!(
                "Fork PR detected; running in non-publishing mode (no GitHub comments will be posted)."
            );
        }
        emit_output(cli, &diff, &findings, &markdown)?;
        return enforce_fail_on(cli.fail_on, &findings);
    }

    upsert_comment(&token, &pr_ctx, &markdown)?;

    if post_inline_enabled(cli) {
        let output_key = build_inline_output_key(&pr_ctx);
        let inline_all = as_inline_comments(&findings, config.max_inline_comments);
        let inline = restrict_inline_to_diff_lines(&diff, &inline_all);
        let skipped = inline_all.len().saturating_sub(inline.len());
        let posted = publish_inline_comments_once(&token, &pr_ctx, &output_key, &inline)?;
        if posted {
            println!(
                "Posted {} inline review comments ({} skipped: not on changed lines).",
                inline.len(),
                skipped
            );
        } else {
            println!(
                "Inline review comments skipped (none or already published for this PR finding marker)."
            );
        }
    }

    println!(
        "Posted Fantastic PR report on PR #{} ({} findings)",
        pr_ctx.number,
        findings.len()
    );

    enforce_fail_on(cli.fail_on, &findings)
}

fn run_scan_mode(
    cli: &Cli,
    config: &AppConfig,
    filter: &FileFilter,
    llm_enabled: bool,
) -> anyhow::Result<()> {
    let base_ref = if let Some(base) = &cli.base_ref {
        base.to_string()
    } else if let Some(guessed) = guess_base_ref() {
        guessed
    } else {
        bail!(
            "base ref not provided and no default remote branch was found (tried origin/main and origin/master)"
        );
    };

    let diff = collect_diff(&base_ref)?;
    let findings_raw = gather_findings(
        cli,
        config,
        filter,
        &diff,
        GatherContext {
            llm_enabled,
            base_ref: &base_ref,
            review_mode: ReviewMode::Scan,
            comprehensive: true,
        },
    )?;
    let findings = apply_baseline_policy(cli, config, &findings_raw)?;

    emit_sarif_if_requested(cli, &findings)?;

    let markdown = format_markdown(&findings, &diff, REPORT_MARKER);
    emit_output(cli, &diff, &findings, &markdown)?;
    enforce_fail_on(cli.fail_on, &findings)
}

fn gather_findings(
    cli: &Cli,
    config: &AppConfig,
    filter: &FileFilter,
    diff: &diff::DiffData,
    context: GatherContext<'_>,
) -> anyhow::Result<Vec<checks::Finding>> {
    let mut findings = run_checks(config, diff, filter)?;

    if context.comprehensive {
        let snapshots = read_changed_files(context.base_ref)?;
        findings.extend(run_comprehensive_checks(&snapshots, filter)?);
    }

    if context.llm_enabled {
        let mut llm_config = config.llm.clone();
        llm_config.enabled = true;
        match run_llm_review(
            &llm_config,
            &config.reviews,
            &config.debug,
            diff,
            context.review_mode,
        ) {
            Ok(mut llm_findings) => findings.append(&mut llm_findings),
            Err(err) => eprintln!("LLM pass skipped: {err}"),
        }
    }

    let mut ingest_paths = cli.ingest.clone();
    for path in config.configured_ingest_paths() {
        if !ingest_paths.contains(&path) {
            ingest_paths.push(path);
        }
    }
    if !ingest_paths.is_empty() {
        let mut ext = ingest_external_findings(&ingest_paths, filter)?;
        findings.append(&mut ext);
    }

    Ok(apply_pre_merge_modes(findings, config))
}

fn is_pr_scope_expanded(config: &AppConfig, action: &str) -> bool {
    let selected = if std::env::var("GITHUB_EVENT_NAME")
        .ok()
        .is_some_and(|v| v == "workflow_dispatch")
    {
        config.scope.manual_scope.as_str()
    } else if action == "opened" {
        config.scope.initial_pr_scope.as_str()
    } else {
        config.scope.sync_scope.as_str()
    };

    matches!(
        selected.to_ascii_lowercase().as_str(),
        "expanded" | "repo" | "full"
    )
}

fn emit_output(
    cli: &Cli,
    diff: &diff::DiffData,
    findings: &[checks::Finding],
    markdown: &str,
) -> anyhow::Result<()> {
    let rendered = match cli.output {
        OutputFormat::Markdown => markdown.to_string(),
        OutputFormat::Json => serde_json::to_string_pretty(&format_json(findings, diff))?,
        OutputFormat::Both => {
            let json = serde_json::to_string_pretty(&format_json(findings, diff))?;
            format!("{}\n\n{}", markdown, json)
        }
        OutputFormat::Skill => format_skill_markdown(findings, diff),
        OutputFormat::Sarif => serde_json::to_string_pretty(&findings_to_sarif(findings))?,
    };

    if let Some(path) = &cli.output_file {
        fs::write(path, &rendered)
            .with_context(|| format!("failed to write output file {}", path.display()))?;
    }

    println!("{rendered}");
    Ok(())
}

fn format_skip_report(reason: &str) -> String {
    format!(
        "{REPORT_MARKER}\n## Fantastic PR Report\n\nReview skipped by policy.\n\n- Reason: `{}`",
        reason
    )
}

fn emit_sarif_if_requested(cli: &Cli, findings: &[checks::Finding]) -> anyhow::Result<()> {
    let Some(path) = &cli.emit_sarif else {
        return Ok(());
    };

    let content = serde_json::to_string_pretty(&findings_to_sarif(findings))?;
    fs::write(path, content)
        .with_context(|| format!("failed to write SARIF file {}", path.display()))?;

    Ok(())
}

fn apply_baseline_policy(
    cli: &Cli,
    config: &AppConfig,
    findings: &[checks::Finding],
) -> anyhow::Result<Vec<checks::Finding>> {
    let baseline_enabled = cli.baseline_enabled.unwrap_or(config.baseline.enabled);
    let baseline_path = cli
        .baseline_file
        .as_ref()
        .cloned()
        .unwrap_or_else(|| Path::new(&config.baseline.file).to_path_buf());

    let should_update = cli.update_baseline || config.baseline.update;
    if should_update {
        write_baseline(&baseline_path, findings)?;
        println!("Wrote baseline to {}", baseline_path.display());
        if baseline_enabled {
            println!(
                "Baseline update requested with suppression enabled; skipping suppression for this run."
            );
            return Ok(findings.to_vec());
        }
    }

    if !baseline_enabled {
        return Ok(findings.to_vec());
    }

    let (filtered, suppressed) = apply_baseline(&baseline_path, findings)?;
    if suppressed > 0 {
        println!(
            "Suppressed {suppressed} finding(s) using baseline {}",
            baseline_path.display()
        );
    }

    Ok(filtered)
}

fn enforce_fail_on(fail_on: FailOn, findings: &[checks::Finding]) -> anyhow::Result<()> {
    let has_critical = findings
        .iter()
        .any(|f| matches!(f.severity, checks::Severity::Critical));
    let has_error = findings.iter().any(|f| {
        matches!(
            f.severity,
            checks::Severity::Error | checks::Severity::Critical
        )
    });
    let has_warning = findings
        .iter()
        .any(|f| matches!(f.severity, checks::Severity::Warning));

    match fail_on {
        FailOn::None => Ok(()),
        FailOn::Warning if has_warning || has_error => {
            bail!("findings include warning or error severity")
        }
        FailOn::Error if has_error => bail!("findings include error severity"),
        FailOn::High if has_error => bail!("findings include high or critical severity"),
        FailOn::Critical if has_critical => bail!("findings include critical severity"),
        _ => Ok(()),
    }
}

fn restrict_inline_to_diff_lines(
    diff: &diff::DiffData,
    comments: &[InlineComment],
) -> Vec<InlineComment> {
    let changed_positions = diff
        .added_lines
        .iter()
        .map(|l| (normalize_path(&l.file), l.line))
        .collect::<std::collections::BTreeSet<_>>();

    comments
        .iter()
        .filter(|c| changed_positions.contains(&(normalize_path(&c.path), c.line)))
        .cloned()
        .collect()
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn should_skip_pr_review(config: &AppConfig, pr_ctx: &github::PrContext) -> Option<String> {
    if pr_ctx.action.eq_ignore_ascii_case("closed") {
        return Some("pull request action is closed".to_string());
    }

    let policy = &config.reviews.auto_review;
    if !policy.enabled {
        return Some("reviews.auto_review.enabled=false".to_string());
    }

    if pr_ctx.action.eq_ignore_ascii_case("converted_to_draft") && !policy.include_drafts {
        return Some("pull request converted to draft and include_drafts=false".to_string());
    }

    if pr_ctx.draft && !policy.include_drafts {
        return Some("draft PR and include_drafts=false".to_string());
    }

    let labels = pr_ctx
        .labels
        .iter()
        .map(|v| v.to_ascii_lowercase())
        .collect::<std::collections::BTreeSet<_>>();

    if !policy.labels.is_empty()
        && !policy
            .labels
            .iter()
            .map(|v| v.to_ascii_lowercase())
            .any(|need| labels.contains(&need))
    {
        return Some("required label not present".to_string());
    }

    if policy
        .exclude_labels
        .iter()
        .map(|v| v.to_ascii_lowercase())
        .any(|deny| labels.contains(&deny))
    {
        return Some("excluded label present".to_string());
    }

    if !policy.base_branches.is_empty()
        && !policy
            .base_branches
            .iter()
            .any(|b| b.eq_ignore_ascii_case(&pr_ctx.base_branch))
    {
        return Some(format!(
            "base branch '{}' not in reviews.auto_review.base_branches",
            pr_ctx.base_branch
        ));
    }

    if !policy.title_keywords.is_empty() {
        let title = pr_ctx.title.to_ascii_lowercase();
        let matched = policy
            .title_keywords
            .iter()
            .any(|k| title.contains(&k.to_ascii_lowercase()));
        if !matched {
            return Some("title does not include required keyword".to_string());
        }
    }

    if policy
        .ignore_usernames
        .iter()
        .any(|u| u.eq_ignore_ascii_case(&pr_ctx.author_login))
    {
        return Some(format!(
            "author '{}' is in reviews.auto_review.ignore_usernames",
            pr_ctx.author_login
        ));
    }

    None
}

fn apply_pre_merge_modes(
    findings: Vec<checks::Finding>,
    config: &AppConfig,
) -> Vec<checks::Finding> {
    findings
        .into_iter()
        .filter_map(|mut finding| {
            match effective_mode_for_rule(&config.pre_merge_checks, &finding.rule) {
                CheckMode::Off => return None,
                CheckMode::Warning => {
                    if matches!(finding.severity, checks::Severity::Info) {
                        finding.severity = checks::Severity::Warning;
                    }
                }
                CheckMode::Error => {
                    if !matches!(finding.severity, checks::Severity::Critical) {
                        finding.severity = checks::Severity::Error;
                    }
                }
                CheckMode::Inherit => {}
            }
            Some(finding)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, CliAction, CliCommand, FailOn, GatherContext, OutputFormat, apply_baseline_policy,
        apply_pre_merge_modes, emit_output, emit_sarif_if_requested, enforce_fail_on,
        format_skip_report, gather_findings, is_pr_scope_expanded, normalize_path,
        resolve_cli_action, resolve_mode, restrict_inline_to_diff_lines, run_pr_mode,
        run_scan_mode, should_skip_pr_review,
    };
    use crate::baseline::write_baseline;
    use crate::checks::{Finding, InlineComment, Severity};
    use crate::config::{AppConfig, CheckMode, DEFAULT_CONFIG_PATH};
    use crate::diff::{AddedLine, DiffData, FileChangeStats, parse_unified_diff};
    use crate::filtering::FileFilter;
    use crate::github::PrContext;
    use clap::Parser;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_ctx() -> PrContext {
        PrContext {
            repo: "owner/repo".to_string(),
            number: 1,
            base_ref: "origin/main".to_string(),
            base_branch: "main".to_string(),
            head_sha: "abc".to_string(),
            action: "opened".to_string(),
            title: "Update parser".to_string(),
            draft: false,
            labels: vec![],
            author_login: "octocat".to_string(),
            is_fork: false,
        }
    }

    fn test_cli() -> Cli {
        Cli {
            command: None,
            config: PathBuf::from(DEFAULT_CONFIG_PATH),
            base_ref: None,
            dry_run: true,
            comprehensive: false,
            output: OutputFormat::Markdown,
            output_file: None,
            fail_on: FailOn::None,
            enable_llm: Some(false),
            post_inline: Some(false),
            set: vec![],
            ingest: vec![],
            baseline_file: None,
            baseline_enabled: None,
            update_baseline: false,
            emit_sarif: None,
        }
    }

    fn unique_temp_file(name: &str, extension: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "fantastic-pr-main-{name}-{}-{nanos}.{extension}",
            std::process::id()
        ))
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "fantastic-pr-main-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    struct CwdGuard {
        original: PathBuf,
    }

    impl CwdGuard {
        fn push(path: &Path) -> Self {
            let original = std::env::current_dir().expect("get current dir");
            std::env::set_current_dir(path).expect("set current dir");
            Self { original }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
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

        fn unset(key: &str) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::remove_var(key) };
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

    fn run_git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git command should execute");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn setup_repo_with_two_commits(name: &str) -> PathBuf {
        let repo = unique_temp_dir(name);
        std::fs::create_dir_all(&repo).expect("create repo");
        run_git(&repo, &["init"]);
        run_git(&repo, &["config", "user.email", "fantastic-pr@example.com"]);
        run_git(&repo, &["config", "user.name", "Fantastic PR"]);

        std::fs::create_dir_all(repo.join("src")).expect("create src");
        std::fs::write(repo.join("src/lib.rs"), "pub fn a() {}\n").expect("write base file");
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        std::fs::write(repo.join("src/lib.rs"), "pub fn a() {}\npub fn b() {}\n")
            .expect("update file");
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "change"]);
        repo
    }

    fn write_pr_event(path: &Path, action: &str, draft: bool, fork: bool) {
        let body = format!(
            r#"{{
  "action": "{action}",
  "pull_request": {{
    "number": 7,
    "base": {{ "ref": "main" }},
    "head": {{ "sha": "abc123", "repo": {{ "fork": {fork} }} }},
    "title": "Security update",
    "draft": {draft},
    "labels": [{{ "name": "needs-review" }}],
    "user": {{ "login": "octocat" }}
  }}
}}"#
        );
        std::fs::write(path, body).expect("write pr event");
    }

    fn set_absolute_prompt_pack(cfg: &mut AppConfig) {
        let root = env!("CARGO_MANIFEST_DIR");
        cfg.llm.prompt_core_file = format!("{root}/prompts/core_system.txt");
        cfg.llm.prompt_pr_file = format!("{root}/prompts/mode_pr.txt");
        cfg.llm.prompt_scan_file = format!("{root}/prompts/mode_scan.txt");
        cfg.llm.prompt_output_contract_file = format!("{root}/prompts/output_contract.json");
    }

    #[test]
    fn keeps_only_comments_that_match_added_lines() {
        let mut files = HashMap::new();
        files.insert(
            "src/lib.rs".to_string(),
            FileChangeStats {
                added: 1,
                removed: 0,
            },
        );

        let diff = DiffData {
            added_lines: vec![AddedLine {
                file: "src/lib.rs".to_string(),
                line: 10,
                content: "let x = 1;".to_string(),
            }],
            files,
            total_added: 1,
            total_removed: 0,
        };

        let comments = vec![
            InlineComment {
                rule: "rule-a".to_string(),
                path: "src/lib.rs".to_string(),
                line: 10,
                body: "valid".to_string(),
            },
            InlineComment {
                rule: "rule-b".to_string(),
                path: "src/lib.rs".to_string(),
                line: 99,
                body: "invalid".to_string(),
            },
        ];

        let filtered = restrict_inline_to_diff_lines(&diff, &comments);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].line, 10);
    }

    #[test]
    fn skips_draft_pr_when_policy_disables_drafts() {
        let cfg = AppConfig::default();
        let mut ctx = sample_ctx();
        ctx.draft = true;

        let reason = should_skip_pr_review(&cfg, &ctx);
        assert!(reason.is_some());
    }

    #[test]
    fn applies_pre_merge_modes_to_findings() {
        let mut cfg = AppConfig::default();
        cfg.pre_merge_checks.unwrap_usage = CheckMode::Error;
        cfg.pre_merge_checks.todo_comments = CheckMode::Off;

        let findings = vec![
            Finding {
                rule: "unwrap-usage".to_string(),
                title: "t".to_string(),
                details: "d".to_string(),
                severity: Severity::Info,
                file: Some("src/lib.rs".to_string()),
                line: Some(1),
                suggestion: None,
            },
            Finding {
                rule: "todo-comments".to_string(),
                title: "t2".to_string(),
                details: "d2".to_string(),
                severity: Severity::Info,
                file: Some("src/lib.rs".to_string()),
                line: Some(2),
                suggestion: None,
            },
        ];

        let adjusted = apply_pre_merge_modes(findings, &cfg);
        assert_eq!(adjusted.len(), 1);
        assert_eq!(adjusted[0].rule, "unwrap-usage");
        assert!(matches!(adjusted[0].severity, Severity::Error));
    }

    #[test]
    fn skip_policy_checks_labels_base_branch_title_and_author() {
        let mut cfg = AppConfig::default();
        cfg.reviews.auto_review.labels = vec!["needs-review".to_string()];
        cfg.reviews.auto_review.exclude_labels = vec!["skip-ai".to_string()];
        cfg.reviews.auto_review.base_branches = vec!["develop".to_string()];
        cfg.reviews.auto_review.title_keywords = vec!["security".to_string()];
        cfg.reviews.auto_review.ignore_usernames = vec!["bot-user".to_string()];
        let ctx = sample_ctx();

        let reason = should_skip_pr_review(&cfg, &ctx).expect("expected skip reason");
        assert!(reason.contains("required label"));

        let mut with_label = ctx.clone();
        with_label.labels = vec!["needs-review".to_string(), "skip-ai".to_string()];
        let reason = should_skip_pr_review(&cfg, &with_label).expect("expected skip reason");
        assert!(reason.contains("excluded label"));

        let mut branch_ok = ctx.clone();
        branch_ok.labels = vec!["needs-review".to_string()];
        let reason = should_skip_pr_review(&cfg, &branch_ok).expect("expected skip reason");
        assert!(reason.contains("base branch"));

        let mut title_check = branch_ok.clone();
        title_check.base_branch = "develop".to_string();
        let reason = should_skip_pr_review(&cfg, &title_check).expect("expected skip reason");
        assert!(reason.contains("title does not include"));

        let mut author_check = title_check.clone();
        author_check.title = "security hardening".to_string();
        author_check.author_login = "bot-user".to_string();
        let reason = should_skip_pr_review(&cfg, &author_check).expect("expected skip reason");
        assert!(reason.contains("ignore_usernames"));
    }

    #[test]
    fn skip_policy_handles_closed_and_converted_to_draft_actions() {
        let cfg = AppConfig::default();
        let mut closed = sample_ctx();
        closed.action = "closed".to_string();
        let reason = should_skip_pr_review(&cfg, &closed).expect("expected skip reason");
        assert!(reason.contains("closed"));

        let mut converted = sample_ctx();
        converted.action = "converted_to_draft".to_string();
        converted.draft = true;
        let reason = should_skip_pr_review(&cfg, &converted).expect("expected skip reason");
        assert!(reason.contains("converted to draft"));
    }

    #[test]
    fn lifecycle_actions_reopened_ready_for_review_and_synchronize_are_reviewable() {
        let cfg = AppConfig::default();

        let mut reopened = sample_ctx();
        reopened.action = "reopened".to_string();
        reopened.draft = false;
        assert!(should_skip_pr_review(&cfg, &reopened).is_none());

        let mut ready = sample_ctx();
        ready.action = "ready_for_review".to_string();
        ready.draft = false;
        assert!(should_skip_pr_review(&cfg, &ready).is_none());

        let mut synchronize = sample_ctx();
        synchronize.action = "synchronize".to_string();
        synchronize.draft = false;
        // GitHub uses `synchronize` for both normal pushes and force pushes.
        assert!(should_skip_pr_review(&cfg, &synchronize).is_none());
    }

    #[test]
    fn fail_on_thresholds_are_enforced() {
        let warning = Finding {
            rule: "warn-rule".to_string(),
            title: "warning".to_string(),
            details: "d".to_string(),
            severity: Severity::Warning,
            file: Some("src/lib.rs".to_string()),
            line: Some(1),
            suggestion: None,
        };
        let error = Finding {
            severity: Severity::Error,
            ..warning.clone()
        };
        let critical = Finding {
            severity: Severity::Critical,
            ..warning.clone()
        };

        assert!(enforce_fail_on(FailOn::None, std::slice::from_ref(&warning)).is_ok());
        assert!(enforce_fail_on(FailOn::Warning, std::slice::from_ref(&warning)).is_err());
        assert!(enforce_fail_on(FailOn::Error, std::slice::from_ref(&error)).is_err());
        assert!(enforce_fail_on(FailOn::High, &[error]).is_err());
        assert!(enforce_fail_on(FailOn::Critical, &[critical]).is_err());
    }

    #[test]
    fn format_skip_report_and_scope_mode_defaults() {
        let cfg = AppConfig::default();
        let report = format_skip_report("policy disabled");
        assert!(report.contains("Fantastic PR Report"));
        assert!(report.contains("policy disabled"));

        assert!(is_pr_scope_expanded(&cfg, "opened"));
        assert!(!is_pr_scope_expanded(&cfg, "synchronize"));
    }

    #[test]
    fn baseline_policy_can_update_and_filter() {
        let findings = vec![Finding {
            rule: "x".to_string(),
            title: "title".to_string(),
            details: "details".to_string(),
            severity: Severity::Warning,
            file: Some("src/lib.rs".to_string()),
            line: Some(1),
            suggestion: None,
        }];

        let baseline_path = unique_temp_file("baseline-policy", "json");

        let mut cfg = AppConfig::default();
        cfg.baseline.file = baseline_path.to_string_lossy().to_string();
        cfg.baseline.enabled = false;

        let mut cli = test_cli();
        cli.update_baseline = true;
        cli.baseline_file = Some(baseline_path.clone());
        cli.baseline_enabled = Some(false);

        let updated = apply_baseline_policy(&cli, &cfg, &findings).expect("baseline update");
        assert_eq!(updated.len(), 1);
        assert!(baseline_path.exists());

        write_baseline(&baseline_path, &findings).expect("write baseline fixture");
        cli.update_baseline = false;
        cli.baseline_enabled = Some(true);
        let filtered = apply_baseline_policy(&cli, &cfg, &findings).expect("baseline apply");
        let _ = std::fs::remove_file(&baseline_path);
        assert!(filtered.is_empty());
    }

    #[test]
    fn baseline_update_skips_suppression_when_enabled() {
        let findings = vec![Finding {
            rule: "x".to_string(),
            title: "title".to_string(),
            details: "details".to_string(),
            severity: Severity::Warning,
            file: Some("src/lib.rs".to_string()),
            line: Some(1),
            suggestion: None,
        }];

        let baseline_path = unique_temp_file("baseline-update-nosuppress", "json");
        let mut cfg = AppConfig::default();
        cfg.baseline.file = baseline_path.to_string_lossy().to_string();
        cfg.baseline.enabled = true;
        cfg.baseline.update = true;

        let cli = test_cli();
        let result =
            apply_baseline_policy(&cli, &cfg, &findings).expect("baseline update should succeed");

        let _ = std::fs::remove_file(&baseline_path);
        assert_eq!(result.len(), findings.len());
    }

    #[test]
    fn emits_sarif_file_when_requested() {
        let findings = vec![Finding {
            rule: "x".to_string(),
            title: "title".to_string(),
            details: "details".to_string(),
            severity: Severity::Warning,
            file: Some("src/lib.rs".to_string()),
            line: Some(2),
            suggestion: None,
        }];
        let mut cli = test_cli();
        let sarif_path = unique_temp_file("emit-sarif", "sarif.json");
        cli.emit_sarif = Some(sarif_path.clone());

        emit_sarif_if_requested(&cli, &findings).expect("sarif emit");
        let body = std::fs::read_to_string(&sarif_path).expect("sarif read");
        let _ = std::fs::remove_file(&sarif_path);
        assert!(body.contains("\"runs\""));
        assert!(body.contains("\"ruleId\""));
    }

    #[test]
    fn normalize_path_replaces_backslashes() {
        assert_eq!(normalize_path("src\\lib.rs"), "src/lib.rs");
    }

    #[test]
    fn parser_accepts_conventional_subcommands() {
        let scan = Cli::try_parse_from(["fantastic-pr", "scan"]).expect("scan subcommand");
        assert!(matches!(
            resolve_cli_action(&scan),
            Ok(CliAction::Run(super::Mode::Scan))
        ));
        assert!(matches!(scan.command, Some(CliCommand::Scan)));
    }

    #[test]
    fn parser_defaults_to_auto_mode_without_subcommand() {
        let cli = Cli::try_parse_from(["fantastic-pr"]).expect("default parse");
        assert!(matches!(
            resolve_cli_action(&cli),
            Ok(CliAction::Run(super::Mode::Auto))
        ));
    }

    #[test]
    fn parser_supports_config_and_provider_utility_subcommands() {
        let validate = Cli::try_parse_from(["fantastic-pr", "validate-config"]).expect("validate");
        assert!(matches!(
            resolve_cli_action(&validate),
            Ok(CliAction::ValidateConfig)
        ));

        let probe = Cli::try_parse_from(["fantastic-pr", "probe-provider"]).expect("probe");
        assert!(matches!(
            resolve_cli_action(&probe),
            Ok(CliAction::ProbeProvider)
        ));

        let mcp = Cli::try_parse_from(["fantastic-pr", "mcp"]).expect("mcp");
        assert!(matches!(resolve_cli_action(&mcp), Ok(CliAction::Mcp)));

        let migrate = Cli::try_parse_from([
            "fantastic-pr",
            "migrate-config",
            "--from",
            "in.yaml",
            "--to",
            "out.yaml",
        ])
        .expect("migrate");
        assert!(matches!(
            resolve_cli_action(&migrate),
            Ok(CliAction::MigrateConfig {
                from: Some(_),
                to: Some(_)
            })
        ));
    }

    #[test]
    fn parser_accepts_post_inline_boolean_values() {
        let explicit_false =
            Cli::try_parse_from(["fantastic-pr", "scan", "--post-inline=false"]).expect("false");
        assert_eq!(explicit_false.post_inline, Some(false));

        let explicit_true =
            Cli::try_parse_from(["fantastic-pr", "scan", "--post-inline"]).expect("true");
        assert_eq!(explicit_true.post_inline, Some(true));
    }

    #[test]
    fn parser_rejects_removed_legacy_action_flags() {
        assert!(Cli::try_parse_from(["fantastic-pr", "--mode", "scan"]).is_err());
        assert!(Cli::try_parse_from(["fantastic-pr", "--validate-config"]).is_err());
        assert!(Cli::try_parse_from(["fantastic-pr", "--migrate-config"]).is_err());
        assert!(Cli::try_parse_from(["fantastic-pr", "--probe-provider"]).is_err());
    }

    #[test]
    fn resolve_mode_auto_switches_between_scan_and_pr() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let _unset_event_path = EnvGuard::unset("GITHUB_EVENT_PATH");
        let _unset_repo = EnvGuard::unset("GITHUB_REPOSITORY");
        let _unset_token = EnvGuard::unset("GITHUB_TOKEN");
        assert!(matches!(resolve_mode(super::Mode::Auto), super::Mode::Scan));

        let _set_event_path = EnvGuard::set("GITHUB_EVENT_PATH", "/tmp/evt.json");
        let _set_repo = EnvGuard::set("GITHUB_REPOSITORY", "owner/repo");
        let _set_token = EnvGuard::set("GITHUB_TOKEN", "token");
        assert!(matches!(resolve_mode(super::Mode::Auto), super::Mode::Pr));
        assert!(matches!(resolve_mode(super::Mode::Scan), super::Mode::Scan));
    }

    #[test]
    fn scope_expands_for_workflow_dispatch_manual_mode() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _set_event_name = EnvGuard::set("GITHUB_EVENT_NAME", "workflow_dispatch");

        let mut cfg = AppConfig::default();
        cfg.scope.manual_scope = "full".to_string();
        assert!(is_pr_scope_expanded(&cfg, "synchronize"));
    }

    #[test]
    fn emit_output_supports_all_formats_and_file_writes() {
        let diff = DiffData {
            added_lines: vec![],
            files: HashMap::new(),
            total_added: 1,
            total_removed: 0,
        };
        let findings = vec![Finding {
            rule: "rule-x".to_string(),
            title: "title".to_string(),
            details: "details".to_string(),
            severity: Severity::Warning,
            file: Some("src/lib.rs".to_string()),
            line: Some(2),
            suggestion: None,
        }];
        let markdown = "sample markdown";

        for (fmt, needle) in [
            (OutputFormat::Markdown, "sample markdown"),
            (OutputFormat::Json, "\"summary\""),
            (OutputFormat::Both, "sample markdown"),
            (OutputFormat::Skill, "# Fantastic PR Local Review"),
            (OutputFormat::Sarif, "\"runs\""),
        ] {
            let mut cli = test_cli();
            cli.output = fmt;
            let out_path = unique_temp_file("emit-output", "txt");
            cli.output_file = Some(out_path.clone());

            emit_output(&cli, &diff, &findings, markdown).expect("emit output");
            let text = std::fs::read_to_string(&out_path).expect("read output file");
            let _ = std::fs::remove_file(&out_path);
            assert!(text.contains(needle));
        }
    }

    #[test]
    fn gather_findings_combines_checks_and_ingest() {
        let diff_text = r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+fn x() { Some(1).unwrap(); }
"#;
        let diff = parse_unified_diff(diff_text).expect("parse diff");

        let ingest_path = unique_temp_file("gather-findings", "json");
        std::fs::write(
            &ingest_path,
            r#"[
  {
    "RuleID":"aws-access-token",
    "Description":"AWS Access Key detected",
    "File":"src/secrets.txt",
    "StartLine":3
  }
]"#,
        )
        .expect("write ingest");

        let mut cfg = AppConfig::default();
        cfg.pre_merge_checks.unwrap_usage = CheckMode::Error;
        let filter = FileFilter::from_config(&cfg.filters).expect("filter");

        let mut cli = test_cli();
        cli.ingest = vec![ingest_path.clone()];
        let findings = gather_findings(
            &cli,
            &cfg,
            &filter,
            &diff,
            GatherContext {
                llm_enabled: false,
                base_ref: "HEAD~1",
                review_mode: crate::llm::ReviewMode::Scan,
                comprehensive: false,
            },
        )
        .expect("gather findings");

        let _ = std::fs::remove_file(&ingest_path);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "unwrap-usage" && matches!(f.severity, Severity::Error))
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "ext:gitleaks:aws-access-token")
        );
    }

    #[test]
    fn gather_findings_respects_enable_llm_cli_flag_when_config_disables_llm() {
        let diff_text = r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+fn x() {}
"#;
        let diff = parse_unified_diff(diff_text).expect("parse diff");
        let mut cfg = AppConfig::default();
        cfg.llm.enabled = false;
        cfg.llm.provider = "codex-cli".to_string();
        cfg.llm.cli_command = "sh".to_string();
        cfg.llm.cli_args = vec![
            "-c".to_string(),
            "printf '%s' '{\"findings\":[{\"rule\":\"cli-llm\",\"severity\":\"warning\",\"title\":\"llm title\",\"details\":\"llm details\",\"file\":\"src/lib.rs\",\"line\":1,\"confidence\":0.9,\"suggestion\":null,\"evidence\":[\"line\"]}]}'".to_string(),
        ];
        cfg.llm.agents.clear();
        set_absolute_prompt_pack(&mut cfg);

        let filter = FileFilter::from_config(&cfg.filters).expect("filter");
        let cli = test_cli();
        let findings = gather_findings(
            &cli,
            &cfg,
            &filter,
            &diff,
            GatherContext {
                llm_enabled: true,
                base_ref: "HEAD~1",
                review_mode: crate::llm::ReviewMode::Scan,
                comprehensive: false,
            },
        )
        .expect("gather findings");

        assert!(findings.iter().any(|f| f.rule == "llm:cli-llm"));
    }

    #[test]
    fn run_scan_mode_executes_against_real_repo() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let repo = setup_repo_with_two_commits("scan-mode");
        let _cwd = CwdGuard::push(&repo);

        let mut cli = test_cli();
        cli.base_ref = Some("HEAD~1".to_string());
        cli.output = OutputFormat::Json;
        cli.dry_run = true;

        let cfg = AppConfig::default();
        let filter = FileFilter::from_config(&cfg.filters).expect("filter");
        run_scan_mode(&cli, &cfg, &filter, false).expect("scan mode should succeed");

        drop(_cwd);
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn run_pr_mode_skip_policy_path_succeeds_without_git() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let event_path = unique_temp_file("pr-skip-event", "json");
        write_pr_event(&event_path, "opened", false, false);

        let _set_event_path =
            EnvGuard::set("GITHUB_EVENT_PATH", event_path.to_string_lossy().as_ref());
        let _set_repo = EnvGuard::set("GITHUB_REPOSITORY", "owner/repo");
        let _set_token = EnvGuard::set("GITHUB_TOKEN", "token");

        let mut cfg = AppConfig::default();
        cfg.reviews.auto_review.enabled = false;
        let filter = FileFilter::from_config(&cfg.filters).expect("filter");
        let mut cli = test_cli();
        cli.dry_run = true;

        run_pr_mode(&cli, &cfg, &filter, false).expect("skip policy should short-circuit");
        let _ = std::fs::remove_file(&event_path);
    }

    #[test]
    fn run_pr_mode_dry_run_executes_against_real_repo() {
        let _lock = crate::test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let repo = setup_repo_with_two_commits("pr-mode");
        let _cwd = CwdGuard::push(&repo);

        let event_path = unique_temp_file("pr-event", "json");
        write_pr_event(&event_path, "opened", false, false);
        let _set_event_path =
            EnvGuard::set("GITHUB_EVENT_PATH", event_path.to_string_lossy().as_ref());
        let _set_repo = EnvGuard::set("GITHUB_REPOSITORY", "owner/repo");
        let _set_token = EnvGuard::set("GITHUB_TOKEN", "token");

        let mut cli = test_cli();
        cli.base_ref = Some("HEAD~1".to_string());
        cli.output = OutputFormat::Markdown;
        cli.dry_run = true;
        cli.post_inline = Some(false);

        let cfg = AppConfig::default();
        let filter = FileFilter::from_config(&cfg.filters).expect("filter");
        run_pr_mode(&cli, &cfg, &filter, false).expect("pr mode should run in dry-run");

        let _ = std::fs::remove_file(&event_path);
        drop(_cwd);
        let _ = std::fs::remove_dir_all(&repo);
    }
}
