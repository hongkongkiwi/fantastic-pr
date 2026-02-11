# Fantastic PR (Rust)

A PR review bot in Rust focused on two surfaces only:

- Local CLI / skill workflows
- GitHub pull requests

## Quick start (5 minutes)

### Prerequisites

- Rust stable toolchain (`cargo`, `rustc`)
- `git`
- Optional for security lane: `python3`, `jq` (the bundled GitHub workflow installs scanner tools)

### Install

From this repository root:

```bash
cargo install --path .
```

Then verify:

```bash
fantastic-pr --help
```

If you prefer not to install globally, run from source with `cargo run -- <command>`.
Example: `cargo run -- scan --base-ref origin/main`.

### Run your first local scan (no config required)

From the repository you want to review:

```bash
fantastic-pr scan --base-ref origin/main
```

Notes:
- If `--base-ref` is omitted, Fantastic PR tries `origin/main`, then `origin/master`.
- Built-in defaults are used when `.fantastic-pr.yaml` is missing.

### Enable LLM in one command

```bash
export OPENAI_API_KEY=your_key_here
fantastic-pr scan --base-ref origin/main --set llm.enabled=true
```

No prompt-pack file setup is required for default prompt paths; built-in prompt content is used automatically when `prompts/...` files are absent.

### Add to GitHub Actions

1. Copy `.github/workflows/fantastic-pr.yml` into your repo at `.github/workflows/fantastic-pr.yml`.
2. Commit and push.
3. Optional: set repository variable `FANTASTIC_PR_INCLUDE_DRAFTS=true` if you want runs on draft PRs.
4. Optional: add provider API secrets (for LLM-enabled jobs), then pass `--set llm.enabled=true` and provider settings in workflow commands.

By default, workflow jobs run only for active PRs (not draft/closed), and fork PRs run in non-publishing mode.

## Usage map

- `scan`: local diff scan and output to terminal/file.
- `pr`: GitHub PR review mode (report upsert + optional inline comments).
- `auto`: picks `pr` when GitHub env vars are present, else `scan`.
- `validate-config`: validates merged config and exits.
- `migrate-config`: rewrites config into normalized YAML.
- `probe-provider`: probes configured LLM provider and output contract.
- `mcp`: starts MCP stdio server with Fantastic PR tools.

## Just commands (recommended)

If you use [`just`](https://github.com/casey/just), this repo includes a comprehensive `Justfile`.

Discover commands:

```bash
just
```

Core commands:

```bash
just ci
just fmt
just fmt-check
just check
just clippy
just test
just validate-config
```

Run scans:

```bash
just scan
just scan base_ref=origin/main output=json
just scan-llm base_ref=origin/main provider=openai-api
just scan-sarif base_ref=origin/main out=fantastic-pr.sarif
just scan-skill base_ref=origin/main out=rfa/fantastic-pr.md
```

LLM/provider and MCP:

```bash
just probe-provider
just pr base_ref=origin/main
just mcp
```

Security workflow commands:

```bash
just security-install-checkov
just security-install-gitleaks
just security-scan base_ref=origin/main fail_on=high
```

Workflow lint:

```bash
just workflow-lint
```

## Open-source references we learned from

From prior open-source reviewer research:

- `pr-agent-rs`: inline review API usage, fallback comment publishing, and config layering ideas.
- `kodiai`: output idempotency markers.
- `review-for-agent`: local agent-friendly markdown workflow.
- council-style reviewer projects: severity framing and review-gating patterns.
- `github-pr-review-mcp-server`: local tool ergonomics.

## Modes

- `pr`: scans PR diff and posts/upserts GitHub comments.
- `scan`: local CLI mode; emits markdown/json/skill/sarif.
- `auto`: PR mode when GitHub env vars are present, otherwise scan mode.
- `mcp`: starts an MCP stdio server that exposes Fantastic PR as tools.

## Capabilities

- Deterministic changed-line checks.
- Inline comments + per-finding idempotent markers across PR updates (no duplicate reposts on new head SHAs).
- Native GitHub suggestion blocks for applicable findings.
- Inline comments are restricted to changed diff lines only.
- Optional LLM review pass with chunked prompt budgeting.
- Configurable multi-agent LLM pipeline (`general`, `security`, `maintainability`) with merge/dedupe reducer before publishing.
- Internal multi-model SDK providers: `openai-api`, `anthropic-api`, `gemini-api`, `openai-compatible`.
- Optional CLI adapter providers: `codex-cli`, `claude-code`, `kimi-cli`, `qwen-cli`, `gemini-cli`, `opencode-cli`.
- Ordered fallback attempts across models/providers.
- Prompt-pack architecture (`prompts/core_system.txt`, `prompts/mode_*.txt`, `prompts/output_contract.json`).
- Official MCP stdio server mode via `rmcp` (Model Context Protocol Rust SDK).
- External tool ingestion (SARIF, ESLint JSON, Semgrep JSON, Checkov JSON, Gitleaks JSON, Clippy JSON lines).
- Configurable file filtering via globs and `.fantastic-prignore`.
- Baseline suppression (`only new findings`) with optional baseline refresh.
- SARIF export and GitHub code-scanning upload workflow.
- IaC/security profile with stricter checks and severity gating.
- GitHub Actions runs as two lanes: `PR Review (Diff)` and `Security Scan (Repo)`.

## Configuration precedence

1. Built-in defaults
2. Repo YAML (`.fantastic-pr.yaml`)
3. Env overrides (`FANTASTIC_PR_CFG_*`)
4. CLI overrides (`--set key=value`)

Schema file: `config/fantastic-pr.schema.json`.
Config decoding is strict: unknown top-level or nested keys fail validation/load.

## Minimal configuration recipes

Deterministic checks only (no config file needed):

```bash
fantastic-pr scan --base-ref origin/main
```

Minimal LLM config (`.fantastic-pr.yaml`):

```yaml
llm:
  enabled: true
  provider: openai-api
  model: gpt-4.1-mini
  api_key_env: OPENAI_API_KEY
```

Minimal CLI-provider config:

```yaml
llm:
  enabled: true
  provider: codex-cli
```

Security-focused profile on demand (no file changes):

```bash
fantastic-pr scan --base-ref origin/main --set profile=iac --fail-on high
```

Optional inheritance in YAML:

```yaml
inheritance: true
extends: .fantastic-pr.parent.yaml
```

Merge semantics:
- Objects deep-merge.
- Scalars use child value.
- Arrays use child-first order with parent deduped append.

Examples:

```bash
FANTASTIC_PR_CFG_LLM__ENABLED=true cargo run -- scan
cargo run -- scan --set llm.max_chunks=6 --set checks.debug_statements=false
```

Config utility commands:

```bash
# Validate config file
cargo run -- validate-config

# Normalize/write config to Fantastic PR YAML
cargo run -- migrate-config --from .fantastic-pr.yaml --to .fantastic-pr.yaml
```

## Profiles

Use `profile=iac` to enable an opinionated IaC/security review mode:

- Enables IaC misconfiguration checks.
- Keeps secret detection enabled.
- Reduces non-security noise checks in this mode.
- Pairs well with `--fail-on high` or `--fail-on critical`.

Examples:

```bash
cargo run -- scan --set profile=iac --fail-on high
FANTASTIC_PR_CFG_PROFILE=iac cargo run -- pr --base-ref origin/main --fail-on critical
```

Use `profile=council` for a stricter security-focused policy preset:

- Raises key security checks to pre-merge `error` mode.
- Raises default LLM confidence floor to at least `0.75`.
- Keeps signal focused by disabling noisy `large_pr` enforcement in this profile.

Example:

```bash
cargo run -- pr --set profile=council --base-ref origin/main --fail-on critical
```

## LLM backend configuration

### Internal SDK (recommended)

### OpenAI-compatible API

```yaml
llm:
  enabled: true
  provider: openai-api
  base_url: https://api.openai.com/v1
  model: gpt-4.1-mini
  api_key_env: OPENAI_API_KEY
```

### Anthropic API

```yaml
llm:
  enabled: true
  provider: anthropic-api
  base_url: https://api.anthropic.com/v1
  model: claude-3-7-sonnet-latest
  api_key_env: ANTHROPIC_API_KEY
```

### Gemini API

```yaml
llm:
  enabled: true
  provider: gemini-api
  base_url: https://generativelanguage.googleapis.com/v1beta
  model: gemini-2.5-pro
  api_key_env: GEMINI_API_KEY
```

### OpenAI-compatible gateway

```yaml
llm:
  enabled: true
  provider: openai-compatible
  base_url: https://your-gateway.example.com/v1
  model: your-model-id
  api_key_env: OPENAI_API_KEY
```

### External CLI adapters (optional)

### Codex CLI backend

```yaml
llm:
  enabled: true
  provider: codex-cli
  cli_command: codex
  cli_args: ["exec", "--json", "-"]
```

### Claude Code backend

```yaml
llm:
  enabled: true
  provider: claude-code
  cli_command: claude
  cli_args: ["-p", "{prompt}"]
```

### Kimi CLI backend

```yaml
llm:
  enabled: true
  provider: kimi-cli
  cli_command: kimi
  cli_args: ["chat", "--json"]
```

### Qwen CLI backend

```yaml
llm:
  enabled: true
  provider: qwen-cli
  cli_command: qwen
  cli_args: ["chat", "--json"]
```

### Gemini CLI backend

```yaml
llm:
  enabled: true
  provider: gemini-cli
  cli_command: gemini
  cli_args: ["-p", "{prompt}"]
```

### OpenCode CLI backend

```yaml
llm:
  enabled: true
  provider: opencode-cli
  cli_command: opencode
  cli_args: ["run", "--json"]
```

Notes:
- CLI adapters pass prompt by stdin unless `llm.cli_args` uses `{prompt}`.
- If `llm.cli_args` is not set, provider-specific safe defaults are used.
- `llm.provider_timeout_secs` controls provider process/API timeout (default `90`).
- `llm.min_confidence` filters weak LLM findings and requires numeric confidence on every LLM finding (default `0.65`).
- `llm.pr_changed_lines_only=true` enforces PR-mode findings on changed lines only.
- You can use `{prompt}` and `{model}` placeholders in `llm.cli_args`.
- Internal SDK adapters are preferred for deterministic CI behavior and strict output validation.

### Multi-agent review configuration

Use `llm.agents` to run multiple specialized review agents and merge/dedupe findings:

```yaml
llm:
  enabled: true
  provider: openai-api
  model: gpt-4.1-mini
  agents:
    - name: general
      enabled: true
      focus: Find correctness and reliability regressions.
      prompt_file: prompts/agents/general.txt
      provider: null
      model: null
      min_confidence: null
    - name: security
      enabled: true
      focus: Focus on secrets, auth boundaries, and data exposure.
      prompt_file: prompts/agents/security.txt
      provider: null
      model: null
      min_confidence: 0.75
    - name: maintainability
      enabled: true
      focus: Focus on testability and complexity hazards.
      prompt_file: prompts/agents/maintainability.txt
      provider: null
      model: null
      min_confidence: null
```

Behavior:
- Only `enabled: true` agents run.
- Each agent can optionally override `provider`, `model`, and `min_confidence`.
- Findings are merged and deduped by root-cause location/title; higher severity then higher confidence wins.
- Output rules are tagged as `llm:<agent>:<rule>` when `llm.agents` is configured.

### Configurable LLM Workflow Strategies

Choose how candidate findings are combined before publishing:

```yaml
llm:
  workflow_strategy: merge # merge | consensus | judge | judge-consensus | debate | critique-revise
  consensus_min_support: 2
  judge_model: gpt-4.1
  judge_prompt_file: prompts/workflows/judge.txt
  judge_max_candidates: 40
  debate_prompt_file: prompts/workflows/debate.txt
  critique_revise_prompt_file: prompts/workflows/critique_revise.txt
```

Strategies:
- `merge` (default): current multi-agent merge/dedupe behavior.
- `consensus`: keeps findings only when at least `consensus_min_support` agents independently report them.
- `judge`: runs an adjudicator pass over merged candidates and keeps only judge-selected findings.
- `judge-consensus`: applies consensus first, then judge adjudication.
- `debate`: two-stage adjudication (proposal, then challenge/rebuttal pass) over the same candidate set.
- `critique-revise`: draft shortlist pass, then critique-and-revise pass for tighter final output.

Judge notes:
- Judge output must still satisfy the strict findings JSON envelope.
- Judge selection is constrained to supplied candidate findings.
- If judge provider attempts fail, Fantastic PR falls back to pre-judge findings.
- Adjudication prompts (`judge`, `debate`, `critique-revise`) are bounded by `llm.max_prompt_chars`; candidate lists are truncated deterministically when needed.

CLI override examples:

```bash
cargo run -- pr --set llm.workflow_strategy=consensus --set llm.consensus_min_support=2
cargo run -- pr --set llm.workflow_strategy=judge --set llm.judge_model=gpt-4.1
cargo run -- pr --set llm.workflow_strategy=debate
cargo run -- pr --set llm.workflow_strategy=critique-revise
```

## Prompt pack

Default files:

- `prompts/core_system.txt`
- `prompts/mode_pr.txt`
- `prompts/mode_scan.txt`
- `prompts/output_contract.json`
- `prompts/agents/general.txt`
- `prompts/agents/security.txt`
- `prompts/agents/maintainability.txt`
- `prompts/workflows/judge.txt`
- `prompts/workflows/debate.txt`
- `prompts/workflows/critique_revise.txt`

If these default files are not present in the current working repo, Fantastic PR automatically
falls back to embedded built-in prompt content for those exact default paths. This keeps
basic LLM usage working without requiring a repo-local prompt pack.

Override via config:

```yaml
llm:
  prompt_core_file: prompts/core_system.txt
  prompt_pr_file: prompts/mode_pr.txt
  prompt_scan_file: prompts/mode_scan.txt
  prompt_output_contract_file: prompts/output_contract.json
```

Fallback strategy:

```yaml
llm:
  provider: openai-api
  model: gpt-4.1
  fallback_models: ["gpt-4.1-mini", "gpt-4o-mini"]
  fallback_providers: ["anthropic-api:claude-3-7-sonnet-latest", "gemini-api:gemini-2.5-pro", "opencode-cli"]
  provider_timeout_secs: 90
  min_confidence: 0.65
  pr_changed_lines_only: true
```

`fallback_providers` also supports provider-specific model hints:

```yaml
llm:
  fallback_providers: ["gemini-cli:gemini-2.5-pro", "kimi-cli:kimidev-72b-32k"]
```

## Filtering

- `filters.include_globs`: optional allow-list globs.
- `filters.exclude_globs`: deny-list globs.
- `filters.ignore_file`: extra ignore patterns file (default `.fantastic-prignore`).

`.fantastic-prignore` supports one glob per line, comments with `#`.

## Review policy

- `reviews.auto_review` controls when PR mode runs:
  - `enabled`, `include_drafts`
  - label allow/deny lists
  - title keyword filters
  - base branch allow list
  - username ignore list
- `reviews.path_instructions` adds path-scoped review guidance into the LLM system prompt when matching files are changed.

Example:

```yaml
reviews:
  auto_review:
    enabled: true
    include_drafts: false
    exclude_labels: [skip-review]
    ignore_usernames: [dependabot[bot]]
  path_instructions:
    - name: infra
      paths: [".github/workflows/**", "**/*.tf", "**/*.tfvars"]
      instructions: Focus on IAM least privilege and public exposure controls.
```

## Pre-merge checks

`pre_merge_checks` supports per-check modes:

- `off`: disable check output
- `warning`: force minimum warning severity
- `error`: force minimum error severity
- `inherit`: keep the check's native severity

Example:

```yaml
pre_merge_checks:
  unwrap_usage: error
  todo_comments: off
```

## Tool registry

Use `tools.*` for config-driven ingest paths (in addition to `--ingest`):

```yaml
tools:
  checkov:
    enabled: true
    paths: [checkov-report.json]
  gitleaks:
    enabled: true
    paths: [gitleaks-report.json]
```

## Baseline suppression

Use baseline to suppress known findings and fail only on new ones.

When `baseline.update=true` (or `--update-baseline`) is used together with baseline suppression,
Fantastic PR updates the baseline and skips suppression for that same run to avoid suppressing all
freshly written entries immediately.

```bash
# Create/update baseline from current findings
cargo run -- scan --update-baseline --baseline-file .fantastic-pr-baseline.json

# Apply baseline suppression
cargo run -- scan --baseline-enabled true --baseline-file .fantastic-pr-baseline.json
```

## External ingest

```bash
cargo run -- scan --ingest eslint-report.json --ingest semgrep.json --ingest clippy.jsonl
```

Ingest behavior is fail-closed:
- Recognized formats that fail to parse will fail the run.
- Unknown non-empty ingest files will fail the run.
- Missing configured ingest paths will fail the run.

Supported formats:

- SARIF 2.1.0
- ESLint JSON
- Semgrep JSON
- Checkov JSON (`results.failed_checks`)
- Gitleaks JSON reports
- Rust/Clippy JSON lines (`compiler-message`)

Typical security scan ingest:

```bash
checkov -d . -o json --soft-fail > checkov-report.json
gitleaks detect --source . --report-format json --report-path gitleaks-report.json --no-git --exit-code 0
cargo run -- scan --set profile=iac --ingest checkov-report.json --ingest gitleaks-report.json --fail-on high
```

## SARIF output

Scan mode:

```bash
cargo run -- scan --output sarif --output-file fantastic-pr.sarif
```

Any mode additional artifact:

```bash
cargo run -- pr --emit-sarif fantastic-pr.sarif
```

Workflow uploads SARIF via `github/codeql-action/upload-sarif@v3`.

## MCP stdio mode

Run Fantastic PR as an MCP stdio server:

```bash
cargo run -- mcp
```

Exposed MCP tools:

- `fantastic_pr_scan`
- `fantastic_pr_validate_config`
- `fantastic_pr_probe_provider`
- `fantastic_pr_migrate_config`

Each tool executes the matching CLI subcommand and returns structured output including command, exit status, stdout, and stderr.

## Skill mode

The repo ships a reusable skill entry at `skills/fantastic-pr/SKILL.md` for local agent workflows.

## Typical commands

PR review with inline comments:

```bash
cargo run --release -- pr --base-ref origin/main
```

Local skill output:

```bash
cargo run -- scan --output skill --output-file rfa/fantastic-pr.md
```

Gate CI on warnings:

```bash
cargo run -- scan --output json --fail-on warning
```

Gate on high/critical severity only:

```bash
cargo run -- scan --set profile=iac --fail-on high
```

Probe provider wiring:

```bash
cargo run -- probe-provider --set llm.enabled=true --set llm.provider=anthropic-api --set llm.base_url=https://api.anthropic.com/v1 --set llm.model=claude-3-7-sonnet-latest --set llm.api_key_env=ANTHROPIC_API_KEY
```

Enable LLM pass with provider override:

```bash
cargo run -- scan --set llm.enabled=true --set llm.provider=codex-cli
```

Probe provider wiring before a full review:

```bash
cargo run -- probe-provider --set llm.enabled=true --set llm.provider=kimi-cli --set llm.cli_command=kimi --set llm.cli_args=chat,--json
```

## Exit behavior and gating

Use `--fail-on` to control non-zero exit conditions:

- `none`: never fail based on findings
- `warning`: fail on warning/error/critical
- `error`: fail on error/critical
- `high`: fail on high/critical equivalent (`error`/`critical` severities)
- `critical`: fail only on critical

This is the primary control for CI pass/fail behavior.

## GitHub Actions usage details

Workflow file: `.github/workflows/fantastic-pr.yml`

Behavior:
- `PR Review (Diff)` posts/upserts PR report and optional inline comments.
- `Security Scan (Repo)` runs Checkov and Gitleaks, ingests their outputs, and uploads SARIF.
- Workflow command execution is routed through `Justfile` recipes to keep local and CI behavior aligned.
- Debug artifacts are uploaded automatically when review/scan execution fails and debug artifact output exists.
- Permissions are least-privilege by default and elevated only per job where needed.
- Gitleaks binary download is checksum-verified before execution.

If you maintain your own workflow, keep those same safety properties.

## Notes

- If provider execution fails, deterministic and ingested checks still run.
- Baseline suppression happens after all finding sources are merged.
- PR scope policy defaults to expanded on `opened` and diff-only on `synchronize`; configure in `[scope]`.
- Failed LLM attempt artifacts are written to `fantastic-pr-debug/` only when `debug.upload_failed_provider_artifacts=true`.
- Workflow lane split: `PR Review (Diff)` comments on PR and enforces diff-focused quality checks; `Security Scan (Repo)` runs Checkov + Gitleaks ingest with `profile=iac` and `--fail-on high`.
- Fork PRs run in non-publishing mode (`--dry-run --post-inline=false`) to avoid write-token failures while preserving analysis and gating.
- By default, workflow jobs run only for active PRs (`opened`, `synchronize`, `reopened`, `ready_for_review`) and skip draft/closed states.
- Set repository variable `FANTASTIC_PR_INCLUDE_DRAFTS=true` to include draft PR runs.

## Troubleshooting

- `base ref not provided ... origin/main and origin/master`:
  pass `--base-ref`, or create/fetch a remote tracking branch.
- `OPENAI_API_KEY is required ...`:
  export the provider key env var configured in `llm.api_key_env`.
- `LLM pass skipped ...`:
  deterministic checks still run; inspect provider config, credentials, and prompt overrides.
- No inline comments posted:
  inline comments are intentionally restricted to changed diff lines.

## Backend strategy

- Recommended default: internal API SDK providers (`openai-api`, `anthropic-api`, `gemini-api`, `openai-compatible`).
- Use CLI adapters only as optional fallback where API access is unavailable.
- Why: API providers are easier to harden (timeouts, retries, strict response parsing, confidence/line gating) and are more deterministic in CI than shelling out to external CLIs.
