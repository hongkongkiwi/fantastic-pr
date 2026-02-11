# Fantastic PR

Deterministic PR review engine for local CLI and GitHub pull requests, with optional LLM augmentation, strong output guardrails, and SARIF support.

## At A Glance

| Area | What you get |
| --- | --- |
| Deterministic checks | High-signal static checks on changed lines/files |
| PR reviews | Upserted PR report + optional inline comments (idempotent) |
| LLM review | Multi-agent LLM passes with strict JSON validation |
| Security tooling | Ingest Checkov, Gitleaks, SARIF, Semgrep, ESLint, Clippy |
| CI integration | Two-lane workflow template for review + security scan |
| MCP support | Run Fantastic PR as an MCP stdio server; optionally use MCP context from agents |

## Contents

- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [CLI Usage](#cli-usage)
- [Configuration](#configuration)
- [LLM Setup](#llm-setup)
- [Checks, Gating, and Baseline](#checks-gating-and-baseline)
- [GitHub Actions Setup](#github-actions-setup)
- [MCP](#mcp)
- [Just Commands](#just-commands)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Prerequisites

- Rust toolchain (stable)
- Git
- Optional for security lane: Python 3.11+, `jq`

### Install

```bash
cargo install --path .
```

### First local scan (no config required)

```bash
fantastic-pr scan --base-ref origin/main
```

This runs deterministic checks only.

### Optional LLM scan (OpenAI example)

```bash
export OPENAI_API_KEY=your_key
fantastic-pr scan --base-ref origin/main --set llm.enabled=true --set llm.provider=openai-api
```

### Validate config

```bash
fantastic-pr validate-config
```

## Core Concepts

### Terminology

- `profile`: deterministic policy preset (for example `default`, `iac`, `council`).
- `agent`: an LLM reviewer pass/persona (for example `general`, `security`, `maintainability`).
- `workflow strategy`: reducer for multi-agent findings (`merge`, `consensus`, `judge`, etc).

### Modes

| Mode | Purpose |
| --- | --- |
| `scan` | Local diff scan; outputs markdown/json/skill/sarif |
| `pr` | GitHub PR mode (reads event context; can publish comments) |
| `auto` | Uses `pr` in GitHub env, otherwise `scan` |
| `mcp` | Runs Fantastic PR MCP stdio server |
| `validate-config` | Validates merged config |
| `migrate-config` | Rewrites config to normalized YAML |
| `probe-provider` | Verifies provider output contract |

### Output formats

| Output | Description |
| --- | --- |
| `markdown` | Human-readable report |
| `json` | Structured findings payload |
| `both` | Markdown + JSON |
| `skill` | Agent-friendly markdown |
| `sarif` | SARIF for code scanning |

## CLI Usage

### Common commands

```bash
# Local deterministic scan
cargo run -- scan --base-ref origin/main

# Auto-select mode (PR in GitHub env, scan locally)
cargo run -- auto

# Validate merged config
cargo run -- validate-config

# Probe provider wiring
cargo run -- probe-provider --set llm.enabled=true --set llm.provider=anthropic-api --set llm.base_url=https://api.anthropic.com/v1 --set llm.model=claude-3-7-sonnet-latest --set llm.api_key_env=ANTHROPIC_API_KEY
```

### Useful global flags

- `--config PATH`
- `--base-ref REF`
- `--output markdown|json|both|skill|sarif`
- `--output-file PATH`
- `--fail-on none|warning|error|high|critical`
- `--enable-llm true|false`
- `--set key=value` (repeatable)
- `--ingest PATH` (repeatable)
- `--emit-sarif PATH`

## Configuration

Schema: `config/fantastic-pr.schema.json`  
Default file: `.fantastic-pr.yaml`

### Precedence

1. Built-in defaults
2. Repo config file
3. Environment overrides (`FANTASTIC_PR_CFG_*`)
4. CLI overrides (`--set key=value`)

Config parsing is strict (`deny_unknown_fields`): unknown keys fail validation.

### Minimal config examples

Deterministic-only: no config needed.

Minimal LLM config:

```yaml
llm:
  enabled: true
  provider: openai-api
  model: gpt-4.1-mini
  api_key_env: OPENAI_API_KEY
```

### Profiles

| Profile | Intent |
| --- | --- |
| `default` | Balanced defaults |
| `iac` / `security-iac` | IaC/security-focused deterministic policy |
| `council` | Stricter security-focused preset + higher confidence floor |

Example:

```bash
cargo run -- pr --set profile=council --base-ref origin/main --fail-on critical
```

### Normalize/write current config

```bash
cargo run -- migrate-config --from .fantastic-pr.yaml --to .fantastic-pr.yaml
```

## LLM Setup

### Supported providers (API only)

| Provider | Typical base URL | Key env |
| --- | --- | --- |
| `openai-api` | `https://api.openai.com/v1` | `OPENAI_API_KEY` |
| `openai-compatible` | Your gateway URL | `OPENAI_API_KEY` |
| `anthropic-api` | `https://api.anthropic.com/v1` | `ANTHROPIC_API_KEY` |
| `gemini-api` | `https://generativelanguage.googleapis.com/v1beta` | `GEMINI_API_KEY` |

### Fallbacks

```yaml
llm:
  provider: openai-api
  model: gpt-4.1
  fallback_models: ["gpt-4.1-mini", "gpt-4o-mini"]
  fallback_providers: ["anthropic-api:claude-3-7-sonnet-latest", "gemini-api:gemini-2.5-pro"]
```

### Multi-agent configuration

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
      mcp: []
    - name: security
      enabled: true
      focus: Focus on secrets, auth boundaries, and data exposure.
      prompt_file: prompts/agents/security.txt
      provider: null
      model: null
      min_confidence: 0.75
      mcp: []
```

### Workflow strategies

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

### Optional repository skills context (off by default)

When enabled, Fantastic PR reads local `skills/**/SKILL.md` files and injects bounded snippets into agent instructions.

```yaml
llm:
  repo_skills:
    enabled: false
    max_files: 6
    max_chars_per_file: 1600
```

### Optional per-agent MCP context

You can attach MCP sources per agent to pull tool context before provider calls.

#### Stdio transport example

```yaml
llm:
  agents:
    - name: security
      enabled: true
      focus: security
      mcp:
        - name: local-git-tools
          enabled: true
          transport: stdio
          command: uvx
          args: ["mcp-server-git"]
          tool_calls:
            - name: git_status
              arguments:
                repo_path: .
          timeout_secs: 20
          max_tool_result_chars: 4000
```

#### HTTP/SSE transport examples

```yaml
llm:
  agents:
    - name: security
      enabled: true
      focus: security
      mcp:
        - name: vuln-http
          enabled: true
          transport: http
          url: https://mcp.example.com
          auth_header_env: MCP_API_TOKEN
          tool_calls:
            - name: latest_advisories
              arguments: {}
        - name: incidents-sse
          enabled: true
          transport: sse
          url: https://mcp.example.com/sse
          tool_calls:
            - name: recent_incidents
              arguments: {}
```

Notes:

- `mcp[].tool_calls` empty: Fantastic PR fetches and injects available tool names.
- MCP context failures are non-fatal (logged, then skipped).
- `auth_header_env` should point to an env var containing the bearer token value.

## Checks, Gating, and Baseline

### Pre-merge check modes

Each deterministic rule can be set to `off | warning | error | inherit` in `pre_merge_checks`.

### Exit gating

`--fail-on` controls non-zero exit:

- `none`
- `warning`
- `error`
- `high`
- `critical`

### Baseline suppression

```bash
# Create/update baseline from current findings
cargo run -- scan --base-ref origin/main --baseline-enabled true --update-baseline

# Apply baseline suppression
cargo run -- scan --base-ref origin/main --baseline-enabled true
```

## GitHub Actions Setup

Template workflow lives at `examples/workflows/fantastic-pr.yml`.

### Copy into your repo

```bash
mkdir -p .github/workflows
cp examples/workflows/fantastic-pr.yml .github/workflows/fantastic-pr.yml
```

### What the template does

- `Tests & Coverage`
- `PR Review (Diff)`
- `Security Scan (Repo)`

Security lane installs pinned Checkov and Gitleaks, with checksum verification for Gitleaks tarball before execution.

### Draft PR behavior

By default, runs are for active PRs only.  
Set repository variable `FANTASTIC_PR_INCLUDE_DRAFTS=true` to include drafts.

### Fork PR behavior

Fork PR review runs in safe mode (`--dry-run --post-inline=false`) to avoid write-token failures while preserving analysis/gating.

## MCP

### Run Fantastic PR as an MCP server

```bash
cargo run -- mcp
```

Exposed tools:

- `fantastic_pr_scan`
- `fantastic_pr_validate_config`
- `fantastic_pr_probe_provider`
- `fantastic_pr_migrate_config`

## Just Commands

`Justfile` is the recommended developer entry point.

### Core

```bash
just help
just build
just fmt
just check
just test
just ci
```

### Review workflows

```bash
just scan base_ref=origin/main output=markdown
just scan-llm base_ref=origin/main provider=openai-api
just pr-review-ci base_ref=origin/main is_fork=false
just probe-provider
```

### Security workflows

```bash
just security-install-checkov version=3.2.469
just security-install-gitleaks version=8.24.2 out_dir=./.bin
just security-scan base_ref=origin/main fail_on=high
```

### Config workflows

```bash
just validate-config config=.fantastic-pr.yaml
just migrate-config from=.fantastic-pr.yaml to=.fantastic-pr.yaml
```

## Troubleshooting

- `base ref not provided ... origin/main and origin/master`  
  Set `--base-ref` or ensure the remote branch exists/fetched.

- `... is required for provider ...`  
  Export the env var set by `llm.api_key_env`.

- `LLM pass skipped ...`  
  Deterministic checks still ran; inspect provider config, credentials, prompt files, and network reachability.

- No inline comments posted in PR mode  
  Inline comments are restricted to changed diff lines.

## References

- Prompt pack: `prompts/`
- Default config: `.fantastic-pr.yaml`
- Schema: `config/fantastic-pr.schema.json`
- Workflow template: `examples/workflows/fantastic-pr.yml`
- Skill entry: `skills/fantastic-pr/SKILL.md`
