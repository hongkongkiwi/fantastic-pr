# AGENTS.md

## Purpose
This file is the compact operating manual for LLM/code agents working in `fantastic-pr`.
Goal: keep sessions fast, consistent, and safe while minimizing prompt/context bloat.

## Product Scope
- `fantastic-pr` is a Rust PR review engine.
- Supported surfaces only:
  - Local CLI (`scan`, `pr`, `auto`, `validate-config`, `migrate-config`, `probe-provider`, `mcp`)
  - GitHub pull requests (comments + inline review + SARIF upload workflows)
- Not in scope: non-GitHub integrations, hosted web app features.

## Primary Objectives
- High-signal findings with file/line anchors.
- Deterministic baseline checks first.
- Optional LLM augmentation with strict output validation.
- Strong anti-noise and anti-hallucination controls.

## Key Architecture
- `src/main.rs`: CLI, mode routing, orchestration, policy gates.
- `src/config.rs`: config schema, YAML/TOML loading, inheritance merge, overrides.
- `src/diff.rs`: diff parsing + changed-line extraction.
- `src/checks.rs`: deterministic rules, severity model, markdown/json formatting.
- `src/llm.rs`: API provider adapters, prompt chunking, schema validation, gating.
- `src/github.rs`: PR context parsing, upsert report, inline idempotency.
- `src/ingest.rs`: external tool ingest (SARIF/ESLint/Semgrep/Checkov/Gitleaks/Clippy).
- `src/sarif.rs`: findings -> SARIF conversion.
- `src/baseline.rs`: baseline suppress/update.
- `src/filtering.rs`: include/exclude/reviewable file logic.

## Config System (Current)
- Default config: `.fantastic-pr.yaml`
- Schema: `config/fantastic-pr.schema.json`
- Precedence:
  1. Built-in defaults
  2. Repo config file
  3. Env overrides (`FANTASTIC_PR_CFG_*`)
  4. CLI overrides (`--set key=value`)
- Inheritance:
  - Enable with `inheritance: true`
  - Parent path in `extends`
  - Merge semantics: deep object merge, child scalar wins, child-first deduped arrays

## Review Policy Model
- `reviews.auto_review` controls PR run eligibility:
  - `enabled`, `include_drafts`, `labels`, `exclude_labels`, `title_keywords`, `base_branches`, `ignore_usernames`
- `reviews.path_instructions` injects path-specific guidance into LLM system prompt when matching changed files exist.

## LLM Policy Model
- SDK/API providers: `openai-api`, `anthropic-api`, `gemini-api`, `openai-compatible`.
- Multi-agent execution is configured via `llm.agents` (role-specialized passes merged/deduped before publish).
- Optional repository skill-context ingestion via `llm.repo_skills` (default off).
- Optional per-agent MCP context sources via `llm.agents[].mcp` (`stdio`, `http`, `sse`).
- Guardrails:
  - strict JSON envelope validation
  - confidence gate (`llm.min_confidence`)
  - PR changed-line gate (`llm.pr_changed_lines_only`)
  - chunk budgeting (`llm.max_prompt_chars`, `llm.max_chunks`)

## Pre-Merge Checks
- Per-check mode: `off | warning | error | inherit`
- `warning` and `error` can raise severity for matching rules.
- `off` suppresses matching rules.

## Standard Commands
- Format: `cargo fmt`
- Test: `cargo test -q`
- Compile check: `cargo check -q`
- Validate config: `cargo run -- validate-config`
- Rewrite/migrate config:
  - `cargo run -- migrate-config --from .fantastic-pr.yaml --to .fantastic-pr.yaml`
- Scan mode example: `cargo run -- scan --base-ref origin/main`
- PR mode example: `cargo run -- pr --base-ref origin/main`

## GitHub Workflow Notes
- Example workflow template: `examples/workflows/fantastic-pr.yml`
- Two jobs:
  - `PR Review (Diff)`
  - `Security Scan (Repo)`
- Config validation runs in workflow before review/scan jobs.

## Output and Idempotency
- Main PR report uses marker `<!-- fantastic-pr-report -->`.
- Inline review comments use per-finding output-key markers to avoid duplicate reposting across head SHA updates.

## Editing Guidance for Agents
- Prefer minimal, surgical changes over refactors unless requested.
- Keep public behavior deterministic by default.
- Add tests whenever behavior/rules/config semantics change.
- Preserve strict schema validation in `src/llm.rs`.
- Preserve changed-line restrictions for PR inline comments and LLM PR findings.

## Definition of Done (for code changes)
- `cargo fmt` clean.
- `cargo test -q` passing.
- `cargo check -q` passing.
- Docs/config examples updated if behavior changed.
- If config behavior changed: include/adjust tests in `src/config.rs`.

## Common Pitfalls
- Do not bypass schema validation by accepting freeform LLM output.
- Do not emit PR inline comments not anchored to changed lines.
- Do not silently change config precedence semantics.
- Do not add non-GitHub integration scope unless explicitly requested.

## When adding features
- Prefer adding config flags with safe defaults.
- Keep CLI UX consistent with existing flags and env naming.
- If new provider/tool is added, update:
  - `src/config.rs` (schema + overrides)
  - `README.md` examples
  - tests

## References
- Main docs: `README.md`
- Prompt pack: `prompts/`
- Audit notes: `docs/review-system-audit.md`
