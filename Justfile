set shell := ["bash", "-euo", "pipefail", "-c"]

default:
  @just --list

help:
  @just --list

# Install fantastic-pr from the current repo into your cargo bin.
install:
  cargo install --path .

# Build binaries without running.
build:
  cargo build

# Build optimized binaries.
build-release:
  cargo build --release

# Format source.
fmt:
  cargo fmt

# Check formatting only.
fmt-check:
  cargo fmt -- --check

# Type-check and compile quickly.
check:
  cargo check -q

# Lint Rust code.
clippy:
  cargo clippy -q --all-targets

# Run default tests.
test:
  cargo test -q

# Run full test matrix matching CI.
test-all:
  cargo test --all-targets --locked

# Enforce line/region coverage thresholds.
coverage-check:
  cargo llvm-cov --all-targets --summary-only --fail-under-lines 90 --fail-under-regions 88

# Validate merged config (defaults to .fantastic-pr.yaml).
validate-config config=".fantastic-pr.yaml":
  cargo run -- validate-config --config "{{config}}"

# Rewrite config into normalized YAML.
migrate-config from=".fantastic-pr.yaml" to=".fantastic-pr.yaml":
  cargo run -- migrate-config --from "{{from}}" --to "{{to}}"

# Run local diff scan.
scan base_ref="origin/main" output="markdown":
  cargo run -- scan --base-ref "{{base_ref}}" --output "{{output}}"

# Run local scan with LLM enabled via inline overrides.
scan-llm base_ref="origin/main" provider="openai-api":
  cargo run -- scan --base-ref "{{base_ref}}" --set llm.enabled=true --set llm.provider="{{provider}}"

# Emit SARIF output for local scan.
scan-sarif base_ref="origin/main" out="fantastic-pr.sarif":
  cargo run -- scan --base-ref "{{base_ref}}" --output sarif --output-file "{{out}}"

# Emit local agent/skill markdown output.
scan-skill base_ref="origin/main" out="rfa/fantastic-pr.md":
  cargo run -- scan --base-ref "{{base_ref}}" --output skill --output-file "{{out}}"

# Probe configured LLM provider contract.
probe-provider:
  cargo run -- probe-provider

# Run mode auto-selection (PR mode in GitHub env, otherwise scan).
auto:
  cargo run -- auto

# Run GitHub PR review mode (requires GitHub env vars in shell/CI).
pr base_ref="origin/main":
  cargo run --release -- pr --base-ref "{{base_ref}}"

# CI-focused PR review runner that mirrors workflow behavior.
pr-review-ci base_ref="origin/main" is_fork="false":
  extra_flags=(); \
  if [ "{{is_fork}}" = "true" ]; then \
    echo "Fork PR detected: running in dry-run mode to avoid write-token failures."; \
    extra_flags+=(--dry-run --post-inline=false); \
  fi; \
  cargo run --release -- \
    pr \
    --base-ref "{{base_ref}}" \
    --set scope.initial_pr_scope=diff \
    --set scope.sync_scope=diff \
    --set scope.manual_scope=diff \
    "${extra_flags[@]}" \
    --fail-on error \
    --emit-sarif fantastic-pr-pr.sarif

# Start MCP stdio server.
mcp:
  cargo run -- mcp

# Local quality gate used before pushing.
ci:
  cargo fmt -- --check
  cargo check -q
  cargo clippy -q --all-targets
  cargo test -q
  cargo run -- validate-config

# Lint workflow definitions when actionlint is installed.
workflow-lint:
  if command -v actionlint >/dev/null 2>&1; then \
    actionlint .github/workflows/fantastic-pr.yml; \
  else \
    echo "actionlint not installed; skipping"; \
  fi

# Install Checkov version used by CI.
security-install-checkov version="3.2.469":
  python3 -m pip install --upgrade pip
  python3 -m pip install "checkov=={{version}}"

# Install Gitleaks with checksum verification (supply-chain safe).
security-install-gitleaks version="8.24.2" out_dir="./.bin":
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"; \
  arch="$(uname -m)"; \
  case "${os}:${arch}" in \
    linux:x86_64) asset_os="linux"; asset_arch="x64" ;; \
    linux:aarch64|linux:arm64) asset_os="linux"; asset_arch="arm64" ;; \
    darwin:x86_64) asset_os="darwin"; asset_arch="x64" ;; \
    darwin:arm64) asset_os="darwin"; asset_arch="arm64" ;; \
    *) echo "unsupported platform: ${os}/${arch}" >&2; exit 1 ;; \
  esac; \
  archive="gitleaks_{{version}}_${asset_os}_${asset_arch}.tar.gz"; \
  base_url="https://github.com/gitleaks/gitleaks/releases/download/v{{version}}"; \
  mkdir -p "{{out_dir}}"; \
  curl -sSfL "${base_url}/${archive}" -o gitleaks.tar.gz; \
  curl -sSfL "${base_url}/gitleaks_{{version}}_checksums.txt" -o gitleaks_checksums.txt; \
  if command -v sha256sum >/dev/null 2>&1; then \
    grep " ${archive}$" gitleaks_checksums.txt | sha256sum -c -; \
  else \
    grep " ${archive}$" gitleaks_checksums.txt | shasum -a 256 -c -; \
  fi; \
  tar -xzf gitleaks.tar.gz -C "{{out_dir}}" gitleaks; \
  "{{out_dir}}/gitleaks" version

# Run repo security tooling and ingest into Fantastic PR.
security-scan base_ref="origin/main" fail_on="high":
  command -v checkov >/dev/null 2>&1 || { echo "checkov not found"; exit 1; }
  command -v gitleaks >/dev/null 2>&1 || { echo "gitleaks not found"; exit 1; }
  command -v jq >/dev/null 2>&1 || { echo "jq not found"; exit 1; }
  checkov -d . -o json --soft-fail > checkov-report.json
  gitleaks detect --source . --report-format json --report-path gitleaks-report.json --no-git --exit-code 0
  jq -e . checkov-report.json >/dev/null
  jq -e . gitleaks-report.json >/dev/null
  cargo run -- scan --base-ref "{{base_ref}}" --ingest checkov-report.json --ingest gitleaks-report.json --set profile=iac --fail-on "{{fail_on}}" --emit-sarif fantastic-pr-security.sarif
