---
name: fantastic-pr
summary: Run a comprehensive local PR-style review and emit agent-friendly findings.
---

# Fantastic PR Skill

Use this skill when you need a deterministic + optional LLM review of current branch changes.

## Command

```bash
cargo run -- scan --base-ref origin/main --output skill --output-file rfa/fantastic-pr.md
```

## Optional strict gate

```bash
cargo run -- scan --base-ref origin/main --output json --fail-on warning --output-file rfa/fantastic-pr.json
```

## Optional LLM pass

```bash
OPENAI_API_KEY=... cargo run -- scan --base-ref origin/main --enable-llm true --output both --output-file rfa/fantastic-pr-report.txt
```

## Expected output

- `rfa/fantastic-pr.md` for agent-readable markdown findings.
- Optional JSON output for automation gates.
