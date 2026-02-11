# Fantastic PR Review System Audit (2026-02-11)

## Objective

Build a high-signal PR reviewer for GitHub + local CLI workflows with deterministic behavior and strong anti-hallucination guardrails.

## Key decisions

- Use internal API SDK providers as the primary path (`openai-api`, `anthropic-api`, `gemini-api`, `openai-compatible`).
- Use API SDK providers as the only supported provider path.
- Enforce strict JSON output contract and reject malformed responses.
- Gate PR-mode LLM findings to changed lines only.
- Filter low-confidence findings by threshold.

## Why SDK-first

- Better determinism in CI than shelling out to external tools.
- Stronger control over timeout, retries, request/response handling, and error surfaces.
- Easier to enforce consistent prompt contracts and schema validation.
- Cleaner path to future provider features (tool-calls, structured outputs, model-specific tuning).

## Current hardening status

- Strict envelope validation: implemented.
- Prompt injection resistance: implemented in core prompt.
- Changed-line-only PR findings: implemented.
- Confidence threshold gate: implemented.
- File-aware prompt chunking with budget truncation: implemented.
- Provider/model fallback chain: implemented.
- GitHub inline idempotency marker: implemented.

## Remaining high-value work

- Add provider-specific retry policy with backoff and retryable status classification.
- Add optional per-language review rules and language-specific prompt slices.
- Add offline replay fixtures for provider responses to test parser robustness across vendors.
- Add explicit token budgeting by model family (chars->tokens heuristic profile per provider).
