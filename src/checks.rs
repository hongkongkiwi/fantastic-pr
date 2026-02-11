use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;

use crate::config::AppConfig;
use crate::diff::{DiffData, FileSnapshot};
use crate::filtering::FileFilter;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Error => "ERROR",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn from_label(value: &str) -> Option<Self> {
        match value.to_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "warn" | "warning" => Some(Severity::Warning),
            "error" => Some(Severity::Error),
            "critical" | "high" => Some(Severity::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: String,
    pub title: String,
    pub details: String,
    pub severity: Severity,
    pub file: Option<String>,
    pub line: Option<usize>,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InlineComment {
    pub rule: String,
    pub path: String,
    pub line: usize,
    pub body: String,
}

pub fn run_checks(
    config: &AppConfig,
    diff: &DiffData,
    filter: &FileFilter,
) -> anyhow::Result<Vec<Finding>> {
    let todo_re = Regex::new(r"(?i)\b(todo|fixme|xxx)\b")?;
    let debug_re = Regex::new(
        r"\b(dbg!\s*\(|println!\s*\(|eprintln!\s*\(|console\.log\s*\(|fmt\.Print(?:ln|f)?\s*\(|printStackTrace\s*\()",
    )?;
    let aws_key_re = Regex::new(r"\bAKIA[0-9A-Z]{16}\b")?;
    let generic_secret_re =
        Regex::new(r#"(?i)\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*["'][^"']{8,}["']"#)?;
    let unwrap_re = Regex::new(r"\.unwrap\s*\(\s*\)")?;
    let iac_open_cidr_re = Regex::new(r#"(?i)\b(cidr_blocks?|source_ranges?)\b.*0\.0\.0\.0/0"#)?;
    let iac_public_re =
        Regex::new(r#"(?i)\b(publicly_accessible|public_network_access_enabled)\s*=\s*true"#)?;
    let iac_privileged_re =
        Regex::new(r"(?i)\b(privileged|allowPrivilegeEscalation|hostNetwork)\s*:\s*true")?;
    let iac_root_re = Regex::new(r"(?i)\brunAsUser\s*:\s*0\b")?;
    let iac_latest_tag_re = Regex::new(r#"(?i)\bimage\s*:\s*[^ \t\n]+:latest\b"#)?;

    let mut findings: Vec<Finding> = Vec::new();

    if config.checks.todo_comments {
        for line in &diff.added_lines {
            if !filter.is_reviewable_file(&line.file) {
                continue;
            }
            if todo_re.is_match(&line.content) {
                findings.push(Finding {
                    rule: "todo-comments".to_string(),
                    title: "TODO/FIXME comment introduced".to_string(),
                    details: "Avoid shipping unresolved TODO/FIXME markers in PR changes."
                        .to_string(),
                    severity: Severity::Info,
                    file: Some(line.file.clone()),
                    line: Some(line.line),
                    suggestion: None,
                });
            }
        }
    }

    if config.checks.debug_statements {
        for line in &diff.added_lines {
            if !filter.is_reviewable_file(&line.file) {
                continue;
            }
            if debug_re.is_match(&line.content) {
                findings.push(Finding {
                    rule: "debug-statements".to_string(),
                    title: "Debug statement introduced".to_string(),
                    details:
                        "Remove debug logging before merge unless it is intentionally permanent."
                            .to_string(),
                    severity: Severity::Warning,
                    file: Some(line.file.clone()),
                    line: Some(line.line),
                    suggestion: None,
                });
            }
        }
    }

    if config.checks.secret_patterns {
        for line in &diff.added_lines {
            if !filter.is_reviewable_file(&line.file) {
                continue;
            }
            if aws_key_re.is_match(&line.content) || generic_secret_re.is_match(&line.content) {
                findings.push(Finding {
                    rule: "secret-patterns".to_string(),
                    title: "Potential secret detected".to_string(),
                    details:
                        "A secret-like pattern was added. Confirm no credentials are committed."
                            .to_string(),
                    severity: Severity::Error,
                    file: Some(line.file.clone()),
                    line: Some(line.line),
                    suggestion: None,
                });
            }
        }
    }

    if config.checks.unsafe_rust {
        for line in &diff.added_lines {
            if !filter.is_reviewable_file(&line.file) {
                continue;
            }
            if line.file.ends_with(".rs") && line.content.contains("unsafe") {
                findings.push(Finding {
                    rule: "unsafe-rust".to_string(),
                    title: "Unsafe Rust usage added".to_string(),
                    details: "New `unsafe` code should include rationale and safety invariants in review notes."
                        .to_string(),
                    severity: Severity::Warning,
                    file: Some(line.file.clone()),
                    line: Some(line.line),
                    suggestion: None,
                });
            }
        }
    }

    if config.checks.unwrap_usage {
        for line in &diff.added_lines {
            if !filter.is_reviewable_file(&line.file) {
                continue;
            }
            if line.file.ends_with(".rs")
                && unwrap_re.is_match(&line.content)
                && !is_test_path(&line.file)
            {
                findings.push(Finding {
                    rule: "unwrap-usage".to_string(),
                    title: "`unwrap()` introduced in non-test code".to_string(),
                    details: "Prefer proper error handling or `expect()` with clear context."
                        .to_string(),
                    severity: Severity::Info,
                    file: Some(line.file.clone()),
                    line: Some(line.line),
                    suggestion: Some(
                        line.content
                            .replace(".unwrap()", ".expect(\"handle error context\")"),
                    ),
                });
            }
        }
    }

    if config.checks.iac_misconfig {
        for line in &diff.added_lines {
            if !filter.is_reviewable_file(&line.file) || !is_iac_path(&line.file) {
                continue;
            }

            if iac_open_cidr_re.is_match(&line.content) || iac_public_re.is_match(&line.content) {
                findings.push(Finding {
                    rule: "iac-open-network".to_string(),
                    title: "Potentially public IaC configuration".to_string(),
                    details: "Detected a broad/public network exposure setting in IaC changes."
                        .to_string(),
                    severity: Severity::Error,
                    file: Some(line.file.clone()),
                    line: Some(line.line),
                    suggestion: None,
                });
            }

            if iac_privileged_re.is_match(&line.content) || iac_root_re.is_match(&line.content) {
                findings.push(Finding {
                    rule: "iac-privileged-workload".to_string(),
                    title: "Privileged workload setting in IaC".to_string(),
                    details:
                        "Detected privileged runtime settings. Confirm this is required and documented."
                            .to_string(),
                    severity: Severity::Warning,
                    file: Some(line.file.clone()),
                    line: Some(line.line),
                    suggestion: None,
                });
            }

            if iac_latest_tag_re.is_match(&line.content) {
                findings.push(Finding {
                    rule: "iac-unpinned-image".to_string(),
                    title: "Container image tag is not pinned".to_string(),
                    details:
                        "Avoid ':latest' in deployment manifests. Pin an immutable version or digest."
                            .to_string(),
                    severity: Severity::Warning,
                    file: Some(line.file.clone()),
                    line: Some(line.line),
                    suggestion: None,
                });
            }
        }
    }

    if config.checks.large_pr && diff.total_added >= config.large_pr_added_lines_threshold {
        findings.push(Finding {
            rule: "large-pr".to_string(),
            title: format!("Large PR detected ({} added lines)", diff.total_added),
            details: format!(
                "Consider splitting into smaller changes. Threshold is {} lines.",
                config.large_pr_added_lines_threshold
            ),
            severity: Severity::Warning,
            file: None,
            line: None,
            suggestion: None,
        });
    }

    if config.checks.missing_tests
        && diff.total_added >= config.missing_tests_added_lines_threshold
        && has_source_changes(diff, filter)
        && !has_test_changes(diff, filter)
    {
        findings.push(Finding {
            rule: "missing-tests".to_string(),
            title: "Code changes without test updates".to_string(),
            details: "Source files changed significantly but no test files were updated."
                .to_string(),
            severity: Severity::Warning,
            file: None,
            line: None,
            suggestion: None,
        });
    }

    Ok(limit_per_rule(
        findings,
        config.max_reported_findings,
        config.max_examples_per_rule,
    ))
}

pub fn run_comprehensive_checks(
    files: &[FileSnapshot],
    filter: &FileFilter,
) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let secret_re =
        Regex::new(r#"(?i)\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*["'][^"']{12,}["']"#)?;

    for file in files {
        if !filter.is_reviewable_file(&file.path) {
            continue;
        }

        let mut long_lines = 0usize;
        for (idx, line) in file.content.lines().enumerate() {
            if line.chars().count() > 140 {
                long_lines += 1;
                if long_lines <= 2 {
                    findings.push(Finding {
                        rule: "long-line".to_string(),
                        title: "Long line (>140 chars) in changed file".to_string(),
                        details: "Comprehensive mode flags long lines for readability review."
                            .to_string(),
                        severity: Severity::Info,
                        file: Some(file.path.clone()),
                        line: Some(idx + 1),
                        suggestion: None,
                    });
                }
            }

            if secret_re.is_match(line) {
                findings.push(Finding {
                    rule: "secret-patterns-comprehensive".to_string(),
                    title: "Potential secret-like assignment in changed file".to_string(),
                    details:
                        "Comprehensive scan saw a secret-like assignment in the full file content."
                            .to_string(),
                    severity: Severity::Warning,
                    file: Some(file.path.clone()),
                    line: Some(idx + 1),
                    suggestion: None,
                });
            }
        }

        if long_lines > 10 {
            findings.push(Finding {
                rule: "many-long-lines".to_string(),
                title: format!("File has many long lines ({long_lines})"),
                details: "Consider formatting or splitting long expressions for maintainability."
                    .to_string(),
                severity: Severity::Info,
                file: Some(file.path.clone()),
                line: None,
                suggestion: None,
            });
        }
    }

    Ok(findings)
}

pub fn as_inline_comments(findings: &[Finding], max_inline: usize) -> Vec<InlineComment> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();

    for finding in findings {
        let (Some(path), Some(line)) = (&finding.file, finding.line) else {
            continue;
        };

        let key = format!("{}:{}:{}", path, line, finding.rule);
        if !seen.insert(key) {
            continue;
        }

        let mut body = format!(
            "[{}] {}\n\n{}\n\nRule: `{}`",
            finding.severity.as_str(),
            finding.title,
            finding.details,
            finding.rule
        );

        if let Some(suggestion) = &finding.suggestion {
            body.push_str("\n\n```suggestion\n");
            body.push_str(suggestion);
            body.push_str("\n```");
        }

        out.push(InlineComment {
            rule: finding.rule.clone(),
            path: path.clone(),
            line,
            body,
        });

        if out.len() >= max_inline {
            break;
        }
    }

    out
}

fn has_source_changes(diff: &DiffData, filter: &FileFilter) -> bool {
    diff.files.keys().any(|path| filter.is_source_file(path))
}

fn has_test_changes(diff: &DiffData, filter: &FileFilter) -> bool {
    diff.files
        .keys()
        .any(|path| filter.is_allowed_path(path) && is_test_path(path))
}

fn is_test_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower == "tests"
        || lower.starts_with("tests/")
        || lower.contains("/tests/")
        || lower.contains("/__tests__/")
        || lower.starts_with("__tests__/")
        || lower.ends_with("_test.rs")
        || lower.ends_with("_test.go")
        || lower.ends_with(".test.ts")
        || lower.ends_with(".test.tsx")
        || lower.ends_with(".test.js")
        || lower.ends_with(".spec.ts")
        || lower.ends_with(".spec.tsx")
        || lower.ends_with(".spec.js")
}

fn is_iac_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".tf")
        || lower.ends_with(".tfvars")
        || lower.ends_with(".hcl")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
        || lower.contains("/helm/")
        || lower.contains("/k8s/")
        || lower.contains("/manifests/")
        || lower.ends_with("dockerfile")
        || lower.contains(".github/workflows/")
}

fn limit_per_rule(findings: Vec<Finding>, max_total: usize, max_per_rule: usize) -> Vec<Finding> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut filtered = Vec::new();

    for finding in findings {
        if filtered.len() >= max_total {
            break;
        }

        let count = counts.entry(finding.rule.clone()).or_insert(0);
        if *count >= max_per_rule {
            continue;
        }

        *count += 1;
        filtered.push(finding);
    }

    filtered
}

pub fn format_markdown(findings: &[Finding], diff: &DiffData, report_marker: &str) -> String {
    if findings.is_empty() {
        return format!(
            "{report_marker}\n## Fantastic PR Report\n\nNo issues found in changed lines.\n\n- Added lines: {}\n- Removed lines: {}\n- Files changed: {}",
            diff.total_added,
            diff.total_removed,
            diff.files.len()
        );
    }

    let mut out = String::new();
    out.push_str(report_marker);
    out.push_str("\n## Fantastic PR Report\n\n");
    out.push_str(&format!(
        "Found **{}** potential issue(s).\n\n",
        findings.len()
    ));
    out.push_str(&format!(
        "- Added lines: {}\n- Removed lines: {}\n- Files changed: {}\n\n",
        diff.total_added,
        diff.total_removed,
        diff.files.len()
    ));

    out.push_str("| Severity | Rule | Location | Finding |\n");
    out.push_str("| --- | --- | --- | --- |\n");
    for finding in findings {
        let location = match (&finding.file, finding.line) {
            (Some(file), Some(line)) => format!("`{}:{}`", file, line),
            (Some(file), None) => format!("`{}`", file),
            _ => "PR-wide".to_string(),
        };
        out.push_str(&format!(
            "| {} | `{}` | {} | {} |\n",
            finding.severity.as_str(),
            finding.rule,
            location,
            finding.title.replace('|', "\\|"),
        ));
    }

    out.push_str("\n### Notes\n");
    let mut seen = BTreeSet::new();
    for finding in findings {
        if seen.insert(finding.rule.clone()) {
            out.push_str(&format!("- `{}`: {}\n", finding.rule, finding.details));
        }
    }

    out
}

pub fn format_skill_markdown(findings: &[Finding], diff: &DiffData) -> String {
    let mut out = String::new();
    out.push_str("# Fantastic PR Local Review\n\n");
    out.push_str("## Scope\n");
    out.push_str(&format!(
        "- Added lines: {}\n- Removed lines: {}\n- Files changed: {}\n\n",
        diff.total_added,
        diff.total_removed,
        diff.files.len()
    ));

    if findings.is_empty() {
        out.push_str("## Findings\nNo findings detected.\n");
        return out;
    }

    out.push_str("## Findings\n");
    for finding in findings {
        let location = match (&finding.file, finding.line) {
            (Some(file), Some(line)) => format!("{}:{}", file, line),
            (Some(file), None) => file.clone(),
            _ => "PR-wide".to_string(),
        };
        out.push_str(&format!(
            "- [{}] `{}` at `{}`: {}. {}\n",
            finding.severity.as_str(),
            finding.rule,
            location,
            finding.title,
            finding.details
        ));
    }

    out
}

pub fn format_json(findings: &[Finding], diff: &DiffData) -> serde_json::Value {
    serde_json::json!({
        "summary": {
            "added_lines": diff.total_added,
            "removed_lines": diff.total_removed,
            "files_changed": diff.files.len(),
            "findings": findings.len(),
        },
        "findings": findings.iter().map(|f| {
            serde_json::json!({
                "rule": f.rule,
                "title": f.title,
                "details": f.details,
                "severity": f.severity.as_str(),
                "file": f.file,
                "line": f.line,
                "suggestion": f.suggestion,
            })
        }).collect::<Vec<_>>()
    })
}

#[cfg(test)]
mod tests {
    use crate::config::{AppConfig, FilterConfig};
    use crate::diff::{DiffData, FileSnapshot, parse_unified_diff};
    use crate::filtering::FileFilter;

    use super::{
        Finding, Severity, as_inline_comments, format_json, format_markdown, format_skill_markdown,
        run_checks, run_comprehensive_checks,
    };

    #[test]
    fn detects_unwrap_and_missing_tests() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1,2 @@
+fn x() { let _ = Some(1).unwrap(); }
+println!(\"debug\");
"#;

        let parsed = parse_unified_diff(diff).expect("parse ok");
        let config = AppConfig {
            missing_tests_added_lines_threshold: 1,
            ..AppConfig::default()
        };
        let filter = FileFilter::from_config(&FilterConfig::default()).expect("filter build");
        let findings = run_checks(&config, &parsed, &filter).expect("checks ok");

        assert!(findings.iter().any(|f| f.rule == "unwrap-usage"));
        assert!(findings.iter().any(|f| f.rule == "debug-statements"));
        assert!(findings.iter().any(|f| f.rule == "missing-tests"));
        assert!(findings.iter().any(|f| f.severity == Severity::Warning));
    }

    #[test]
    fn top_level_tests_directory_counts_as_test_change() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+fn x() { let _ = Some(1).unwrap(); }
diff --git a/tests/lib.rs b/tests/lib.rs
--- a/tests/lib.rs
+++ b/tests/lib.rs
@@ -1 +1 @@
+#[test] fn covers_x() {}
"#;

        let parsed = parse_unified_diff(diff).expect("parse ok");
        let config = AppConfig {
            missing_tests_added_lines_threshold: 1,
            ..AppConfig::default()
        };
        let filter = FileFilter::from_config(&FilterConfig::default()).expect("filter build");
        let findings = run_checks(&config, &parsed, &filter).expect("checks ok");

        assert!(!findings.iter().any(|f| f.rule == "missing-tests"));
    }

    #[test]
    fn excluded_tests_do_not_suppress_missing_tests_rule() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+fn x() { let _ = Some(1).unwrap(); }
diff --git a/tests/lib.rs b/tests/lib.rs
--- a/tests/lib.rs
+++ b/tests/lib.rs
@@ -1 +1 @@
+#[test] fn covers_x() {}
"#;

        let parsed = parse_unified_diff(diff).expect("parse ok");
        let config = AppConfig {
            missing_tests_added_lines_threshold: 1,
            ..AppConfig::default()
        };
        let filter_cfg = FilterConfig {
            exclude_globs: vec!["tests/**".to_string()],
            ..FilterConfig::default()
        };
        let filter = FileFilter::from_config(&filter_cfg).expect("filter build");
        let findings = run_checks(&config, &parsed, &filter).expect("checks ok");

        assert!(findings.iter().any(|f| f.rule == "missing-tests"));
    }

    #[test]
    fn includes_suggestion_block_for_inline_comment() {
        let diff = r#"diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+fn x() { Some(1).unwrap(); }
"#;

        let parsed = parse_unified_diff(diff).expect("parse ok");
        let filter = FileFilter::from_config(&FilterConfig::default()).expect("filter build");
        let findings = run_checks(&AppConfig::default(), &parsed, &filter).expect("checks ok");
        let inline = as_inline_comments(&findings, 10);

        assert!(inline.iter().any(|c| c.body.contains("```suggestion")));
    }

    #[test]
    fn skips_generated_paths() {
        let diff = r#"diff --git a/dist/app.min.js b/dist/app.min.js
--- a/dist/app.min.js
+++ b/dist/app.min.js
@@ -1 +1 @@
+console.log(\"debug\")
"#;

        let parsed = parse_unified_diff(diff).expect("parse ok");
        let filter = FileFilter::from_config(&FilterConfig::default()).expect("filter build");
        let findings = run_checks(&AppConfig::default(), &parsed, &filter).expect("checks ok");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_iac_misconfig_patterns() {
        let diff = r#"diff --git a/infra/main.tf b/infra/main.tf
--- a/infra/main.tf
+++ b/infra/main.tf
@@ -1 +1,3 @@
+resource "aws_db_instance" "x" { publicly_accessible = true }
+resource "aws_security_group" "x" { cidr_blocks = ["0.0.0.0/0"] }
+image: repo/app:latest
"#;

        let parsed = parse_unified_diff(diff).expect("parse ok");
        let mut config = AppConfig::default();
        config.checks.iac_misconfig = true;
        let filter = FileFilter::from_config(&FilterConfig::default()).expect("filter build");
        let findings = run_checks(&config, &parsed, &filter).expect("checks ok");

        assert!(findings.iter().any(|f| f.rule == "iac-open-network"));
        assert!(findings.iter().any(|f| f.rule == "iac-unpinned-image"));
    }

    #[test]
    fn comprehensive_scan_limits_long_line_examples_and_flags_many_long_lines() {
        let mut content = String::new();
        for idx in 0..11 {
            content.push_str(&format!("const L{idx} = \"{}\";\n", "a".repeat(145)));
        }
        content.push_str("api_key = \"abcdefghijklmnop\"\n");

        let files = vec![FileSnapshot {
            path: "src/lib.rs".to_string(),
            content,
        }];
        let filter = FileFilter::from_config(&FilterConfig::default()).expect("filter build");
        let findings = run_comprehensive_checks(&files, &filter).expect("checks ok");

        let long_line_examples = findings.iter().filter(|f| f.rule == "long-line").count();
        assert_eq!(long_line_examples, 2);
        assert!(findings.iter().any(|f| f.rule == "many-long-lines"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule == "secret-patterns-comprehensive")
        );
    }

    #[test]
    fn inline_comments_are_deduped_and_capped() {
        let findings = vec![
            Finding {
                rule: "r".to_string(),
                title: "t".to_string(),
                details: "d".to_string(),
                severity: Severity::Warning,
                file: Some("src/lib.rs".to_string()),
                line: Some(5),
                suggestion: None,
            },
            Finding {
                rule: "r".to_string(),
                title: "t2".to_string(),
                details: "d2".to_string(),
                severity: Severity::Warning,
                file: Some("src/lib.rs".to_string()),
                line: Some(5),
                suggestion: None,
            },
            Finding {
                rule: "r2".to_string(),
                title: "t3".to_string(),
                details: "d3".to_string(),
                severity: Severity::Warning,
                file: Some("src/lib.rs".to_string()),
                line: Some(6),
                suggestion: None,
            },
        ];

        let deduped = as_inline_comments(&findings, 10);
        assert_eq!(deduped.len(), 2);

        let capped = as_inline_comments(&findings, 1);
        assert_eq!(capped.len(), 1);
    }

    #[test]
    fn markdown_and_json_output_include_expected_fields() {
        let diff = DiffData {
            added_lines: vec![],
            files: std::collections::HashMap::new(),
            total_added: 3,
            total_removed: 1,
        };

        let finding = Finding {
            rule: "rule-x".to_string(),
            title: "Pipe | title".to_string(),
            details: "detail body".to_string(),
            severity: Severity::Error,
            file: Some("src/lib.rs".to_string()),
            line: Some(8),
            suggestion: None,
        };

        let md_empty = format_markdown(&[], &diff, "<!-- marker -->");
        assert!(md_empty.contains("No issues found in changed lines."));

        let md_with_findings =
            format_markdown(std::slice::from_ref(&finding), &diff, "<!-- marker -->");
        assert!(md_with_findings.contains("Pipe \\| title"));
        assert!(md_with_findings.contains("`src/lib.rs:8`"));

        let skill = format_skill_markdown(std::slice::from_ref(&finding), &diff);
        assert!(skill.contains("# Fantastic PR Local Review"));
        assert!(skill.contains("[ERROR]"));

        let json = format_json(std::slice::from_ref(&finding), &diff);
        assert_eq!(json["summary"]["findings"], 1);
        assert_eq!(json["findings"][0]["rule"], "rule-x");
    }
}
