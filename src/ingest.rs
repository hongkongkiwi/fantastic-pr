use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;
use serde_json::Value;

use crate::checks::{Finding, Severity};
use crate::filtering::FileFilter;

pub fn ingest_external_findings(
    paths: &[PathBuf],
    filter: &FileFilter,
) -> anyhow::Result<Vec<Finding>> {
    let mut out = Vec::new();

    for path in paths {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read ingest file {}", path.display()))?;

        let parsed = parse_path(path, &text, filter)?;
        out.extend(parsed);
    }

    Ok(out)
}

fn parse_path(path: &Path, text: &str, filter: &FileFilter) -> anyhow::Result<Vec<Finding>> {
    if looks_like_sarif(text) {
        return parse_sarif(text, filter)
            .with_context(|| format!("{} detected as SARIF but failed to parse", path.display()));
    }

    if looks_like_eslint(text) {
        return parse_eslint(text, filter).with_context(|| {
            format!(
                "{} detected as ESLint JSON but failed to parse",
                path.display()
            )
        });
    }

    if looks_like_checkov(text) {
        return parse_checkov(text, filter).with_context(|| {
            format!(
                "{} detected as Checkov JSON but failed to parse",
                path.display()
            )
        });
    }

    if looks_like_semgrep(text) {
        return parse_semgrep(text, filter).with_context(|| {
            format!(
                "{} detected as Semgrep JSON but failed to parse",
                path.display()
            )
        });
    }

    if looks_like_gitleaks(text) {
        return parse_gitleaks(text, filter).with_context(|| {
            format!(
                "{} detected as Gitleaks JSON but failed to parse",
                path.display()
            )
        });
    }

    if looks_like_clippy_jsonl(text) {
        return parse_clippy_lines(path, text, filter).with_context(|| {
            format!(
                "{} detected as Clippy JSON lines but failed to parse",
                path.display()
            )
        });
    }

    if text.trim().is_empty() {
        return Ok(Vec::new());
    }

    bail!(
        "unsupported ingest format in {} (expected SARIF, ESLint, Semgrep, Checkov, Gitleaks, or Clippy JSON lines)",
        path.display()
    );
}

fn looks_like_sarif(text: &str) -> bool {
    text.contains("\"version\"") && text.contains("\"runs\"")
}

fn looks_like_eslint(text: &str) -> bool {
    text.trim_start().starts_with('[') && text.contains("\"messages\"")
}

fn looks_like_semgrep(text: &str) -> bool {
    text.contains("\"results\"") && text.contains("\"check_id\"")
}

fn looks_like_checkov(text: &str) -> bool {
    text.contains("\"check_type\"")
        || text.contains("\"failed_checks\"")
        || text.contains("\"check_id\"") && text.contains("\"file_path\"")
}

fn looks_like_gitleaks(text: &str) -> bool {
    text.contains("\"RuleID\"") || text.contains("\"Description\"") && text.contains("\"File\"")
}

fn looks_like_clippy_jsonl(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .any(|line| line.starts_with('{') && line.contains("\"reason\""))
}

#[derive(Debug, Deserialize)]
struct SarifRoot {
    runs: Vec<SarifRun>,
}

#[derive(Debug, Deserialize)]
struct SarifRun {
    results: Option<Vec<SarifResult>>,
}

#[derive(Debug, Deserialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: Option<String>,
    level: Option<String>,
    message: SarifMessage,
    locations: Option<Vec<SarifLocation>>,
}

#[derive(Debug, Deserialize)]
struct SarifMessage {
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: Option<SarifPhysicalLocation>,
}

#[derive(Debug, Deserialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: Option<SarifArtifactLocation>,
    region: Option<SarifRegion>,
}

#[derive(Debug, Deserialize)]
struct SarifArtifactLocation {
    uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: Option<usize>,
}

fn parse_sarif(text: &str, filter: &FileFilter) -> anyhow::Result<Vec<Finding>> {
    let root: SarifRoot = serde_json::from_str(text).context("invalid SARIF input")?;
    let mut out = Vec::new();

    for run in root.runs {
        for result in run.results.unwrap_or_default() {
            let mut file = None;
            let mut line = None;
            if let Some(first) = result.locations.and_then(|mut v| v.drain(..).next())
                && let Some(phys) = first.physical_location
            {
                file = phys.artifact_location.and_then(|a| a.uri);
                line = phys.region.and_then(|r| r.start_line);
            }

            if let Some(path) = &file
                && !filter.is_reviewable_file(path)
            {
                continue;
            }

            out.push(Finding {
                rule: format!(
                    "ext:{}",
                    result.rule_id.unwrap_or_else(|| "sarif-rule".to_string())
                ),
                title: "External tool finding".to_string(),
                details: result
                    .message
                    .text
                    .unwrap_or_else(|| "No message".to_string()),
                severity: map_text_severity(result.level.as_deref()),
                file,
                line,
                suggestion: None,
            });
        }
    }

    Ok(out)
}

#[derive(Debug, Deserialize)]
struct EslintReport {
    #[serde(rename = "filePath")]
    file_path: String,
    messages: Vec<EslintMessage>,
}

#[derive(Debug, Deserialize)]
struct EslintMessage {
    #[serde(rename = "ruleId")]
    rule_id: Option<String>,
    severity: i64,
    message: String,
    line: Option<usize>,
}

fn parse_eslint(text: &str, filter: &FileFilter) -> anyhow::Result<Vec<Finding>> {
    let reports: Vec<EslintReport> = serde_json::from_str(text).context("invalid ESLint JSON")?;
    let mut out = Vec::new();

    for report in reports {
        if !filter.is_reviewable_file(&report.file_path) {
            continue;
        }

        for msg in report.messages {
            out.push(Finding {
                rule: format!(
                    "ext:{}",
                    msg.rule_id.unwrap_or_else(|| "eslint".to_string())
                ),
                title: "External tool finding".to_string(),
                details: msg.message,
                severity: if msg.severity >= 2 {
                    Severity::Error
                } else {
                    Severity::Warning
                },
                file: Some(report.file_path.clone()),
                line: msg.line,
                suggestion: None,
            });
        }
    }

    Ok(out)
}

#[derive(Debug, Deserialize)]
struct SemgrepRoot {
    results: Vec<SemgrepResult>,
}

#[derive(Debug, Deserialize)]
struct SemgrepResult {
    check_id: String,
    path: String,
    start: SemgrepStart,
    extra: SemgrepExtra,
}

#[derive(Debug, Deserialize)]
struct SemgrepStart {
    line: usize,
}

#[derive(Debug, Deserialize)]
struct SemgrepExtra {
    message: String,
    severity: Option<String>,
}

fn parse_semgrep(text: &str, filter: &FileFilter) -> anyhow::Result<Vec<Finding>> {
    let root: SemgrepRoot = serde_json::from_str(text).context("invalid Semgrep JSON")?;
    let mut out = Vec::new();

    for result in root.results {
        if !filter.is_reviewable_file(&result.path) {
            continue;
        }

        out.push(Finding {
            rule: format!("ext:{}", result.check_id),
            title: "External tool finding".to_string(),
            details: result.extra.message,
            severity: map_text_severity(result.extra.severity.as_deref()),
            file: Some(result.path),
            line: Some(result.start.line),
            suggestion: None,
        });
    }

    Ok(out)
}

fn parse_checkov(text: &str, filter: &FileFilter) -> anyhow::Result<Vec<Finding>> {
    let root: Value = serde_json::from_str(text).context("invalid Checkov JSON")?;
    let failed_checks = root
        .get("results")
        .and_then(|v| v.get("failed_checks"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let mut out = Vec::new();
    for item in failed_checks {
        let file = item
            .get("file_path")
            .and_then(|v| v.as_str())
            .map(|s| s.trim_start_matches('/').to_string());
        if let Some(path) = &file
            && !filter.is_allowed_path(path)
        {
            continue;
        }

        let line = item
            .get("file_line_range")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_u64())
            .map(|v| v as usize);

        let rule_id = item
            .get("check_id")
            .and_then(|v| v.as_str())
            .unwrap_or("checkov");
        let title = item
            .get("check_name")
            .and_then(|v| v.as_str())
            .unwrap_or("Checkov finding");
        let details = item
            .get("details")
            .and_then(|v| v.as_str())
            .or_else(|| item.get("guideline").and_then(|v| v.as_str()))
            .unwrap_or("External tool finding");
        let severity = map_text_severity(item.get("severity").and_then(|v| v.as_str()));

        out.push(Finding {
            rule: format!("ext:checkov:{rule_id}"),
            title: "External tool finding".to_string(),
            details: format!("{title}: {details}"),
            severity,
            file,
            line,
            suggestion: None,
        });
    }

    Ok(out)
}

fn parse_gitleaks(text: &str, filter: &FileFilter) -> anyhow::Result<Vec<Finding>> {
    let root: Value = serde_json::from_str(text).context("invalid Gitleaks JSON")?;
    let leaks = if let Some(arr) = root.as_array() {
        arr.clone()
    } else {
        root.get("findings")
            .and_then(|v| v.as_array())
            .cloned()
            .or_else(|| root.get("leaks").and_then(|v| v.as_array()).cloned())
            .unwrap_or_default()
    };

    let mut out = Vec::new();
    for item in leaks {
        let file = item
            .get("File")
            .or_else(|| item.get("file"))
            .and_then(|v| v.as_str())
            .map(|v| v.to_string());
        if let Some(path) = &file
            && !filter.is_allowed_path(path)
        {
            continue;
        }

        let line = item
            .get("StartLine")
            .or_else(|| item.get("start_line"))
            .and_then(|v| v.as_u64())
            .map(|v| v as usize);
        let rule_id = item
            .get("RuleID")
            .or_else(|| item.get("rule_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("gitleaks");
        let desc = item
            .get("Description")
            .or_else(|| item.get("description"))
            .and_then(|v| v.as_str())
            .unwrap_or("Potential secret detected");

        out.push(Finding {
            rule: format!("ext:gitleaks:{rule_id}"),
            title: "Potential secret detected by Gitleaks".to_string(),
            details: desc.to_string(),
            severity: Severity::Critical,
            file,
            line,
            suggestion: None,
        });
    }

    Ok(out)
}

#[derive(Debug, Deserialize)]
struct ClippyEnvelope {
    reason: Option<String>,
    message: Option<ClippyMessage>,
}

#[derive(Debug, Deserialize)]
struct ClippyMessage {
    level: Option<String>,
    message: Option<String>,
    code: Option<ClippyCode>,
    spans: Option<Vec<ClippySpan>>,
}

#[derive(Debug, Deserialize)]
struct ClippyCode {
    code: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct ClippySpan {
    file_name: Option<String>,
    line_start: Option<usize>,
    is_primary: Option<bool>,
}

fn parse_clippy_lines(
    path: &Path,
    text: &str,
    filter: &FileFilter,
) -> anyhow::Result<Vec<Finding>> {
    let mut out = Vec::new();

    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if !line.starts_with('{') {
            bail!(
                "invalid Clippy JSON line {} in {}: expected JSON object",
                line_no,
                path.display()
            );
        }

        let env: ClippyEnvelope = serde_json::from_str(line).with_context(|| {
            format!("invalid Clippy JSON line {} in {}", line_no, path.display())
        })?;

        if env.reason.as_deref() != Some("compiler-message") {
            continue;
        }

        let Some(message) = env.message else {
            continue;
        };

        let spans = message.spans.unwrap_or_default();
        let primary = spans
            .iter()
            .find(|s| s.is_primary.unwrap_or(false))
            .cloned()
            .or_else(|| spans.into_iter().next());

        let file = primary.as_ref().and_then(|s| s.file_name.clone());
        let line_no = primary.as_ref().and_then(|s| s.line_start);

        if let Some(p) = &file
            && !filter.is_reviewable_file(p)
        {
            continue;
        }

        out.push(Finding {
            rule: format!(
                "ext:{}",
                message
                    .code
                    .and_then(|c| c.code)
                    .unwrap_or_else(|| "clippy".to_string())
            ),
            title: "External tool finding".to_string(),
            details: message
                .message
                .unwrap_or_else(|| "No diagnostic message".to_string()),
            severity: map_text_severity(message.level.as_deref()),
            file,
            line: line_no,
            suggestion: None,
        });
    }

    Ok(out)
}

fn map_text_severity(level: Option<&str>) -> Severity {
    match level.unwrap_or("warning").to_ascii_lowercase().as_str() {
        "critical" | "high" => Severity::Critical,
        "error" => Severity::Error,
        "warning" | "warn" | "medium" => Severity::Warning,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::checks::Severity;
    use crate::config::FilterConfig;

    use super::ingest_external_findings;

    fn unique_temp_file(name: &str, extension: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "fantastic-pr-ingest-{name}-{}-{nanos}.{extension}",
            std::process::id()
        ))
    }

    #[test]
    fn ingests_sarif_input() {
        let file = unique_temp_file("sarif", "json");
        let body = r#"{
          "version":"2.1.0",
          "runs":[{
            "results":[{
              "ruleId":"x",
              "level":"warning",
              "message":{"text":"test"},
              "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/a.rs"},"region":{"startLine":7}}}]
            }]
          }]
        }"#;
        std::fs::write(&file, body).expect("write fixture");

        let filter = crate::filtering::FileFilter::from_config(&FilterConfig::default())
            .expect("filter build");
        let findings = ingest_external_findings(std::slice::from_ref(&file), &filter)
            .expect("ingest should succeed");

        let _ = std::fs::remove_file(&file);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].file.as_deref(), Some("src/a.rs"));
    }

    #[test]
    fn ingests_checkov_json() {
        let file = unique_temp_file("checkov", "json");
        let body = r#"{
          "check_type":"terraform",
          "results":{
            "failed_checks":[
              {
                "check_id":"CKV_AWS_20",
                "check_name":"Ensure S3 bucket has versioning",
                "severity":"HIGH",
                "file_path":"infra/main.tf",
                "file_line_range":[12,15],
                "details":"versioning disabled"
              }
            ]
          }
        }"#;
        std::fs::write(&file, body).expect("write fixture");

        let filter = crate::filtering::FileFilter::from_config(&FilterConfig::default())
            .expect("filter build");
        let findings = ingest_external_findings(std::slice::from_ref(&file), &filter)
            .expect("ingest should succeed");

        let _ = std::fs::remove_file(&file);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "ext:checkov:CKV_AWS_20");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn ingests_gitleaks_json() {
        let file = unique_temp_file("gitleaks", "json");
        let body = r#"[
          {
            "RuleID":"aws-access-token",
            "Description":"AWS Access Key detected",
            "File":"src/secrets.txt",
            "StartLine":3
          }
        ]"#;
        std::fs::write(&file, body).expect("write fixture");

        let filter = crate::filtering::FileFilter::from_config(&FilterConfig::default())
            .expect("filter build");
        let findings = ingest_external_findings(std::slice::from_ref(&file), &filter)
            .expect("ingest should succeed");

        let _ = std::fs::remove_file(&file);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "ext:gitleaks:aws-access-token");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn fails_on_malformed_detected_format() {
        let file = unique_temp_file("checkov-bad", "json");
        let body = r#"{"check_type":"terraform","results":}"#;
        std::fs::write(&file, body).expect("write fixture");

        let filter = crate::filtering::FileFilter::from_config(&FilterConfig::default())
            .expect("filter build");
        let err = ingest_external_findings(std::slice::from_ref(&file), &filter)
            .expect_err("malformed detected format should fail");

        let _ = std::fs::remove_file(&file);
        assert!(err.to_string().contains("detected as Checkov JSON"));
    }

    #[test]
    fn fails_on_unsupported_non_empty_ingest() {
        let file = unique_temp_file("unknown", "txt");
        std::fs::write(&file, "this is not a supported ingest format").expect("write fixture");

        let filter = crate::filtering::FileFilter::from_config(&FilterConfig::default())
            .expect("filter build");
        let err = ingest_external_findings(std::slice::from_ref(&file), &filter)
            .expect_err("unsupported ingest should fail");

        let _ = std::fs::remove_file(&file);
        assert!(err.to_string().contains("unsupported ingest format"));
    }

    #[test]
    fn ingests_eslint_json_and_maps_severity_levels() {
        let file = unique_temp_file("eslint", "json");
        let body = r#"[
          {
            "filePath": "src/app.js",
            "messages": [
              {"ruleId":"no-console","severity":1,"message":"warn msg","line":3},
              {"ruleId":"eqeqeq","severity":2,"message":"error msg","line":4}
            ]
          }
        ]"#;
        std::fs::write(&file, body).expect("write fixture");

        let filter = crate::filtering::FileFilter::from_config(&FilterConfig::default())
            .expect("filter build");
        let findings = ingest_external_findings(std::slice::from_ref(&file), &filter)
            .expect("ingest should succeed");

        let _ = std::fs::remove_file(&file);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.severity == Severity::Warning));
        assert!(findings.iter().any(|f| f.severity == Severity::Error));
    }

    #[test]
    fn ingests_semgrep_json() {
        let file = unique_temp_file("semgrep", "json");
        let body = r#"{
          "results": [
            {
              "check_id": "sg.rule",
              "path": "src/lib.rs",
              "start": {"line": 12},
              "extra": {"message": "bad pattern", "severity": "ERROR"}
            }
          ]
        }"#;
        std::fs::write(&file, body).expect("write fixture");

        let filter = crate::filtering::FileFilter::from_config(&FilterConfig::default())
            .expect("filter build");
        let findings = ingest_external_findings(std::slice::from_ref(&file), &filter)
            .expect("ingest should succeed");

        let _ = std::fs::remove_file(&file);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "ext:sg.rule");
        assert_eq!(findings[0].line, Some(12));
        assert_eq!(findings[0].severity, Severity::Error);
    }

    #[test]
    fn ingests_clippy_json_lines() {
        let file = unique_temp_file("clippy", "jsonl");
        let body = r#"{"reason":"compiler-message","message":{"level":"warning","message":"avoid unwrap","code":{"code":"clippy::unwrap_used"},"spans":[{"file_name":"src/lib.rs","line_start":9,"is_primary":true}]}}
"#;
        std::fs::write(&file, body).expect("write fixture");

        let filter = crate::filtering::FileFilter::from_config(&FilterConfig::default())
            .expect("filter build");
        let findings = ingest_external_findings(std::slice::from_ref(&file), &filter)
            .expect("ingest should succeed");

        let _ = std::fs::remove_file(&file);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "ext:clippy::unwrap_used");
        assert_eq!(findings[0].file.as_deref(), Some("src/lib.rs"));
        assert_eq!(findings[0].line, Some(9));
    }

    #[test]
    fn fails_on_invalid_clippy_json_lines_input() {
        let file = unique_temp_file("clippy-bad", "jsonl");
        let body = r#"not-json
{"reason":"compiler-message","message":{"level":"warning","message":"avoid unwrap","code":{"code":"clippy::unwrap_used"},"spans":[{"file_name":"src/lib.rs","line_start":9,"is_primary":true}]}}
"#;
        std::fs::write(&file, body).expect("write fixture");

        let filter = crate::filtering::FileFilter::from_config(&FilterConfig::default())
            .expect("filter build");
        let err = ingest_external_findings(std::slice::from_ref(&file), &filter)
            .expect_err("malformed clippy input should fail");

        let _ = std::fs::remove_file(&file);
        assert!(err.to_string().contains("detected as Clippy JSON lines"));
    }

    #[test]
    fn empty_ingest_file_returns_no_findings() {
        let file = unique_temp_file("empty", "txt");
        std::fs::write(&file, " \n\t ").expect("write fixture");

        let filter = crate::filtering::FileFilter::from_config(&FilterConfig::default())
            .expect("filter build");
        let findings = ingest_external_findings(std::slice::from_ref(&file), &filter)
            .expect("ingest should succeed");

        let _ = std::fs::remove_file(&file);
        assert!(findings.is_empty());
    }
}
