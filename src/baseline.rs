use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::checks::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFile {
    pub version: u8,
    pub entries: Vec<String>,
}

impl Default for BaselineFile {
    fn default() -> Self {
        Self {
            version: 1,
            entries: Vec::new(),
        }
    }
}

pub fn apply_baseline(path: &Path, findings: &[Finding]) -> anyhow::Result<(Vec<Finding>, usize)> {
    if !path.exists() {
        return Ok((findings.to_vec(), 0));
    }

    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline file {}", path.display()))?;

    let baseline: BaselineFile = serde_json::from_str(&text)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let existing = baseline.entries.into_iter().collect::<BTreeSet<_>>();

    let mut filtered = Vec::new();
    let mut suppressed = 0usize;

    for finding in findings {
        let key = finding_key(finding);
        if existing.contains(&key) {
            suppressed += 1;
        } else {
            filtered.push(finding.clone());
        }
    }

    Ok((filtered, suppressed))
}

pub fn write_baseline(path: &Path, findings: &[Finding]) -> anyhow::Result<()> {
    let mut entries = findings.iter().map(finding_key).collect::<Vec<_>>();
    entries.sort();
    entries.dedup();

    let payload = BaselineFile {
        version: 1,
        entries,
    };

    fs::write(path, serde_json::to_string_pretty(&payload)?)
        .with_context(|| format!("failed to write baseline {}", path.display()))?;

    Ok(())
}

pub fn finding_key(f: &Finding) -> String {
    format!(
        "{}|{}|{}|{}",
        f.rule,
        f.file.clone().unwrap_or_else(|| "<none>".to_string()),
        f.line
            .map(|v| v.to_string())
            .unwrap_or_else(|| "<none>".to_string()),
        f.title
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::checks::{Finding, Severity};

    use super::{BaselineFile, apply_baseline, finding_key, write_baseline};

    fn unique_temp_file(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "fantastic-pr-{name}-{}-{nanos}.json",
            std::process::id()
        ))
    }

    #[test]
    fn suppresses_existing_findings() {
        let path = unique_temp_file("suppress");

        let findings = vec![Finding {
            rule: "x".to_string(),
            title: "title".to_string(),
            details: "details".to_string(),
            severity: Severity::Warning,
            file: Some("src/a.rs".to_string()),
            line: Some(10),
            suggestion: None,
        }];

        write_baseline(&path, &findings).expect("baseline write");
        let (filtered, suppressed) = apply_baseline(&path, &findings).expect("baseline apply");
        let _ = std::fs::remove_file(&path);

        assert_eq!(filtered.len(), 0);
        assert_eq!(suppressed, 1);
    }

    #[test]
    fn missing_baseline_file_keeps_all_findings() {
        let path = unique_temp_file("missing");
        let findings = vec![Finding {
            rule: "x".to_string(),
            title: "title".to_string(),
            details: "details".to_string(),
            severity: Severity::Warning,
            file: Some("src/a.rs".to_string()),
            line: Some(10),
            suggestion: None,
        }];

        let (filtered, suppressed) =
            apply_baseline(&path, &findings).expect("apply should succeed");
        assert_eq!(filtered.len(), findings.len());
        assert_eq!(suppressed, 0);
    }

    #[test]
    fn malformed_baseline_returns_parse_error() {
        let path = unique_temp_file("malformed");
        std::fs::write(&path, "{ not-valid-json").expect("write malformed baseline");

        let err = apply_baseline(&path, &[]).expect_err("apply should fail for malformed baseline");
        let _ = std::fs::remove_file(&path);
        assert!(err.to_string().contains("failed to parse"));
    }

    #[test]
    fn write_baseline_sorts_and_deduplicates_entries() {
        let path = unique_temp_file("sorted");
        let findings = vec![
            Finding {
                rule: "b-rule".to_string(),
                title: "b-title".to_string(),
                details: "details".to_string(),
                severity: Severity::Warning,
                file: Some("src/b.rs".to_string()),
                line: Some(2),
                suggestion: None,
            },
            Finding {
                rule: "a-rule".to_string(),
                title: "a-title".to_string(),
                details: "details".to_string(),
                severity: Severity::Warning,
                file: Some("src/a.rs".to_string()),
                line: Some(1),
                suggestion: None,
            },
            Finding {
                rule: "a-rule".to_string(),
                title: "a-title".to_string(),
                details: "details".to_string(),
                severity: Severity::Warning,
                file: Some("src/a.rs".to_string()),
                line: Some(1),
                suggestion: None,
            },
        ];

        write_baseline(&path, &findings).expect("baseline write");

        let text = std::fs::read_to_string(&path).expect("baseline read");
        let parsed: BaselineFile = serde_json::from_str(&text).expect("baseline parse");
        let _ = std::fs::remove_file(&path);

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.entries.len(), 2);
        assert!(parsed.entries[0] < parsed.entries[1]);
    }

    #[test]
    fn finding_key_uses_none_placeholders() {
        let finding = Finding {
            rule: "rule".to_string(),
            title: "title".to_string(),
            details: "details".to_string(),
            severity: Severity::Info,
            file: None,
            line: None,
            suggestion: None,
        };

        assert_eq!(finding_key(&finding), "rule|<none>|<none>|title");
    }
}
