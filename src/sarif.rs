use crate::checks::{Finding, Severity};

pub fn findings_to_sarif(findings: &[Finding]) -> serde_json::Value {
    let results = findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical => "error",
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "note",
            };

            let mut item = serde_json::json!({
                "ruleId": f.rule,
                "level": level,
                "message": { "text": format!("{}: {}", f.title, f.details) },
            });

            if let (Some(file), Some(line)) = (&f.file, f.line) {
                item["locations"] = serde_json::json!([{
                    "physicalLocation": {
                        "artifactLocation": { "uri": file },
                        "region": { "startLine": line }
                    }
                }]);
            }

            item
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "fantastic-pr",
                    "informationUri": "https://github.com",
                    "rules": []
                }
            },
            "results": results
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::findings_to_sarif;
    use crate::checks::{Finding, Severity};

    #[test]
    fn maps_severity_and_sets_locations_when_available() {
        let findings = vec![
            Finding {
                rule: "crit-rule".to_string(),
                title: "critical".to_string(),
                details: "critical details".to_string(),
                severity: Severity::Critical,
                file: Some("src/main.rs".to_string()),
                line: Some(7),
                suggestion: None,
            },
            Finding {
                rule: "warn-rule".to_string(),
                title: "warning".to_string(),
                details: "warning details".to_string(),
                severity: Severity::Warning,
                file: None,
                line: None,
                suggestion: None,
            },
            Finding {
                rule: "info-rule".to_string(),
                title: "info".to_string(),
                details: "info details".to_string(),
                severity: Severity::Info,
                file: Some("src/lib.rs".to_string()),
                line: None,
                suggestion: None,
            },
            Finding {
                rule: "error-rule".to_string(),
                title: "error".to_string(),
                details: "error details".to_string(),
                severity: Severity::Error,
                file: Some("src/error.rs".to_string()),
                line: Some(3),
                suggestion: None,
            },
        ];

        let sarif = findings_to_sarif(&findings);
        let results = sarif["runs"][0]["results"]
            .as_array()
            .expect("results must be an array");

        assert_eq!(results.len(), 4);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "warning");
        assert_eq!(results[2]["level"], "note");
        assert_eq!(results[3]["level"], "error");

        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/main.rs"
        );
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            7
        );
        assert!(results[1].get("locations").is_none());
        assert!(results[2].get("locations").is_none());
    }

    #[test]
    fn formats_message_text_from_title_and_details() {
        let findings = vec![Finding {
            rule: "rule".to_string(),
            title: "Readable title".to_string(),
            details: "specific details".to_string(),
            severity: Severity::Warning,
            file: Some("src/file.rs".to_string()),
            line: Some(1),
            suggestion: None,
        }];

        let sarif = findings_to_sarif(&findings);
        assert_eq!(
            sarif["runs"][0]["results"][0]["message"]["text"],
            "Readable title: specific details"
        );
    }
}
