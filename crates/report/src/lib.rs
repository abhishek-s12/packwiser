//! Multi-format report compiler for PackWiser.
//!
//! Generates Markdown summaries, styled static HTML dashboards, and standard-compliant
//! SARIF files for code security analysis integrations.

use packwiser_core::{ReportInput, ReportGenerator, ReportError};

/// Default implementation of the `ReportGenerator` trait.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultReportGenerator;

impl DefaultReportGenerator {
    /// Creates a new `DefaultReportGenerator`.
    pub fn new() -> Self {
        Self
    }
}

impl ReportGenerator for DefaultReportGenerator {
    fn generate_markdown(&self, input: &ReportInput) -> Result<String, ReportError> {
        let mut md = String::new();
        md.push_str(&format!("# PackWiser Security & Build Report - {}\n\n", input.project_name));
        md.push_str(&format!("* **Version**: {}\n", input.version));
        md.push_str(&format!("* **Package Quality Score**: **{}/100**\n\n", input.quality_score));

        md.push_str("## Package Statistics\n\n");
        md.push_str("| Metric | Value |\n");
        md.push_str("| --- | --- |\n");
        md.push_str(&format!("| Scanned Files | {} |\n", input.total_files_scanned));
        md.push_str(&format!("| Excluded Files | {} |\n", input.total_files_ignored));
        md.push_str(&format!("| Compressed Size | {} bytes |\n", input.archive_size_bytes));
        md.push_str(&format!("| Compression Ratio | {:.2}x |\n\n", input.compression_ratio));

        if !input.secrets_detected.is_empty() {
            md.push_str("## ⚠️ Detected Credentials & Secrets\n\n");
            md.push_str("> [!CAUTION]\n");
            md.push_str("> The following potential secrets were identified and excluded/masked:\n\n");
            for secret in &input.secrets_detected {
                md.push_str(&format!("* `{}`\n", secret));
            }
            md.push_str("\n");
        }

        if !input.warnings.is_empty() {
            md.push_str("## Warnings\n\n");
            for warning in &input.warnings {
                md.push_str(&format!("* ⚠️ {}\n", warning));
            }
            md.push_str("\n");
        }

        if !input.recommendations.is_empty() {
            md.push_str("## Optimization Recommendations\n\n");
            for rec in &input.recommendations {
                md.push_str(&format!("* 💡 {}\n", rec));
            }
            md.push_str("\n");
        }

        Ok(md)
    }

    fn generate_html(&self, input: &ReportInput) -> Result<String, ReportError> {
        let mut html = String::new();
        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("  <meta charset=\"UTF-8\">\n");
        html.push_str("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str(&format!("  <title>PackWiser Report - {}</title>\n", input.project_name));
        html.push_str("  <style>\n");
        html.push_str("    body { font-family: 'Inter', system-ui, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 2rem; margin: 0; }\n");
        html.push_str("    .container { max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 2.5rem; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3); border: 1px solid #334155; }\n");
        html.push_str("    h1 { margin-top: 0; color: #38bdf8; font-size: 2.25rem; font-weight: 800; }\n");
        html.push_str("    .meta { font-size: 0.875rem; color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 1rem; margin-bottom: 2rem; }\n");
        html.push_str("    .score-badge { display: inline-block; padding: 0.5rem 1rem; border-radius: 9999px; font-weight: bold; background: #059669; color: #fff; }\n");
        html.push_str("    .score-low { background: #dc2626; }\n");
        html.push_str("    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem; }\n");
        html.push_str("    .card { background: #0f172a; padding: 1.5rem; border-radius: 8px; border: 1px solid #334155; text-align: center; }\n");
        html.push_str("    .card-value { font-size: 1.75rem; font-weight: 700; color: #f8fafc; margin-top: 0.5rem; }\n");
        html.push_str("    .card-label { font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }\n");
        html.push_str("    .section-title { font-size: 1.25rem; font-weight: 700; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; margin-top: 2rem; color: #e2e8f0; }\n");
        html.push_str("    ul { padding-left: 1.25rem; line-height: 1.6; }\n");
        html.push_str("    li { margin-bottom: 0.5rem; }\n");
        html.push_str("    .secret-item { background: #450a0a; border: 1px solid #991b1b; padding: 0.75rem 1rem; border-radius: 6px; color: #fca5a5; font-family: monospace; list-style-type: none; margin-bottom: 0.5rem; }\n");
        html.push_str("  </style>\n</head>\n<body>\n");
        html.push_str("  <div class=\"container\">\n");
        html.push_str(&format!("    <h1>{}</h1>\n", input.project_name));
        html.push_str("    <div class=\"meta\">\n");
        html.push_str(&format!("      <span>Version: {}</span> | \n", input.version));
        
        let low_class = if input.quality_score < 80 { " score-low" } else { "" };
        html.push_str(&format!("      <span>Quality Score: <span class=\"score-badge{}\">{}/100</span></span>\n", low_class, input.quality_score));
        html.push_str("    </div>\n\n");

        html.push_str("    <div class=\"grid\">\n");
        html.push_str(&format!("      <div class=\"card\"><div class=\"card-label\">Scanned Files</div><div class=\"card-value\">{}</div></div>\n", input.total_files_scanned));
        html.push_str(&format!("      <div class=\"card\"><div class=\"card-label\">Excluded Files</div><div class=\"card-value\">{}</div></div>\n", input.total_files_ignored));
        html.push_str(&format!("      <div class=\"card\"><div class=\"card-label\">Package Size</div><div class=\"card-value\">{} B</div></div>\n", input.archive_size_bytes));
        html.push_str(&format!("      <div class=\"card\"><div class=\"card-label\">Compression Ratio</div><div class=\"card-value\">{:.2}x</div></div>\n", input.compression_ratio));
        html.push_str("    </div>\n\n");

        if !input.secrets_detected.is_empty() {
            html.push_str("    <div class=\"section-title\">⚠️ Potential Secrets Flagged</div>\n");
            html.push_str("    <ul style=\"padding: 0;\">\n");
            for secret in &input.secrets_detected {
                html.push_str(&format!("      <li class=\"secret-item\">{}</li>\n", secret));
            }
            html.push_str("    </ul>\n");
        }

        if !input.warnings.is_empty() {
            html.push_str("    <div class=\"section-title\">Warnings</div>\n");
            html.push_str("    <ul>\n");
            for warning in &input.warnings {
                html.push_str(&format!("      <li>⚠️ {}</li>\n", warning));
            }
            html.push_str("    </ul>\n");
        }

        if !input.recommendations.is_empty() {
            html.push_str("    <div class=\"section-title\">Recommendations</div>\n");
            html.push_str("    <ul>\n");
            for rec in &input.recommendations {
                html.push_str(&format!("      <li>💡 {}</li>\n", rec));
            }
            html.push_str("    </ul>\n");
        }

        html.push_str("  </div>\n</body>\n</html>\n");
        Ok(html)
    }

    fn generate_sarif(&self, input: &ReportInput) -> Result<String, ReportError> {
        let mut results = Vec::new();

        for (idx, secret) in input.secrets_detected.iter().enumerate() {
            let msg = format!("Credential leak warning: detected potential secret string '{}'", secret);
            let result_json = serde_json::json!({
                "ruleId": "PW001",
                "ruleIndex": 0,
                "level": "error",
                "message": {
                    "text": msg
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": format!("unknown-file-leak-{}", idx),
                                "uriBaseId": "SRCROOT"
                            }
                        }
                    }
                ]
            });
            results.push(result_json);
        }

        let sarif_val = serde_json::json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "PackWiser",
                            "semanticVersion": "0.1.0",
                            "informationUri": "https://github.com/pack-wiser/pack-wiser",
                            "rules": [
                                {
                                    "id": "PW001",
                                    "shortDescription": {
                                        "text": "Credential and security token leakage detected"
                                    },
                                    "fullDescription": {
                                        "text": "Scans package files for entropy indicators and regular expression matches pointing to API keys or private keys."
                                    },
                                    "helpUri": "https://github.com/pack-wiser/pack-wiser/blob/main/docs/rules/PW001.md"
                                }
                            ]
                        }
                    },
                    "results": results
                }
            ]
        });

        serde_json::to_string_pretty(&sarif_val)
            .map_err(|e| ReportError::Write(format!("Failed to serialize SARIF report: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_input() -> ReportInput {
        ReportInput {
            project_name: "test-proj".to_string(),
            version: "1.0.0".to_string(),
            total_files_scanned: 100,
            total_files_ignored: 45,
            archive_size_bytes: 409600,
            compression_ratio: 3.12,
            quality_score: 95,
            secrets_detected: vec!["AWS-Token-123***".to_string()],
            warnings: vec!["Unsigned package".to_string()],
            recommendations: vec!["Activate signatures".to_string()],
        }
    }

    #[test]
    fn test_generate_markdown_report() {
        let generator = DefaultReportGenerator::new();
        let input = mock_input();
        let md = generator.generate_markdown(&input).unwrap();

        assert!(md.contains("# PackWiser Security & Build Report - test-proj"));
        assert!(md.contains("AWS-Token-123***"));
        assert!(md.contains("Unsigned package"));
    }

    #[test]
    fn test_generate_html_report() {
        let generator = DefaultReportGenerator::new();
        let input = mock_input();
        let html = generator.generate_html(&input).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("test-proj"));
        assert!(html.contains("AWS-Token-123***"));
    }

    #[test]
    fn test_generate_sarif_report() {
        let generator = DefaultReportGenerator::new();
        let input = mock_input();
        let sarif = generator.generate_sarif(&input).unwrap();

        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(sarif.contains("PW001"));
        assert!(sarif.contains("AWS-Token-123***"));
    }
}
