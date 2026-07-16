//! Secret and credentials scanner engine for PackWiser.
//!
//! Implements regex-based signature matching and Shannon entropy checks to
//! find credentials, keys, and tokens in files without exposing their raw values.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use regex::Regex;
use packwiser_core::{ScanError, SecretLeak, SecretScanner, Severity};

/// Defines a rule for regex-based secret detection.
#[derive(Debug, Clone)]
pub struct ScannerRule {
    /// Name of the scanning rule
    pub name: String,
    /// Precompiled regex pattern
    pub pattern: Regex,
    /// Default severity rating
    pub severity: Severity,
    /// Explanation of what this rule detects
    pub description: String,
}

/// The main credentials and secret leakage detection engine.
#[derive(Debug, Clone)]
pub struct CredentialScanner {
    rules: Vec<ScannerRule>,
    entropy_threshold: f64,
    min_entropy_length: usize,
}

impl Default for CredentialScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialScanner {
    /// Creates a new `CredentialScanner` with default rule configurations.
    pub fn new() -> Self {
        let rules = vec![
            ScannerRule {
                name: "aws_access_key".to_string(),
                pattern: Regex::new(r"\b(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b").unwrap(),
                severity: Severity::Critical,
                description: "AWS Access Key ID detected".to_string(),
            },
            ScannerRule {
                name: "github_token".to_string(),
                pattern: Regex::new(r"\b(ghp|gho|ghu|ghs|ghr|ghp)_[a-zA-Z0-9]{36}\b").unwrap(),
                severity: Severity::High,
                description: "GitHub Personal Access Token detected".to_string(),
            },
            ScannerRule {
                name: "private_key".to_string(),
                pattern: Regex::new(r"-----BEGIN\s+([A-Z0-9\s_]+)\s+PRIVATE\s+KEY-----").unwrap(),
                severity: Severity::Critical,
                description: "Private Key header detected".to_string(),
            },
            ScannerRule {
                name: "slack_token".to_string(),
                pattern: Regex::new(r"\bxox[baptsr]-[a-zA-Z0-9]{10,96}\b").unwrap(),
                severity: Severity::High,
                description: "Slack API/Webhook Token detected".to_string(),
            },
            ScannerRule {
                name: "stripe_key".to_string(),
                pattern: Regex::new(r"\bsk_(test|live)_[0-9a-zA-Z]{24}\b").unwrap(),
                severity: Severity::High,
                description: "Stripe Secret API Key detected".to_string(),
            },
            ScannerRule {
                name: "openai_key".to_string(),
                pattern: Regex::new(r"\bsk-[a-zA-Z0-9]{48}\b|\bsk-proj-[a-zA-Z0-9_-]{48,}\b").unwrap(),
                severity: Severity::Critical,
                description: "OpenAI Secret Key detected".to_string(),
            },
            ScannerRule {
                name: "anthropic_key".to_string(),
                pattern: Regex::new(r"\bsk-ant-sid01-[a-zA-Z0-9_-]{93,}\b").unwrap(),
                severity: Severity::Critical,
                description: "Anthropic Secret Key detected".to_string(),
            },
        ];

        Self {
            rules,
            entropy_threshold: 4.5,
            min_entropy_length: 16,
        }
    }

    /// Appends a custom rule to the scanning engine.
    pub fn add_rule(&mut self, rule: ScannerRule) {
        self.rules.push(rule);
    }

    /// Configures the Shannon entropy detection parameters.
    pub fn configure_entropy(&mut self, threshold: f64, min_length: usize) {
        self.entropy_threshold = threshold;
        self.min_entropy_length = min_length;
    }

    /// Helper to compute the Shannon entropy of a string token.
    pub fn calculate_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut frequencies = [0usize; 256];
        let mut total_chars = 0;

        for byte in s.bytes() {
            frequencies[byte as usize] += 1;
            total_chars += 1;
        }

        let mut entropy = 0.0;
        for &freq in frequencies.iter() {
            if freq > 0 {
                let probability = freq as f64 / total_chars as f64;
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    /// Masks a secret value to prevent printing raw strings to standard outputs.
    pub fn mask_secret(secret: &str) -> String {
        let len = secret.len();
        if len <= 8 {
            return "*".repeat(len);
        }

        let prefix = &secret[..4];
        let suffix = &secret[len - 4..];
        format!("{}...[masked]...{}", prefix, suffix)
    }

    /// Check text segments for high entropy strings that might be password hashes or tokens.
    fn check_high_entropy(&self, line: &str, line_num: usize, file_path: &Path, leaks: &mut Vec<SecretLeak>) {
        // Splitting tokens using typical assignment delimiters
        let delimiters = [' ', '\t', '=', ':', '"', '\'', ',', ';', '(', ')', '[', ']'];
        for token in line.split(&delimiters[..]) {
            let token = token.trim();
            // Validate length constraints
            if token.len() >= self.min_entropy_length {
                let entropy = Self::calculate_entropy(token);
                if entropy >= self.entropy_threshold {
                    // Avoid matching keywords that represent known imports or system identifiers
                    if token.contains('/') || token.contains('\\') || token.contains("std::") {
                        continue;
                    }
                    // Filter out already detected regex signatures to avoid double listings
                    let is_matched_by_regex = self.rules.iter().any(|r| r.pattern.is_match(token));
                    if !is_matched_by_regex {
                        leaks.push(SecretLeak {
                            file_path: file_path.to_path_buf(),
                            line_number: line_num,
                            rule_name: "high_entropy_string".to_string(),
                            severity: Severity::Medium,
                            masked_value: Self::mask_secret(token),
                        });
                    }
                }
            }
        }
    }
}

impl SecretScanner for CredentialScanner {
    fn scan_file(&self, path: &Path) -> Result<Vec<SecretLeak>, ScanError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut leaks = Vec::new();

        for (idx, line) in reader.lines().enumerate() {
            let line = match line {
                Ok(l) => l,
                Err(_) => {
                    // Stop scanning if we encounter binary files or non-UTF8 buffers
                    break;
                }
            };

            let line_num = idx + 1;

            // Run standard Regex checks
            for rule in &self.rules {
                for mat in rule.pattern.find_iter(&line) {
                    let matched_str = mat.as_str();
                    leaks.push(SecretLeak {
                        file_path: path.to_path_buf(),
                        line_number: line_num,
                        rule_name: rule.name.clone(),
                        severity: rule.severity,
                        masked_value: Self::mask_secret(matched_str),
                    });
                }
            }

            // Run Shannon entropy check
            self.check_high_entropy(&line, line_num, path, &mut leaks);
        }

        Ok(leaks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_shannon_entropy() {
        // Known low entropy
        let low = "aaaaabbbbb";
        // High entropy randomized key
        let high = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c";

        let low_ent = CredentialScanner::calculate_entropy(low);
        let high_ent = CredentialScanner::calculate_entropy(high);

        assert!(low_ent < 2.0);
        assert!(high_ent > 3.8);
    }

    #[test]
    fn test_secret_masking() {
        let short = "abcd";
        let long = "AKIA1234567890123456";

        assert_eq!(CredentialScanner::mask_secret(short), "****");
        assert_eq!(CredentialScanner::mask_secret(long), "AKIA...[masked]...3456");
    }

    #[test]
    fn test_scan_regex_rules() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("config.env");

        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "AWS_KEY=AKIAFOOBARBAZ1234567").unwrap();
        writeln!(file, "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789").unwrap();
        writeln!(file, "SOME_VALUE=regular_text").unwrap();
        file.flush().unwrap();

        let scanner = CredentialScanner::new();
        let leaks = scanner.scan_file(&file_path).unwrap();

        assert_eq!(leaks.len(), 2);
        assert_eq!(leaks[0].rule_name, "aws_access_key");
        assert_eq!(leaks[0].masked_value, "AKIA...[masked]...4567");
        assert_eq!(leaks[1].rule_name, "github_token");
        assert_eq!(leaks[1].masked_value, "ghp_...[masked]...6789");
    }

    #[test]
    fn test_scan_high_entropy_strings() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("secrets.txt");

        let mut file = File::create(&file_path).unwrap();
        // Randomized secret token with no recognizable pattern
        writeln!(file, "MY_PASSWORD=\"7zXy9W#1mK@9qLp2vTsR5xN!aB3cD4eF5\"").unwrap();
        file.flush().unwrap();

        let scanner = CredentialScanner::new();
        let leaks = scanner.scan_file(&file_path).unwrap();

        assert!(!leaks.is_empty());
        assert_eq!(leaks[0].rule_name, "high_entropy_string");
    }
}
