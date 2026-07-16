//! Quality Score calculation engine for PackWiser.
//!
//! Evaluates the quality and reproducibility of a package manifest, returning
//! a rating score scaled from 0 to 100.

use packwiser_core::{PackageManifest, Severity};

/// Calculates the quality score (0-100) based on properties in the package manifest.
pub fn calculate_quality_score(manifest: &PackageManifest) -> u8 {
    let mut score = 100i16;

    // 1. Deduct for secrets (Critical leaks cost more)
    for leak in &manifest.secrets {
        match leak.severity {
            Severity::Critical => score -= 50,
            _ => score -= 25,
        }
    }

    // 2. Deduct if cryptographic checksums are missing
    if manifest.checksums.is_empty() {
        score -= 15;
    }

    // 3. Deduct if Git metadata is missing (limits reproducibility)
    if manifest.git_commit.is_none() {
        score -= 10;
    }

    // 4. Deduct if no exclusions/ignores are utilized (risk of packaging junk)
    if manifest.excluded_files.is_empty() {
        score -= 5;
    }

    // 5. Clamp to range 0..=100
    if score < 0 {
        0
    } else if score > 100 {
        100
    } else {
        score as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use packwiser_core::SecretLeak;

    fn base_manifest() -> PackageManifest {
        PackageManifest {
            project_name: "quality-test".to_string(),
            version: "1.0.0".to_string(),
            git_commit: Some("abcdef123".to_string()),
            git_branch: Some("main".to_string()),
            timestamp: "2026-07-16T12:00:00Z".to_string(),
            language: "rust".to_string(),
            score: 0,
            checksums: HashMap::from([("sha256".to_string(), "hash123".to_string())]),
            files: vec![PathBuf::from("a.rs")],
            directories: vec![],
            excluded_files: vec![PathBuf::from("target/")],
            secrets: vec![],
            compression_ratio: 1.0,
            os: "linux".to_string(),
        }
    }

    #[test]
    fn test_perfect_score() {
        let manifest = base_manifest();
        assert_eq!(calculate_quality_score(&manifest), 100);
    }

    #[test]
    fn test_reproducibility_and_integrity_deductions() {
        let mut manifest = base_manifest();
        // Remove checksums (-15)
        manifest.checksums.clear();
        // Remove git commit (-10)
        manifest.git_commit = None;

        assert_eq!(calculate_quality_score(&manifest), 75);
    }

    #[test]
    fn test_secrets_deductions() {
        let mut manifest = base_manifest();
        manifest.secrets.push(SecretLeak {
            file_path: PathBuf::from("a.rs"),
            line_number: 5,
            rule_name: "aws".to_string(),
            severity: Severity::High,
            masked_value: "AKIA...".to_string(),
        });
        // One standard secret leak: -25 points
        assert_eq!(calculate_quality_score(&manifest), 75);

        // Add a critical secret leak: -50 points
        manifest.secrets.push(SecretLeak {
            file_path: PathBuf::from("a.rs"),
            line_number: 10,
            rule_name: "pkey".to_string(),
            severity: Severity::Critical,
            masked_value: "key...".to_string(),
        });
        assert_eq!(calculate_quality_score(&manifest), 25);
    }

    #[test]
    fn test_clamped_score() {
        let mut manifest = base_manifest();
        manifest.git_commit = None;
        manifest.checksums.clear();
        // Multiple critical secret leaks to force score below 0
        for _ in 0..5 {
            manifest.secrets.push(SecretLeak {
                file_path: PathBuf::from("a.rs"),
                line_number: 1,
                rule_name: "pkey".to_string(),
                severity: Severity::Critical,
                masked_value: "key...".to_string(),
            });
        }
        assert_eq!(calculate_quality_score(&manifest), 0);
    }
}
