//! Policy validation engine for PackWiser.
//!
//! Parses TOML-based policy rule settings (`policy.toml`) and evaluates package
//! properties against them to ensure compliance in build pipelines.

use packwiser_core::PackageManifest;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Struct representing parsed policy settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    /// Minimum required health and quality score (0-100)
    pub minimum_score: Option<u8>,
    /// Maximum allowed final archive size in bytes
    pub max_archive_size: Option<u64>,
    /// True if any detected secret leaks should trigger failures
    pub no_secrets: Option<bool>,
    /// True if cryptographic checksum digests are mandatory
    pub require_checksum: Option<bool>,
    /// True if package signing is mandatory
    pub require_signature: Option<bool>,
}

/// Validates a package manifest and its build artifacts against configured policy rules.
///
/// Returns a list of strings detailing each violation if any exist.
pub fn validate_policy(
    manifest: &PackageManifest,
    archive_size: u64,
    is_signed: bool,
    policy: &PolicyConfig,
) -> Result<(), Vec<String>> {
    let mut violations = Vec::new();

    // 1. Validate minimum score
    if let Some(min_score) = policy.minimum_score
        && manifest.score < min_score
    {
        violations.push(format!(
            "Quality score {} is below the required minimum of {}",
            manifest.score, min_score
        ));
    }

    // 2. Validate maximum archive size
    if let Some(max_size) = policy.max_archive_size
        && archive_size > max_size
    {
        violations.push(format!(
            "Archive size ({} bytes) exceeds the allowed limit of {} bytes",
            archive_size, max_size
        ));
    }

    // 3. Validate secrets policy
    if let Some(true) = policy.no_secrets
        && !manifest.secrets.is_empty()
    {
        violations.push(format!(
            "Security policy violation: {} credential leak(s) detected",
            manifest.secrets.len()
        ));
    }

    // 4. Validate checksums requirement
    if let Some(true) = policy.require_checksum
        && manifest.checksums.is_empty()
    {
        violations.push("Integrity policy violation: package checksums are required".to_string());
    }

    // 5. Validate signature requirement
    if let Some(true) = policy.require_signature
        && !is_signed
    {
        violations.push("Authenticity policy violation: package signature is required".to_string());
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// Loads a policy configuration from a TOML file path.
pub fn load_policy(path: &Path) -> Result<PolicyConfig, std::io::Error> {
    if !path.exists() {
        return Ok(PolicyConfig::default());
    }

    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let config: PolicyConfig = toml::from_str(&content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use packwiser_core::SecretLeak;
    use std::collections::HashMap;
    use std::io::Write;
    use std::path::PathBuf;

    fn test_manifest() -> PackageManifest {
        PackageManifest {
            project_name: "policy-test".to_string(),
            version: "1.0.0".to_string(),
            git_commit: Some("commit123".to_string()),
            git_branch: Some("main".to_string()),
            timestamp: "2026-07-16T12:00:00Z".to_string(),
            language: "rust".to_string(),
            score: 90,
            checksums: HashMap::from([("sha256".to_string(), "hash123".to_string())]),
            files: vec![],
            directories: vec![],
            excluded_files: vec![],
            secrets: vec![],
            compression_ratio: 1.0,
            os: "linux".to_string(),
        }
    }

    #[test]
    fn test_load_policy_from_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let policy_path = temp_dir.path().join("policy.toml");

        let mut file = File::create(&policy_path).unwrap();
        writeln!(
            file,
            "minimum_score = 85\nmax_archive_size = 100000\nno_secrets = true\nrequire_checksum = false"
        )
        .unwrap();
        file.flush().unwrap();

        let policy = load_policy(&policy_path).unwrap();
        assert_eq!(policy.minimum_score, Some(85));
        assert_eq!(policy.max_archive_size, Some(100_000));
        assert_eq!(policy.no_secrets, Some(true));
        assert_eq!(policy.require_checksum, Some(false));
    }

    #[test]
    fn test_compliant_package() {
        let manifest = test_manifest();
        let policy = PolicyConfig {
            minimum_score: Some(80),
            max_archive_size: Some(50000),
            no_secrets: Some(true),
            require_checksum: Some(true),
            require_signature: Some(false),
        };

        assert!(validate_policy(&manifest, 10000, false, &policy).is_ok());
    }

    #[test]
    fn test_non_compliant_package() {
        let mut manifest = test_manifest();
        // Lower the score to trigger a violation
        manifest.score = 70;
        // Inject a secret to trigger a secret violation
        manifest.secrets.push(SecretLeak {
            file_path: PathBuf::from("a.rs"),
            line_number: 1,
            rule_name: "aws".to_string(),
            severity: packwiser_core::Severity::High,
            masked_value: "key".to_string(),
        });

        let policy = PolicyConfig {
            minimum_score: Some(80),
            max_archive_size: Some(5000), // set size limit lower than package
            no_secrets: Some(true),
            require_checksum: Some(true),
            require_signature: Some(true), // require signature when none is present
        };

        let result = validate_policy(&manifest, 8000, false, &policy);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert_eq!(errs.len(), 4);
        assert!(errs[0].contains("Quality score 70 is below"));
        assert!(errs[1].contains("Archive size (8000 bytes) exceeds"));
        assert!(errs[2].contains("Security policy violation: 1 credential leak"));
        assert!(errs[3].contains("Authenticity policy violation: package signature"));
    }
}
