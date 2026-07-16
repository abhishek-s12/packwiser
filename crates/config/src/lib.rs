//! Hierarchical configuration loader and active profile engine for PackWiser.
//!
//! Loads options from global directories, home user configurations, and local workspace roots,
//! merging profile tables (release, ci, backup, distribution) based on priority rules.

use packwiser_core::{ConfigError, ConfigLoader, ConfigProfile, PackWiserConfig};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Default implementation of the `ConfigLoader` trait.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultConfigLoader;

impl DefaultConfigLoader {
    /// Creates a new `DefaultConfigLoader`.
    pub fn new() -> Self {
        Self
    }

    /// Resolves the home user configuration file directory.
    pub fn resolve_user_config_path(&self) -> Option<PathBuf> {
        let home = if cfg!(windows) {
            std::env::var("USERPROFILE")
                .or_else(|_| {
                    let drive = std::env::var("HOMEDRIVE").unwrap_or_else(|_| "C:".to_string());
                    let path = std::env::var("HOMEPATH")
                        .unwrap_or_else(|_| "\\Users\\Default".to_string());
                    Ok::<String, std::env::VarError>(format!("{}{}", drive, path))
                })
                .ok()
        } else {
            std::env::var("HOME").ok()
        };

        home.map(|h| {
            PathBuf::from(h)
                .join(".config")
                .join("packwiser")
                .join("packwiser.toml")
        })
    }

    /// Resolves the global system configuration file directory.
    pub fn resolve_global_config_path(&self) -> PathBuf {
        if cfg!(windows) {
            PathBuf::from("C:\\ProgramData\\packwiser\\packwiser.toml")
        } else {
            PathBuf::from("/etc/packwiser/packwiser.toml")
        }
    }

    /// Generates standard default profiles when no configuration files are found.
    pub fn default_config(&self) -> PackWiserConfig {
        let mut profiles = HashMap::new();

        profiles.insert(
            "release".to_string(),
            ConfigProfile {
                compression_format: Some("zip".to_string()),
                min_quality_score: Some(90),
                no_secrets: Some(true),
                require_signature: Some(true),
                upload_target: None,
            },
        );

        profiles.insert(
            "ci".to_string(),
            ConfigProfile {
                compression_format: Some("tar.gz".to_string()),
                min_quality_score: Some(80),
                no_secrets: Some(true),
                require_signature: Some(false),
                upload_target: None,
            },
        );

        profiles.insert(
            "backup".to_string(),
            ConfigProfile {
                compression_format: Some("tar.zst".to_string()),
                min_quality_score: Some(0),
                no_secrets: Some(false),
                require_signature: Some(false),
                upload_target: None,
            },
        );

        profiles.insert(
            "distribution".to_string(),
            ConfigProfile {
                compression_format: Some("zip".to_string()),
                min_quality_score: Some(95),
                no_secrets: Some(true),
                require_signature: Some(true),
                upload_target: None,
            },
        );

        PackWiserConfig { profiles }
    }
}

impl ConfigLoader for DefaultConfigLoader {
    fn load_config(&self, workspace_root: &Path) -> Result<PackWiserConfig, ConfigError> {
        let mut resolved = self.default_config();

        // 1. Try loading Global configuration (lowest priority)
        let global_path = self.resolve_global_config_path();
        if global_path.exists()
            && let Ok(global_cfg) = parse_config_file(&global_path)
        {
            merge_config(&mut resolved, global_cfg);
        }

        // 2. Try loading User configuration
        if let Some(user_path) = self.resolve_user_config_path()
            && user_path.exists()
            && let Ok(user_cfg) = parse_config_file(&user_path)
        {
            merge_config(&mut resolved, user_cfg);
        }

        // 3. Try loading Workspace configuration (highest priority)
        let workspace_path = workspace_root.join("packwiser.toml");
        if workspace_path.exists() {
            let workspace_cfg = parse_config_file(&workspace_path)?;
            merge_config(&mut resolved, workspace_cfg);
        }

        Ok(resolved)
    }
}

fn parse_config_file(path: &Path) -> Result<PackWiserConfig, ConfigError> {
    let content = fs::read_to_string(path).map_err(|e| {
        ConfigError::Read(format!("Failed to read config file at {:?}: {}", path, e))
    })?;

    toml::from_str(&content).map_err(|e| {
        ConfigError::Parse(format!("Failed to parse config TOML at {:?}: {}", path, e))
    })
}

/// Merges `incoming` config options into the `base` configuration, overriding base values.
fn merge_config(base: &mut PackWiserConfig, incoming: PackWiserConfig) {
    for (prof_name, incoming_prof) in incoming.profiles {
        let base_prof = base.profiles.entry(prof_name).or_insert(ConfigProfile {
            compression_format: None,
            min_quality_score: None,
            no_secrets: None,
            require_signature: None,
            upload_target: None,
        });

        if incoming_prof.compression_format.is_some() {
            base_prof.compression_format = incoming_prof.compression_format;
        }
        if incoming_prof.min_quality_score.is_some() {
            base_prof.min_quality_score = incoming_prof.min_quality_score;
        }
        if incoming_prof.no_secrets.is_some() {
            base_prof.no_secrets = incoming_prof.no_secrets;
        }
        if incoming_prof.require_signature.is_some() {
            base_prof.require_signature = incoming_prof.require_signature;
        }
        if incoming_prof.upload_target.is_some() {
            base_prof.upload_target = incoming_prof.upload_target;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_merge_profiles() {
        let mut base = PackWiserConfig {
            profiles: HashMap::new(),
        };

        base.profiles.insert(
            "release".to_string(),
            ConfigProfile {
                compression_format: Some("zip".to_string()),
                min_quality_score: Some(80),
                no_secrets: Some(false),
                require_signature: Some(false),
                upload_target: None,
            },
        );

        let mut incoming_profiles = HashMap::new();
        incoming_profiles.insert(
            "release".to_string(),
            ConfigProfile {
                compression_format: None,
                min_quality_score: Some(95),
                no_secrets: Some(true),
                require_signature: None,
                upload_target: Some("s3://prod".to_string()),
            },
        );
        let incoming = PackWiserConfig {
            profiles: incoming_profiles,
        };

        merge_config(&mut base, incoming);

        let merged = base.profiles.get("release").unwrap();
        // Values updated by incoming
        assert_eq!(merged.min_quality_score, Some(95));
        assert_eq!(merged.no_secrets, Some(true));
        assert_eq!(merged.upload_target, Some("s3://prod".to_string()));
        // Values kept from base
        assert_eq!(merged.compression_format, Some("zip".to_string()));
        assert_eq!(merged.require_signature, Some(false));
    }

    #[test]
    fn test_load_workspace_overrides() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("packwiser.toml");

        let toml_content = r#"
[profiles.release]
compression_format = "tar.zst"
min_quality_score = 99
"#;
        fs::write(&config_path, toml_content).unwrap();

        let loader = DefaultConfigLoader;
        let resolved = loader.load_config(temp_dir.path()).unwrap();

        let release = resolved.profiles.get("release").unwrap();
        // Overridden by file
        assert_eq!(release.compression_format, Some("tar.zst".to_string()));
        assert_eq!(release.min_quality_score, Some(99));
        // Kept from default config fallback
        assert_eq!(release.no_secrets, Some(true));
    }
}
