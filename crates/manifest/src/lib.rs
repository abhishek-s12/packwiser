//! Manifest serialization and reading/writing capabilities for PackWiser.
//!
//! Exposes helper functions to generate `manifest.json`, load/save manifests,
//! and extract repository metadata (VCS/Git info) programmatically.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use chrono::Utc;
use serde_json;
use packwiser_core::{PackageManifest, SecretLeak};

/// Programmatically extracts the git commit hash and active branch name.
///
/// Resolves HEAD directly from the filesystem `.git` structures, falling back
/// to packed-refs if branch references are stored packed.
pub fn resolve_git_metadata(workspace_root: &Path) -> (Option<String>, Option<String>) {
    let git_dir = workspace_root.join(".git");
    if !git_dir.exists() {
        return (None, None);
    }

    let head_path = git_dir.join("HEAD");
    let head_content = match std::fs::read_to_string(&head_path) {
        Ok(c) => c.trim().to_string(),
        Err(_) => return (None, None),
    };

    if head_content.starts_with("ref: ") {
        let ref_path = head_content.strip_prefix("ref: ").unwrap_or("").trim();
        let branch_name = ref_path.split('/').last().map(|s| s.to_string());

        let ref_file_path = git_dir.join(ref_path);
        let commit_hash = match std::fs::read_to_string(&ref_file_path) {
            Ok(hash) => Some(hash.trim().to_string()),
            Err(_) => {
                // If refs are compressed inside packed-refs
                let packed_refs_path = git_dir.join("packed-refs");
                if packed_refs_path.exists() {
                    match std::fs::read_to_string(&packed_refs_path) {
                        Ok(packed) => packed
                            .lines()
                            .find(|line| line.contains(ref_path))
                            .and_then(|line| line.split_whitespace().next())
                            .map(|hash| hash.to_string()),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            }
        };
        (commit_hash, branch_name)
    } else if !head_content.is_empty() {
        // Detached HEAD configuration, file holds raw SHA hash
        (Some(head_content), None)
    } else {
        (None, None)
    }
}

/// Generates a new package manifest capturing the build metadata and details.
#[allow(clippy::too_many_arguments)]
pub fn build_manifest(
    project_name: String,
    version: String,
    workspace_root: &Path,
    language: String,
    score: u8,
    checksums: HashMap<String, String>,
    files: Vec<PathBuf>,
    directories: Vec<PathBuf>,
    excluded_files: Vec<PathBuf>,
    secrets: Vec<SecretLeak>,
    compression_ratio: f64,
) -> PackageManifest {
    let (git_commit, git_branch) = resolve_git_metadata(workspace_root);
    let timestamp = Utc::now().to_rfc3339();
    let os = std::env::consts::OS.to_string();

    PackageManifest {
        project_name,
        version,
        git_commit,
        git_branch,
        timestamp,
        language,
        score,
        checksums,
        files,
        directories,
        excluded_files,
        secrets,
        compression_ratio,
        os,
    }
}

/// Saves the manifest to a destination path in JSON format.
pub fn save_manifest(manifest: &PackageManifest, destination: &Path) -> Result<(), std::io::Error> {
    let mut file = File::create(destination)?;
    let serialized = serde_json::to_string_pretty(manifest)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    file.write_all(serialized.as_bytes())?;
    file.flush()?;
    Ok(())
}

/// Loads a manifest from a source JSON file path.
pub fn load_manifest(source: &Path) -> Result<PackageManifest, std::io::Error> {
    let mut file = File::open(source)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    let manifest: PackageManifest = serde_json::from_str(&content)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_git_metadata_resolution() {
        let temp_dir = tempfile::tempdir().unwrap();
        let workspace = temp_dir.path();

        // 1. Uninitialized state
        let (commit, branch) = resolve_git_metadata(workspace);
        assert!(commit.is_none());
        assert!(branch.is_none());

        // 2. Initialize mock Git repo structure
        let git_dir = workspace.join(".git");
        fs::create_dir_all(&git_dir).unwrap();

        // Standard HEAD ref pointing to main branch
        let head_path = git_dir.join("HEAD");
        fs::write(&head_path, "ref: refs/heads/main\n").unwrap();

        // Target branch commit reference
        let branch_ref_dir = git_dir.join("refs/heads");
        fs::create_dir_all(&branch_ref_dir).unwrap();
        let main_ref_path = branch_ref_dir.join("main");
        fs::write(&main_ref_path, "a1b2c3d4e5f6a1b2c3d4e5f6\n").unwrap();

        let (commit, branch) = resolve_git_metadata(workspace);
        assert_eq!(commit, Some("a1b2c3d4e5f6a1b2c3d4e5f6".to_string()));
        assert_eq!(branch, Some("main".to_string()));
    }

    #[test]
    fn test_manifest_serialization_io() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manifest_path = temp_dir.path().join("manifest.json");

        let manifest = PackageManifest {
            project_name: "test-proj".to_string(),
            version: "1.2.3".to_string(),
            git_commit: Some("commit123".to_string()),
            git_branch: Some("master".to_string()),
            timestamp: "2026-07-16T12:00:00Z".to_string(),
            language: "rust".to_string(),
            score: 95,
            checksums: HashMap::from([("sha256".to_string(), "hash123".to_string())]),
            files: vec![PathBuf::from("src/main.rs")],
            directories: vec![PathBuf::from("src")],
            excluded_files: vec![PathBuf::from("target/debug/test")],
            secrets: vec![],
            compression_ratio: 2.5,
            os: "windows".to_string(),
        };

        save_manifest(&manifest, &manifest_path).unwrap();
        assert!(manifest_path.exists());

        let loaded = load_manifest(&manifest_path).unwrap();
        assert_eq!(loaded.project_name, "test-proj");
        assert_eq!(loaded.version, "1.2.3");
        assert_eq!(loaded.score, 95);
        assert_eq!(loaded.checksums.get("sha256").unwrap(), "hash123");
        assert_eq!(loaded.files[0], PathBuf::from("src/main.rs"));
        assert_eq!(loaded.compression_ratio, 2.5);
    }
}
