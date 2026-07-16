use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use packwiser_integration_tests::create_mock_project;
use packwiser_core::PackageManifest;

fn get_golden_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("manifest_golden.json")
}

#[test]
fn test_manifest_golden_regression() {
    let temp_dir = tempdir().unwrap();
    create_mock_project(temp_dir.path()).unwrap();

    // Create a mock manifest matching PackageManifest schema
    let mock_manifest = PackageManifest {
        project_name: "mock-workspace".to_string(),
        version: "1.2.3".to_string(),
        git_commit: Some("commit-12345".to_string()),
        git_branch: Some("main".to_string()),
        timestamp: "2026-07-16T12:00:00Z".to_string(),
        language: "Rust".to_string(),
        score: 98,
        checksums: vec![
            ("Cargo.toml".to_string(), "sha256-dummy".to_string()),
            ("src/main.rs".to_string(), "sha256-dummy-2".to_string()),
        ].into_iter().collect(),
        files: vec![
            PathBuf::from("src/main.rs"),
            PathBuf::from("src/lib.rs"),
            PathBuf::from("Cargo.toml"),
        ],
        directories: vec![PathBuf::from("src")],
        excluded_files: vec![PathBuf::from("target")],
        secrets: Vec::new(),
        compression_ratio: 2.15,
        os: "windows".to_string(),
    };

    let serialized = serde_json::to_string_pretty(&mock_manifest).unwrap();
    let golden_file = get_golden_path();

    // Update golden file if environment variable is present
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        fs::create_dir_all(golden_file.parent().unwrap()).unwrap();
        fs::write(&golden_file, &serialized).unwrap();
    }

    // Ensure the golden file exists
    if !golden_file.exists() {
        fs::create_dir_all(golden_file.parent().unwrap()).unwrap();
        fs::write(&golden_file, &serialized).unwrap();
    }

    let expected = fs::read_to_string(&golden_file).unwrap();
    
    // Normalize newlines to prevent cross-platform OS failures
    let normalized_serialized = serialized.replace("\r\n", "\n");
    let normalized_expected = expected.replace("\r\n", "\n");

    assert_eq!(
        normalized_serialized, 
        normalized_expected, 
        "Golden file mismatch! Run with UPDATE_GOLDEN=1 environment variable to update."
    );
}
