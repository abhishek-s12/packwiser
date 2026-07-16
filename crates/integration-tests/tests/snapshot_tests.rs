use packwiser_core::ProjectDetector;
use packwiser_detector::HeuristicProjectDetector;
use packwiser_integration_tests::create_mock_project;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn get_snapshot_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("snapshots")
        .join("detector_snapshot.json")
}

#[test]
fn test_detector_snapshot_regression() {
    let temp_dir = tempdir().unwrap();
    create_mock_project(temp_dir.path()).unwrap();

    let detector = HeuristicProjectDetector::new();
    let result = detector.detect(temp_dir.path()).unwrap();

    let serialized = serde_json::to_string_pretty(&result).unwrap();
    let snapshot_file = get_snapshot_path();

    if std::env::var("UPDATE_SNAPSHOT").is_ok() {
        fs::create_dir_all(snapshot_file.parent().unwrap()).unwrap();
        fs::write(&snapshot_file, &serialized).unwrap();
    }

    if !snapshot_file.exists() {
        fs::create_dir_all(snapshot_file.parent().unwrap()).unwrap();
        fs::write(&snapshot_file, &serialized).unwrap();
    }

    let expected = fs::read_to_string(&snapshot_file).unwrap();

    let normalized_serialized = serialized.replace("\r\n", "\n");
    let normalized_expected = expected.replace("\r\n", "\n");

    assert_eq!(
        normalized_serialized, normalized_expected,
        "Snapshot mismatch! Run with UPDATE_SNAPSHOT=1 environment variable to update."
    );
}
