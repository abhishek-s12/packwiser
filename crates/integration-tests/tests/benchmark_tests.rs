use packwiser_compressor::{TarGzCompressor, ZipCompressor};
use packwiser_core::{Compressor, FileEntry};
use packwiser_integration_tests::create_mock_project;
use std::fs::File;
use std::time::Instant;
use tempfile::tempdir;

#[test]
fn test_compression_format_performance_comparison() {
    let temp_dir = tempdir().unwrap();
    let src_dir = temp_dir.path().join("src_project");
    std::fs::create_dir(&src_dir).unwrap();
    create_mock_project(&src_dir).unwrap();

    // Create extra heavy mock files to measure sizes and durations
    let mut files = Vec::new();
    for i in 0..5 {
        let relative = format!("src/large_file_{}.dat", i);
        let path = src_dir.join(&relative);
        let content = vec![b'a'; 1024 * 1024]; // 1MB each
        std::fs::write(&path, content).unwrap();

        files.push(FileEntry {
            relative_path: std::path::PathBuf::from(relative),
            absolute_path: path,
            size: 1024 * 1024,
            is_symlink: false,
            file_type: "dat".to_string(),
        });
    }

    // 1. Measure ZIP speed and size
    let zip_archive = temp_dir.path().join("archive.zip");
    let mut zip_out = File::create(&zip_archive).unwrap();
    let zip_comp = ZipCompressor::new();
    let start_zip = Instant::now();
    zip_comp
        .compress(&files, &mut zip_out, Box::new(|_| {}))
        .unwrap();
    let zip_duration = start_zip.elapsed();
    let zip_size = std::fs::metadata(&zip_archive).unwrap().len();

    // 2. Measure TAR.GZ speed and size
    let targz_archive = temp_dir.path().join("archive.tar.gz");
    let mut targz_out = File::create(&targz_archive).unwrap();
    let targz_comp = TarGzCompressor::new(6);
    let start_targz = Instant::now();
    targz_comp
        .compress(&files, &mut targz_out, Box::new(|_| {}))
        .unwrap();
    let targz_duration = start_targz.elapsed();
    let targz_size = std::fs::metadata(&targz_archive).unwrap().len();

    println!("\n=== PackWiser Compression Benchmark ===");
    println!("ZIP Speed: {:?}, Size: {} bytes", zip_duration, zip_size);
    println!(
        "TAR.GZ Speed: {:?}, Size: {} bytes",
        targz_duration, targz_size
    );

    assert!(zip_size > 0);
    assert!(targz_size > 0);
}
