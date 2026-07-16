# API Guide - PackWiser Library Integration

Developers can integrate `packwiser-core` components programmatically into custom Rust applications.

---

## 1. Initializing and Running the Packaging Pipeline

The `PackagingPipeline` coordinates the entire packaging cycle:

```rust
use std::path::Path;
use packwiser_core::{PackagingPipeline, PackagingConfig, DefaultPipelineContext};
use packwiser_ignore::GitIgnoreMatcher;
use packwiser_scanner::RegexSecretScanner;
use packwiser_compressor::ZipCompressor;
use packwiser_uploader::DryRunUploader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = Path::new("./my-project");
    let output_zip = Path::new("./build/package.zip");

    // Initialize dependencies
    let ignore = GitIgnoreMatcher::new(workspace)?;
    let scanner = RegexSecretScanner::new(vec![]);
    let compressor = ZipCompressor::new();
    let uploader = DryRunUploader;

    // Build configuration
    let config = PackagingConfig {
        project_name: "custom-app".to_string(),
        version: "0.1.0".to_string(),
        compression_format: "zip".to_string(),
        sign_key_path: None,
        upload_target: Some("s3://my-releases/zips".to_string()),
        min_quality_score: 90,
        no_secrets: true,
    };

    // Run pipeline orchestrator
    let pipeline = PackagingPipeline::new(ignore, scanner, compressor, uploader);
    let manifest = pipeline.execute(&config, workspace, output_zip)?;

    println!("Package created successfully with score: {}/100", manifest.score);
    Ok(())
}
```

---

## 2. Programmatic Secret Scan

Use `RegexSecretScanner` directly to verify file buffer arrays:

```rust
use packwiser_core::SecretScanner;
use packwiser_scanner::RegexSecretScanner;

let scanner = RegexSecretScanner::new(vec![]); // loads default rules
let file_content = "api_key = \"AKIAIOSFODNN7EXAMPLE\"";

let findings = scanner.scan_buffer(file_content.as_bytes()).unwrap();
for leak in findings {
    println!("Found leak: {:?} in line {}", leak.rule_name, leak.line_number);
}
```
