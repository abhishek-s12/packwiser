# PackWiser

[![CI Status](https://github.com/abhishek-s12/packwiser/actions/workflows/ci.yml/badge.svg)](https://github.com/abhishek-s12/packwiser/actions)
[![License](https://img.shields.io/badge/License-MIT%20or%20Apache%202.0-blue.svg)](#license)
[![Rust Edition](https://img.shields.io/badge/Rust-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

**Secure. Intelligent. Reproducible Project Packaging.**

PackWiser is an industrial-grade project packaging toolchain and library designed to automate the process of bundling software repositories securely. It combines file ignoring, high-speed secrets scanning, reproducibility verification, package signing, and automatic SBOM (Software Bill of Materials) generation into a single unified CLI and programmatic API.

Think of PackWiser as:
> **Git** + **Docker Ignore** + **Cargo Package** + **npm pack** + **Gitleaks** + **ripgrep** + **zip/tar** + **Sigstore** + **SBOM Generator**
> ... all combined into one high-performance Rust tool.

---

## Key Features

- 🧠 **Intelligent Environment Detection**: Auto-detects 20+ development frameworks and environments to apply optimal ignore filters and metadata mapping.
- 🛡️ **Built-in Security Scanning**: Scans workspace contents using high-speed regex engines and Shannon entropy calculation to mask or reject packages containing leaked credentials/secrets.
- 🗜️ **Reproducible Archiving**: Packs codebases into exact, deterministic zip, tar, tar.gz, tar.xz, or tar.zst formats. Includes built-in Zip Slip path traversal protections.
- 📊 **Software Bill of Materials (SBOM)**: Automatically analyzes workspace configurations and generates compliant CycloneDX or SPDX JSON bills of materials.
- 🔏 **Cryptographic Signing**: Sign packages using Ed25519 signatures and verify integrity on the receiving end.
- 📈 **Quality & Policy Compliance**: Analyzes packaging contents to compute a quality index score and enforces policy threshold gates (e.g. max archive size, minimum quality score, strict no-secrets rules).
- ☁️ **Native Cloud Uploaders**: Built-in support for uploading build outputs directly to S3, GCS, Azure, or GitHub releases.

---

## Workspace Architecture

PackWiser is designed following **Clean Architecture** patterns, leveraging a highly modular Rust workspace layout:

```text
       CLI (packwiser-cli)
               ↓
     Application Commands
               ↓
   Application Services (PackagingPipeline)
               ↓
       Core Domain (packwiser-core)
               ↓
     Infrastructure Adapters
  (ignore, scanner, compressor, uploader, etc.)
```

- **`packwiser-core`**: Defines the central interfaces, domain models, and pipeline orchestrator.
- **`packwiser-cli`**: Standard command-line parser, styling, and colorized output interface.
- **`packwiser-ignore`**: Recursively parses `.gitignore` and custom inclusion/exclusion glob rules.
- **`packwiser-scanner`**: Scans files for secret strings using custom regex and entropy heuristics.
- **`packwiser-compressor`**: High-performance streaming compression formats.
- **`packwiser-checksum`**: Cryptographic digests (SHA-256, BLAKE3, etc.).
- **`packwiser-manifest`**: Gathers environment-specific workspace metadata.
- **`packwiser-quality`**: Calculates a comprehensive quality score for the package.
- **`packwiser-policy`**: Validates packages against custom compliance rules.
- **`packwiser-signature`**: Ed25519 digital signature signing and validation.
- **`packwiser-uploader`**: Push artifacts to cloud storage (S3, GCS, etc.).
- **`packwiser-sbom`**: Produces CycloneDX and SPDX dependency matrices.
- **`packwiser-license`**: Scans for license files and verifies SPDX compatibility.
- **`packwiser-plugin`**: Dynamically loads hooks and extensions.

---

## Installation

Building from source requires the latest stable Rust toolchain (Rust 2024 edition):

```bash
# Clone the repository
git clone https://github.com/abhishek-s12/packwiser.git
cd packwiser

# Build release binary
cargo build --release

# Run the CLI
./target/release/packwiser --help
```

---

## CLI Quick Start

### 1. Package a Workspace
Pack a target directory into a secure zstd-compressed tarball, signs it using an Ed25519 private key, and validates it against compliance thresholds:
```bash
packwiser package ./my-project ./build/output.tar.zst --format tar.zst --sign ./keys/private.pem
```

### 2. Scan for Leaked Secrets
Scan a workspace directory for compliance, licenses, and credential leaks without writing any output archive:
```bash
packwiser scan ./my-project
```

### 3. Verify a Package Signature
Verify the signature of a packed archive to confirm authenticity and extract its package metadata:
```bash
packwiser verify ./build/output.tar.zst
```

### 4. Check Config
Inspect active configuration profiles merged from hierarchical `packwiser.toml` settings:
```bash
packwiser config release
```

*For more details on CLI options, see the [CLI Reference Guide](docs/CLI_REFERENCE.md).*

---

## Programmatic Library Integration

You can easily integrate `packwiser-core` orchestrators and infrastructure crates directly into your own Rust systems.

Add it to your `Cargo.toml`:
```toml
[dependencies]
packwiser-core = { path = "./crates/core" }
packwiser-ignore = { path = "./crates/ignore" }
packwiser-scanner = { path = "./crates/scanner" }
packwiser-compressor = { path = "./crates/compressor" }
packwiser-uploader = { path = "./crates/uploader" }
```

Use the `PackagingPipeline` model in your code:
```rust
use std::path::Path;
use packwiser_core::{PackagingPipeline, PackagingConfig};
use packwiser_ignore::GitIgnoreMatcher;
use packwiser_scanner::RegexSecretScanner;
use packwiser_compressor::ZipCompressor;
use packwiser_uploader::DryRunUploader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = Path::new("./my-project");
    let output_zip = Path::new("./build/package.zip");

    // Initialize adapters
    let ignore = GitIgnoreMatcher::new(workspace)?;
    let scanner = RegexSecretScanner::new(vec![]);
    let compressor = ZipCompressor::new();
    let uploader = DryRunUploader;

    // Define pipeline configuration
    let config = PackagingConfig {
        project_name: "my-app".to_string(),
        version: "0.1.0".to_string(),
        compression_format: "zip".to_string(),
        sign_key_path: None,
        upload_target: Some("s3://my-releases/zips".to_string()),
        min_quality_score: 90,
        no_secrets: true,
    };

    // Run the pipeline
    let pipeline = PackagingPipeline::new(ignore, scanner, compressor, uploader);
    let manifest = pipeline.execute(&config, workspace, output_zip)?;

    println!("Package created successfully! Quality Score: {}/100", manifest.score);
    Ok(())
}
```

*For more integration patterns, refer to the [API Guide](docs/API_GUIDE.md).*

---

## Documentation

Comprehensive guides are available in the `docs/` directory:

- 🏗️ **[Architecture Overview](docs/ARCHITECTURE.md)**: Deep dive into layers, modules, and security design choices.
- ⚙️ **[CLI Reference](docs/CLI_REFERENCE.md)**: Detailed breakdown of arguments, global flags, and commands.
- 🔌 **[API Guide](docs/API_GUIDE.md)**: Library integration and custom driver implementation details.
- 🗺️ **[Development Roadmap](docs/ROADMAP.md)**: Feature priorities, upcoming integrations, and platform targets.
- 🤝 **[Contributing Guidelines](docs/CONTRIBUTING.md)**: Coding guidelines, test requirements, and workflow instructions.
- 🔒 **[Security Policy](docs/SECURITY.md)**: Reporting vulnerability disclosures and cryptographic guidelines.

---

## License

This project is licensed under either:

* Apache License, Version 2.0 ([LICENSE-APACHE](http://www.apache.org/licenses/LICENSE-2.0))
* MIT license ([LICENSE-MIT](http://opensource.org/licenses/MIT))

at your option.
