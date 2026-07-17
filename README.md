# PackWiser

[![CI Status](https://github.com/abhishek-s12/packwiser/actions/workflows/ci.yml/badge.svg)](https://github.com/abhishek-s12/packwiser/actions)
[![License](https://img.shields.io/badge/License-MIT%20or%20Apache%202.0-blue.svg)](#license)
[![Rust Edition](https://img.shields.io/badge/Rust-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

**A single, secure-by-default Rust tool to validate, package, sign, and upload your build artifacts in a single pipeline execution.**

Easily bundle your compiled releases from a local workstation or CI runner, scan them for leaked API keys, produce a deterministic zip/tar package, sign it with Ed25519, and push it directly to S3 or GCS with a single command.

<!-- DEMO: asciinema/gif goes here -->
<!-- 
Instructions for maintainers:
To embed a demo recording here:
1. Run `asciinema rec docs/demo.cast`
2. Run standard commands like:
   ./target/release/packwiser package ./test-fixtures/sample-project sample.zip
3. Upload to asciinema or use `svgterm` to convert to an SVG animation, and embed it:
   ![PackWiser Demo](docs/demo.svg)
-->

---

> **Status:** Early-stage development. The core pipeline is fully functional end-to-end, including secure AWS Signature Version 4 uploading, Azure Blob and GCS uploads, reproducible archiving, and cryptographic Ed25519 signing.

---

## Why I built this

I got tired of hand-rolling custom release scripts that chain `gitleaks` to find credentials, `syft` to generate SBOMs, `cosign` to sign packages, and custom bucket uploaders in GitHub Actions. It was fragile, slow to run, and hard to maintain across multiple projects. PackWiser consolidates all of these separate release tasks into a single fast binary so you configure it once and run one command.

---

## Key Features

- **Environment-aware ignore filtering** — parses `.gitignore` and custom glob rules, with auto-detection for common project layouts.
- **Secrets scanning** — regex + Shannon entropy heuristics to catch leaked credentials before they ship.
- **Reproducible archiving** — deterministic zip / tar / tar.gz / tar.xz / tar.zst output, with Zip Slip path-traversal protection.
- **SBOM generation** — CycloneDX and SPDX JSON output from your workspace's dependency metadata.
- **Ed25519 signing** — sign packages and verify integrity on the receiving end.
- **Policy gates** — enforce thresholds like max archive size, minimum quality score, or "no secrets, no exceptions."
- **Cloud uploaders** — push build output to S3 (authenticated via proper AWS SigV4), GCS, Azure, or GitHub Releases.

---

## Quick Start

### 1. Clone and Build
Requires the Rust 2024 edition toolchain:
```bash
git clone https://github.com/abhishek-s12/packwiser.git
cd packwiser
cargo build --release
```

### 2. Package a Directory
To pack a directory into a zip archive and sign it using a private key:
```bash
./target/release/packwiser package ./test-fixtures/sample-project target/sample-output.zip --key-file target/private.key
```

**Real output:**
```
Evaluating workspace at: "test-fixtures/sample-project"
Packaging completed successfully!
  Archive:          "target/sample-output.zip" (459 bytes)
  Manifest:         "manifest.json"
  Quality Score:    85/100
  Signature:        "target/sample-output.zip".sig saved
```

### 3. Scan for Secrets (Without Packaging)
To analyze a directory for leaked keys and compliance indicators without compiling an archive:
```bash
./target/release/packwiser scan ./test-fixtures/sample-project
```

**Real output:**
```
Starting credentials and secret detection scan on "test-fixtures/sample-project"
Scan completed successfully.
Scanned 3 files. Found 0 potential leaks.
```

### 4. Verify a Signed Package
```bash
./target/release/packwiser verify target/sample-output.zip --key-file target/public.key
```

### 5. Inspect Config Profile
```bash
./target/release/packwiser config release
```

Full flag reference: [CLI Reference Guide](docs/CLI_REFERENCE.md)

---

## Using PackWiser as a Library

Each pipeline stage is a separate crate, so you can pull in only what you need:

```toml
[dependencies]
packwiser-core = { path = "./crates/core" }
packwiser-ignore = { path = "./crates/ignore" }
packwiser-scanner = { path = "./crates/scanner" }
packwiser-compressor = { path = "./crates/compressor" }
packwiser-uploader = { path = "./crates/uploader" }
```

```rust
use std::path::Path;
use packwiser_core::{PackagingPipeline, PipelineOptions};
use packwiser_ignore::IgnoreMatcher;
use packwiser_scanner::CredentialScanner;
use packwiser_compressor::ZipCompressor;
use packwiser_uploader::UniversalUploader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = Path::new("./my-project");
    let output_zip = Path::new("./build/package.zip");

    let ignore = IgnoreMatcher::new(workspace, &[]);
    let scanner = CredentialScanner::new();
    let compressor = Box::new(ZipCompressor::default());
    let uploader = UniversalUploader::new(true); // dry-run mode

    // Build wrappers for quality, policy, and hashing to execute the pipeline...
    Ok(())
}
```

More patterns: [API Guide](docs/API_GUIDE.md)

---

## Mapping PackWiser to Existing Tools

If you are already familiar with the standard release toolchain, here is how PackWiser's integrated stages map to individual single-purpose tools:

| Capability | PackWiser | gitleaks | syft / cdxgen | cosign | goreleaser |
|---|---|---|---|---|---|
| Secrets scanning | ✅ | ✅ | ❌ | ❌ | ❌ |
| SBOM (CycloneDX/SPDX) | ✅ | ❌ | ✅ | ❌ | ✅ (via syft) |
| Artifact signing (Ed25519) | ✅ | ❌ | ❌ | ✅ | ✅ (via cosign) |
| Reproducible archiving | ✅ | ❌ | ❌ | ❌ | ✅ |
| Policy / quality gates | ✅ | ❌ | ❌ | ❌ | ❌ |
| Cloud upload (S3/GCS/Azure) | ✅ | ❌ | ❌ | ❌ | ✅ |
| Single binary, no orchestration | ✅ | — | — | — | ✅ |
| Production track record | 🆕 new | mature | mature | mature | mature |

---

## Architecture

Built as a modular Rust workspace following Clean Architecture:

```
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

| Crate | Responsibility |
|---|---|
| `packwiser-core` | Central interfaces, domain models, pipeline orchestrator |
| `packwiser-cli` | Command-line parsing and output |
| `packwiser-ignore` | `.gitignore` + custom glob rule parsing |
| `packwiser-scanner` | Secret detection (regex + entropy heuristics) |
| `packwiser-compressor` | Streaming compression |
| `packwiser-checksum` | SHA-256 / BLAKE3 digests |
| `packwiser-manifest` | Workspace metadata collection |
| `packwiser-quality` | Package quality scoring |
| `packwiser-policy` | Compliance rule enforcement |
| `packwiser-signature` | Ed25519 signing/validation |
| `packwiser-uploader` | Cloud storage push (S3, GCS, etc.) |
| `packwiser-sbom` | CycloneDX / SPDX generation |
| `packwiser-license` | License file detection + SPDX compatibility |
| `packwiser-plugin` | Hook/extension loading |

Details: [Architecture Overview](docs/ARCHITECTURE.md)

---

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [CLI Reference](docs/CLI_REFERENCE.md)
- [API Guide](docs/API_GUIDE.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](docs/CONTRIBUTING.md)
- [Security Policy](docs/SECURITY.md)

## Contributing

Issues and PRs welcome — especially real-world feedback from trying this on an actual project. See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
