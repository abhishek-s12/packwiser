# PackWiser

[![CI Status](https://github.com/abhishek-s12/packwiser/actions/workflows/ci.yml/badge.svg)](https://github.com/abhishek-s12/packwiser/actions)
[![License](https://img.shields.io/badge/License-MIT%20or%20Apache%202.0-blue.svg)](#license)
[![Rust Edition](https://img.shields.io/badge/Rust-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

**A single Rust CLI for packaging, scanning, signing, and documenting your release artifacts.**

Shipping a release usually means stitching together several tools: something to respect `.gitignore` rules, something to scan for leaked secrets, something to produce an SBOM, something to sign the artifact, and something to push it to storage. PackWiser combines those steps into one pipeline so you configure it once and run one command.

> **Status:** early-stage / pre-1.0. The core pipeline works end-to-end (see [Roadmap](docs/ROADMAP.md) for what's still in progress). If you're evaluating this for production security-critical workflows, please read the code and open issues before relying on it — feedback from real usage is exactly what this project needs right now.

---

## Why PackWiser instead of the individual tools?

If you're already happy composing `gitleaks` + `syft` + `cosign` + `goreleaser`, that's a completely reasonable setup — those are mature, widely-used tools. PackWiser's value is consolidation: one config file, one binary, one command, for teams that want fewer moving parts.

| Capability | PackWiser | gitleaks | syft / cdxgen | cosign | goreleaser |
|---|---|---|---|---|---|
| Secrets scanning | ✅ | ✅ | ❌ | ❌ | ❌ |
| SBOM (CycloneDX/SPDX) | ✅ | ❌ | ✅ | ❌ | ✅ (via syft) |
| Artifact signing (Ed25519) | ✅ | ❌ | ❌ | ✅ | ✅ (via cosign) |
| Reproducible archiving | ✅ | ❌ | ❌ | ❌ | ✅ |
| Policy / quality gates | ✅ | ❌ | ❌ | ❌ | ❌ |
| Cloud upload (S3/GCS/Azure) | ✅ | ❌ | ❌ | ❌ | ✅ |
| Single binary, no orchestration needed | ✅ | — | — | — | ✅ |
| Production track record | 🆕 new | mature | mature | mature | mature |

*(Verify each checkmark against your own test coverage before publishing — this table is a starting point, not a claim of parity.)*

---

## Key Features

- **Environment-aware ignore filtering** — parses `.gitignore` and custom glob rules, with auto-detection for common project layouts.
- **Secrets scanning** — regex + Shannon entropy heuristics to catch leaked credentials before they ship.
- **Reproducible archiving** — deterministic zip / tar / tar.gz / tar.xz / tar.zst output, with Zip Slip path-traversal protection.
- **SBOM generation** — CycloneDX and SPDX JSON output from your workspace's dependency metadata.
- **Ed25519 signing** — sign packages and verify integrity on the receiving end.
- **Policy gates** — enforce thresholds like max archive size, minimum quality score, or "no secrets, no exceptions."
- **Cloud uploaders** — push build output to S3, GCS, Azure, or GitHub Releases.

---

## Quick Start

```bash
# Clone and build (requires Rust 2024 edition toolchain)
git clone https://github.com/abhishek-s12/packwiser.git
cd packwiser
cargo build --release
./target/release/packwiser --help
```

### Package a workspace

Pack a directory into a zstd-compressed tarball, sign it, and enforce compliance thresholds in one step:

```bash
packwiser package ./my-project ./build/output.tar.zst \
  --format tar.zst \
  --sign ./keys/private.pem
```

<details>
<summary>Example output</summary>

```
$ packwiser package ./my-project ./build/output.tar.zst --format tar.zst --sign ./keys/private.pem

[ignore]   using .gitignore + 3 custom rules — 142 files matched, 891 excluded
[scanner]  scanning 142 files for secrets... none found
[sbom]     generated CycloneDX SBOM (37 dependencies)
[compress] tar.zst — 4.2 MB → 1.1 MB
[sign]     signed with Ed25519 key ./keys/private.pem
[quality]  score: 94/100 (threshold: 90) — PASS

Package created: ./build/output.tar.zst
```

*(Replace with real CLI output once you've run it — placeholder shown for illustration.)*
</details>

### Scan without packaging

```bash
packwiser scan ./my-project
```

### Verify a signed package

```bash
packwiser verify ./build/output.tar.zst
```

### Inspect merged config

```bash
packwiser config release
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
use packwiser_core::{PackagingPipeline, PackagingConfig};
use packwiser_ignore::GitIgnoreMatcher;
use packwiser_scanner::RegexSecretScanner;
use packwiser_compressor::ZipCompressor;
use packwiser_uploader::DryRunUploader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = Path::new("./my-project");
    let output_zip = Path::new("./build/package.zip");

    let ignore = GitIgnoreMatcher::new(workspace)?;
    let scanner = RegexSecretScanner::new(vec![]);
    let compressor = ZipCompressor::new();
    let uploader = DryRunUploader;

    let config = PackagingConfig {
        project_name: "my-app".to_string(),
        version: "0.1.0".to_string(),
        compression_format: "zip".to_string(),
        sign_key_path: None,
        upload_target: Some("s3://my-releases/zips".to_string()),
        min_quality_score: 90,
        no_secrets: true,
    };

    let pipeline = PackagingPipeline::new(ignore, scanner, compressor, uploader);
    let manifest = pipeline.execute(&config, workspace, output_zip)?;

    println!("Package created. Quality score: {}/100", manifest.score);
    Ok(())
}
```

More patterns: [API Guide](docs/API_GUIDE.md)

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

- [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT License](http://opensource.org/licenses/MIT)

at your option.
