# Architecture Documentation - PackWiser

PackWiser is structured following **Clean Architecture** patterns to ensure testability, safety, extensibility, and maintainability.

---

## 1. Architectural Layers

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

1. **CLI Layer (`packwiser-cli`)**: Parses user arguments and prints colored output. Zero business logic is stored here.
2. **Application Orchestrator (`crates/core`)**: Coordinates scanning, validation, compression, checksum calculation, and uploads using the `PackagingPipeline` model.
3. **Core Domain (`crates/core`)**: Declares trait abstractions (e.g. `IgnoreMatcher`, `SecretScanner`, `Compressor`, `SignatureSigner`) and core structs (e.g. `FileEntry`, `PackageManifest`).
4. **Infrastructure Layer (`crates/*`)**: Leaf dependencies implementing concrete algorithms (e.g. `Ed25519` signature signing, S3 client uploading).

---

## 2. Crate Modules Layout

PackWiser uses a modular Cargo Workspace:

* **`packwiser-core`**: Core contracts, domain types, and pipeline orchestrator.
* **`packwiser-ignore`**: Parses `.gitignore` and glob rules recursively.
* **`packwiser-scanner`**: High-speed regex checks and Shannon entropy calculation.
* **`packwiser-compressor`**: Multi-format streaming compression encoders.
* **`packwiser-checksum`**: Multi-algorithm hash verification (SHA256, BLAKE3, etc.).
* **`packwiser-manifest`**: Resolves local project and Git VCS metadata.
* **`packwiser-quality`**: Calculates packaging quality index scores.
* **`packwiser-policy`**: Validates target threshold rules.
* **`packwiser-signature`**: Ed25519 payload signing and validation.
* **`packwiser-uploader`**: S3/GCS/Azure/GitHub API upload client.
* **`packwiser-sbom`**: Formats dependency lists as CycloneDX or SPDX JSON.
* **`packwiser-license`**: Scans files and headers for SPDX compliance identifiers.
* **`packwiser-plugin`**: Dynamically loads custom language manifest hooks.
* **`packwiser-config`**: Hierarchically overrides profile properties.
* **`packwiser-ux`**: Colored TTY decoration primitives (spinners, tree views).
* **`packwiser-detector`**: Auto-detects 20+ development frameworks and platforms.
* **`packwiser-report`**: Formats reports as Markdown, HTML, or SARIF logs.

---

## 3. Key Design Choices

* **Do Not Hardcode Providers**: Compressor formats, uploaders, and language matching rules are routed dynamically through traits and shell command plugin hooks.
* **Security Guardrails**:
  - **Zip Slip protection**: Verifies relative paths are safely normalized and restricted within target directory roots.
  - **Secrets Isolation**: Leaks are masked and completely excluded from compilation outputs.
