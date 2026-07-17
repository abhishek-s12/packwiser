# CLI Reference Guide - PackWiser

PackWiser provides commands to inspect, scan, secure, package, and upload workspace folders.

---

## 1. Global Options

The following flags can be passed to any subcommand:

* `-h, --help`: Prints usage help.
* `-V, --version`: Prints application version.
* `--verbose`: Activates verbose debug outputs.
* `--quiet`: Silences console logs.
* `--dry-run`: Runs scanner and packaging pipelines without generating disk archives.
* `--json`: Outputs results in machine-readable JSON format.
* `--color <MODE>`: Force ANSI color output (options: `auto`, `always`, `never`).
* `-o, --output <OUTPUT_FILE>`: Custom target output destination path for packaging.

---

## 2. Subcommands

### A. `packwiser package`
Packages a target workspace directory into a secure compressed archive.

* **Usage**: `packwiser package [SOURCE_DIR] [OUTPUT_FILE]`
* **Arguments**:
  - `SOURCE_DIR`: Target folder to package (defaults to `.` if omitted).
  - `OUTPUT_FILE`: Path to write the output archive (defaults to `packwiser_archive.zip` if omitted). Format is automatically inferred from suffix (`zip`, `tar`, `tar.gz`, `tar.xz`, `tar.zst`).
* **Options**:
  - `--key-file <KEY_FILE>`: Path to a 32-byte raw Ed25519 private key file for digital signing.
  - `--upload <URI>`: Target upload destination URI (e.g. `s3://bucket/key`, `gcs://bucket/key`).

### B. `packwiser scan`
Scans a target directory for credentials, secrets, and compliance indicators without compiling an output package.

* **Usage**: `packwiser scan [SOURCE_DIR]`
* **Arguments**:
  - `SOURCE_DIR`: Target folder to inspect (defaults to `.` if omitted).

### C. `packwiser verify`
Validates signature verification digests and extracts manifest files from a packaged archive.

* **Usage**: `packwiser verify <ARCHIVE_FILE> --key-file <KEY_FILE>`
* **Arguments**:
  - `ARCHIVE_FILE`: Path pointing to the target archive file.
* **Options**:
  - `--key-file <KEY_FILE>`: Path to a 32-byte raw Ed25519 public key file for signature verification.

### D. `packwiser config`
Inspects resolved configurations after merging hierarchical `packwiser.toml` settings.

* **Usage**: `packwiser config [PROFILE_NAME]`
* **Arguments**:
  - `PROFILE_NAME`: Configuration profile name to inspect (e.g. `release`, `ci`, `backup`).
