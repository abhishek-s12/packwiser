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

---

## 2. Subcommands

### A. `packwiser package`
Packages a target workspace directory into a secure compressed archive.

* **Usage**: `packwiser package <SOURCE_DIR> [OUTPUT_FILE]`
* **Options**:
  - `--format <FORMAT>`: Suffix format selection (`zip`, `tar`, `tar.gz`, `tar.xz`, `tar.zst`).
  - `--profile <PROFILE>`: Active configuration profile to apply (`release`, `ci`, `backup`, `distribution`).
  - `--sign <KEY_PATH>`: Path to Ed25519 signing key.

### B. `packwiser scan`
Scans a target directory for credentials, secrets, and compliance indicators without compiling an output package.

* **Usage**: `packwiser scan <SOURCE_DIR>`

### C. `packwiser verify`
Validates signature verification digests and extracts manifest files from a packaged archive.

* **Usage**: `packwiser verify <ARCHIVE_FILE>`

### D. `packwiser config`
Inspects resolved configurations after merging hierarchical `packwiser.toml` settings.

* **Usage**: `packwiser config [PROFILE_NAME]`
