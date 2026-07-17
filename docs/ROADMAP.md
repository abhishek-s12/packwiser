# Product Roadmap - PackWiser

PackWiser intends to become the standard for modern secure software packaging. Here are our future development phases:

---

## 1. Short-Term Targets (v0.2.x)

* **Parallel WalkDir**: Implement multi-threaded directory crawlers using Rayon to walk heavy repositories (e.g. monorepos with 100k+ files) at physical disk rates.
* **Custom Reporting Engines**: Expose configuration settings allowing users to declare dynamic HTML reports using external templates.

---

## 2. Mid-Term Targets (v0.3.x)

* **Incremental Archiving**: Read existing checksum files to bypass compressing files whose contents haven't changed, reducing packaging cycles on continuous integration platforms.
* **SARIF rules expansion**: Add precise line-column range location details inside SARIF output payloads to support inline code scanning annotations on GitHub PRs.

---

## 3. Long-Term Targets (v1.0.0)

* **Zero-Allocation Streaming**: Refactor compressor blocks to bypass intermediate buffers entirely, writing input read blocks directly to network uploader threads.
* **Native GUI App**: Create a sleek Tauri wrapper to visualize exclusions, secret scans, and quality scores locally.

---

## Good First Issues

Looking to contribute? Here are some small, well-scoped tasks (each taking under half a day of work) that are perfect for first-time contributors:

- [ ] **Add `--zstd-level` flag** - Expose a CLI flag to configure the ZSTD compression level (currently defaulted).
- [ ] **Support `.packwiserignore` file** - Add support for a dedicated `.packwiserignore` file separate from standard `.gitignore` rules.
- [ ] **Add `--dry-run` to `verify` subcommand** - Support simulating the verification steps without extracting files or altering states.
- [ ] **Add SHA-1 checksum calculation** - Extend `packwiser-checksum` to optionally calculate legacy SHA-1 hashes for backwards compatibility with older artifact repositories.
- [ ] **Add color modes configuration via config file** - Allow users to persist their preferred CLI terminal colorization mode in `packwiser.toml`.

