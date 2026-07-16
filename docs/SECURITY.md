# Security Policy - PackWiser

PackWiser treats package integrity and secret leak prevention as primary objectives.

---

## 1. Secret Scanning Guardrails

PackWiser integrates active scan heuristic modules:
* **Shannon Entropy Verification**: Scans lines for high-entropy strings (default threshold `6.0` bits) to detect random API keys and generated access codes.
* **Regex Rule Engine**: Pre-configured with regex checks matching AWS, GCS, OpenAI, Azure, private SSH keys, RSA PEM files, and JWT blocks.
* **Masking Safeguard**: Identified secrets are masked in reports and logs to prevent leak exposure, and are strictly excluded from output build archives.

---

## 2. Archival Safe Guards

* **Zip Slip Vulnerability**: We prevent path traversal attacks by validating that all extracted/archived paths normalize to directories located strictly *inside* the target workspace directory root.
* **Symlinks Verification**: Symbolic links are parsed to ensure they do not point outside the repository boundaries to system resource files (e.g. `/etc/passwd`).

---

## 3. Reporting Vulnerabilities

If you discover a security issue or vulnerability in PackWiser, please do not open a public issue. Email details to `security@packwiser.dev`. We aim to reply to all reports within 48 hours and fix issues under responsible disclosure guidelines.
