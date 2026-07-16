# Contributing to PackWiser

Thank you for contributing to PackWiser! We appreciate your support in making packaging secure, fast, and reproducible.

---

## 1. Development Environment Setup

1. **Rust Stable**: Ensure you are using the latest stable Rust compiler.
2. **Clone Workspace**:
   ```bash
   git clone https://github.com/pack-wiser/pack-wiser.git
   cd pack-wiser
   ```
3. **Verify Build**:
   ```bash
   cargo build --workspace
   ```

---

## 2. Code Quality Checklist

To maintain production-grade standards, check the following rules:
* **No Panics**: Never use `unwrap()` or `expect()` in library crates (`crates/*`). Bubble up errors gracefully using `thiserror`.
* **Zero Unsafe**: Do not use `unsafe` code blocks.
* **Format**: Format files using `cargo fmt` before staging commits.
* **Clippy**: Run Clippy and resolve any lint warnings:
  ```bash
  cargo clippy --workspace --all-targets -- -D warnings
  ```

---

## 3. Testing Protocols

Ensure all changes have matching unit tests:
```bash
cargo test --workspace
```
Write integration tests under `crates/integration-tests` for complex scenarios, checking golden templates using `UPDATE_GOLDEN=1` if schemas change.
