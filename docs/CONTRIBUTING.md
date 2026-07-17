# Contributing to PackWiser

We welcome contributions! Here is the fast track to getting started:

## 1. Quick Start

```bash
# Clone the repository
git clone https://github.com/abhishek-s12/packwiser.git
cd packwiser

# Build all workspace packages
cargo build --workspace

# Run the test suite
cargo test --workspace
```

## 2. Before You Push

Your changes must compile without warnings and adhere to formatting standards. Run the following checks locally:

```bash
# Format your code
cargo fmt --all

# Run clippy and fail on warnings
cargo clippy --workspace --all-targets -- -D warnings
```

## 3. Guidelines

- **Error Handling**: Do not use `unwrap()` or `expect()` in library crates (`crates/*`). Gracefully return errors using `thiserror`.
- **Safety**: Do not write `unsafe` blocks (unsafe count is currently zero).
- **Tests**: Include unit tests for any new features or bug fixes.
- **Roadmap / Issues**: Check [ROADMAP.md](ROADMAP.md) for pre-approved good first issues.

## 4. Pull Request Review

1. Create a branch and submit your PR.
2. Ensure CI passes all compilation, testing, clippy, and formatting checks.
3. Keep PRs focused on a single change. Maintainers will review and merge approved PRs.
