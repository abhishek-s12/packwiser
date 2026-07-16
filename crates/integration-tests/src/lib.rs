//! Integration testing utilities and mock workspaces builders for PackWiser.

use std::fs;
use std::path::Path;

/// Sets up a mock project workspace structure with standard source and target files.
pub fn create_mock_project(root: &Path) -> std::io::Result<()> {
    fs::create_dir_all(root.join("src"))?;
    fs::write(root.join("Cargo.toml"), "[package]\nname = \"mock-workspace\"\nversion = \"1.2.3\"")?;
    fs::write(root.join("src/main.rs"), "fn main() { println!(\"Mock\"); }")?;
    fs::write(root.join("src/lib.rs"), "pub fn add(a: i32, b: i32) -> i32 { a + b }")?;
    fs::write(root.join(".gitignore"), "/target\nnode_modules/")?;
    Ok(())
}
