//! Path ignore engine for PackWiser.
//!
//! Exposes the `IgnoreMatcher` which implements `PathMatcher` using standard
//! gitignore behavior and glob patterns.

use std::path::{Path, PathBuf};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use packwiser_core::PathMatcher;

/// A path matcher utilizing standard gitignore format and rules.
#[derive(Debug)]
pub struct IgnoreMatcher {
    root_dir: PathBuf,
    gitignore: Gitignore,
}

impl IgnoreMatcher {
    /// Creates a new `IgnoreMatcher` rooted at the specified directory.
    ///
    /// Loads the root `.gitignore` file if present, and appends any custom patterns.
    pub fn new(root_dir: &Path, custom_patterns: &[&str]) -> Self {
        let mut builder = GitignoreBuilder::new(root_dir);

        // Load root .gitignore if present
        let root_git_ignore = root_dir.join(".gitignore");
        if root_git_ignore.exists() {
            let _ = builder.add(&root_git_ignore);
        }

        // Add custom ignore rules
        for pattern in custom_patterns {
            let _ = builder.add_line(None, pattern);
        }

        // Always ignore internal VCS and common temporary structures by default
        let _ = builder.add_line(None, ".git/");
        let _ = builder.add_line(None, ".git/**");

        let gitignore = builder.build().unwrap_or_else(|_| Gitignore::empty());

        Self {
            root_dir: root_dir.to_path_buf(),
            gitignore,
        }
    }
}

impl PathMatcher for IgnoreMatcher {
    fn is_ignored(&self, path: &Path) -> bool {
        // Strip absolute root prefixes to run matching relative to root_dir
        let relative = if path.is_absolute() {
            match path.strip_prefix(&self.root_dir) {
                Ok(p) => p,
                Err(_) => path,
            }
        } else {
            path
        };

        // Determine if target points to a directory
        let is_dir = path.is_dir();

        // Run gitignore checks
        self.gitignore.matched(relative, is_dir).is_ignore()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;

    #[test]
    fn test_vcs_ignored_by_default() {
        let temp_dir = tempfile::tempdir().unwrap();
        let matcher = IgnoreMatcher::new(temp_dir.path(), &[]);

        let git_dir = temp_dir.path().join(".git");
        fs::create_dir_all(&git_dir).unwrap();
        let git_file = git_dir.join("config");
        fs::write(&git_file, "metadata").unwrap();

        assert!(matcher.is_ignored(&git_dir));
        assert!(matcher.is_ignored(&git_file));
    }

    #[test]
    fn test_custom_patterns() {
        let temp_dir = tempfile::tempdir().unwrap();
        let matcher = IgnoreMatcher::new(temp_dir.path(), &["*.log", "target/"]);

        let log_file = temp_dir.path().join("error.log");
        let rust_file = temp_dir.path().join("src/main.rs");
        let target_dir = temp_dir.path().join("target");

        // Set directory flags using empty temporary structures
        fs::create_dir_all(&target_dir).unwrap();

        assert!(matcher.is_ignored(&log_file));
        assert!(!matcher.is_ignored(&rust_file));
        assert!(matcher.is_ignored(&target_dir));
    }

    #[test]
    fn test_gitignore_file_loading() {
        let temp_dir = tempfile::tempdir().unwrap();
        let gitignore_path = temp_dir.path().join(".gitignore");
        
        let mut file = File::create(&gitignore_path).unwrap();
        writeln!(file, "*.txt").unwrap();
        writeln!(file, "!keep.txt").unwrap();
        file.flush().unwrap();

        let matcher = IgnoreMatcher::new(temp_dir.path(), &[]);

        let txt_file = temp_dir.path().join("notes.txt");
        let keep_file = temp_dir.path().join("keep.txt");

        assert!(matcher.is_ignored(&txt_file));
        assert!(!matcher.is_ignored(&keep_file));
    }
}
