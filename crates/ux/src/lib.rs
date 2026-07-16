//! Terminal UX and TTY decoration primitives for PackWiser.
//!
//! Provides colorization adapters, inline progress indicators, tabular formatting,
//! and recursive project tree layout printing with graceful fallback support.

use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};
use std::path::Path;

/// Options for terminal color decoration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

/// Helper utility to decorate output with ANSI escape color sequences.
#[derive(Debug, Clone)]
pub struct TerminalColorizer {
    enabled: bool,
}

impl TerminalColorizer {
    /// Creates a new `TerminalColorizer` validating color modes and TTY constraints.
    pub fn new(mode: ColorMode) -> Self {
        let enabled = match mode {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => io::stdout().is_terminal(),
        };
        Self { enabled }
    }

    /// Colorizes text to bold blue.
    pub fn info(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1;34m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    /// Colorizes text to green (success indicators).
    pub fn success(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[32m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    /// Colorizes text to yellow (warnings).
    pub fn warning(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[33m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    /// Colorizes text to bold red (errors).
    pub fn error(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1;31m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    /// Adds bold decoration.
    pub fn bold(&self, text: &str) -> String {
        if self.enabled {
            format!("\x1b[1m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }
}

/// Dynamic inline spinner to show packaging operations are processing.
#[derive(Debug)]
pub struct Spinner {
    frames: Vec<&'static str>,
    current_idx: usize,
    message: String,
    enabled: bool,
}

impl Spinner {
    /// Creates a new `Spinner`.
    pub fn new(message: &str) -> Self {
        Self {
            frames: vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
            current_idx: 0,
            message: message.to_string(),
            enabled: io::stdout().is_terminal(),
        }
    }

    /// Refreshes the spinner frame.
    pub fn tick(&mut self) {
        if !self.enabled {
            return;
        }
        let frame = self.frames[self.current_idx];
        print!("\r{} {}", frame, self.message);
        let _ = io::stdout().flush();
        self.current_idx = (self.current_idx + 1) % self.frames.len();
    }

    /// Erases spinner text and prints a final result.
    pub fn stop(&mut self, final_message: &str) {
        if self.enabled {
            // Clear line
            print!("\r\x1b[2K");
            println!("{}", final_message);
            let _ = io::stdout().flush();
        } else {
            println!("{}", final_message);
        }
    }
}

/// Styled progress indicator representing upload or archival completion percentage.
#[derive(Debug)]
pub struct ProgressBar {
    width: usize,
    enabled: bool,
}

impl ProgressBar {
    /// Creates a new `ProgressBar`.
    pub fn new(width: usize) -> Self {
        Self {
            width,
            enabled: io::stdout().is_terminal(),
        }
    }

    /// Renders progress percentage bar inline.
    pub fn draw(&self, current: u64, total: u64, prefix: &str) {
        if !self.enabled {
            return;
        }

        let ratio = if total == 0 {
            0.0
        } else {
            current as f64 / total as f64
        };

        let filled = (ratio * self.width as f64).round() as usize;
        let empty = self.width.saturating_sub(filled);

        let mut bar = String::new();
        for _ in 0..filled {
            bar.push('█');
        }
        for _ in 0..empty {
            bar.push('░');
        }

        let percentage = (ratio * 100.0) as usize;
        print!("\r{} [{}] {}%", prefix, bar, percentage);
        let _ = io::stdout().flush();
    }

    /// Completes the bar, writing a final carriage return line.
    pub fn finish(&self) {
        if self.enabled {
            println!();
            let _ = io::stdout().flush();
        }
    }
}

/// A structured console table formatter using Unicode box lines.
#[derive(Debug)]
pub struct ColoredTable {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl ColoredTable {
    /// Creates a new `ColoredTable` with headers.
    pub fn new(headers: Vec<&str>) -> Self {
        Self {
            headers: headers.iter().map(|h| h.to_string()).collect(),
            rows: Vec::new(),
        }
    }

    /// Appends a structured row to the table.
    pub fn add_row(&mut self, row: Vec<&str>) {
        self.rows.push(row.iter().map(|r| r.to_string()).collect());
    }

    /// Formats and prints the table to the console.
    pub fn print(&self) {
        if self.headers.is_empty() {
            return;
        }

        // Determine column widths
        let mut widths = vec![0; self.headers.len()];
        for (i, h) in self.headers.iter().enumerate() {
            widths[i] = h.len();
        }
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < widths.len() {
                    widths[i] = widths[i].max(cell.len());
                }
            }
        }

        // Helper to draw border
        let draw_border = |left: char, mid: char, right: char| {
            let mut line = String::new();
            line.push(left);
            for (i, w) in widths.iter().enumerate() {
                for _ in 0..*w + 2 {
                    line.push('─');
                }
                if i < widths.len() - 1 {
                    line.push(mid);
                }
            }
            line.push(right);
            println!("{}", line);
        };

        // Header Border Top
        draw_border('┌', '┬', '┐');

        // Headers
        let mut header_line = String::new();
        header_line.push('│');
        for (i, h) in self.headers.iter().enumerate() {
            header_line.push_str(&format!(" {:<width$} │", h, width = widths[i]));
        }
        println!("{}", header_line);

        // Header Border Bottom
        draw_border('├', '┼', '┤');

        // Rows
        for row in &self.rows {
            let mut row_line = String::new();
            row_line.push('│');
            for (i, cell) in row.iter().enumerate() {
                if i < widths.len() {
                    row_line.push_str(&format!(" {:<width$} │", cell, width = widths[i]));
                }
            }
            println!("{}", row_line);
        }

        // Table Bottom
        draw_border('└', '┴', '┘');
    }
}

/// Dynamic Trie mapping directories and files into recursive tree layouts.
#[derive(Debug, Default)]
struct TrieNode {
    children: BTreeMap<String, TrieNode>,
    is_file: bool,
}

/// Helper tree generator utilizing prefix drawing characters.
#[derive(Debug, Default)]
pub struct TreeViewer {
    root: TrieNode,
}

impl TreeViewer {
    /// Creates a new `TreeViewer`.
    pub fn new() -> Self {
        Self {
            root: TrieNode::default(),
        }
    }

    /// Appends path list elements to build tree nodes.
    pub fn add_path(&mut self, path: &Path) {
        let mut current_node = &mut self.root;
        for component in path.iter() {
            let name = component.to_string_lossy().into_owned();
            current_node = current_node.children.entry(name).or_default();
        }
        current_node.is_file = true;
    }

    /// Serializes trie hierarchy structure into branch logs.
    pub fn render(&self) -> String {
        let mut output = String::new();
        self.render_node(&self.root, "", &mut output);
        output
    }

    fn render_node(&self, node: &TrieNode, prefix: &str, output: &mut String) {
        let count = node.children.len();
        for (i, (name, child)) in node.children.iter().enumerate() {
            let is_last = i == count - 1;
            let marker = if is_last { "└── " } else { "├── " };
            output.push_str(&format!("{}{}{}\n", prefix, marker, name));

            let next_prefix = if is_last {
                format!("{}    ", prefix)
            } else {
                format!("{}│   ", prefix)
            };
            self.render_node(child, &next_prefix, output);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_viewer_rendering() {
        let mut viewer = TreeViewer::new();
        viewer.add_path(Path::new("src/main.rs"));
        viewer.add_path(Path::new("src/lib.rs"));
        viewer.add_path(Path::new("Cargo.toml"));

        let rendered = viewer.render();
        let expected = "\
├── Cargo.toml
└── src
    ├── lib.rs
    └── main.rs
";
        assert_eq!(rendered, expected);
    }

    #[test]
    fn test_colored_table_widths() {
        let mut table = ColoredTable::new(vec!["File", "Leak", "Severity"]);
        table.add_row(vec!["src/main.rs", "AWS Token", "High"]);
        table.add_row(vec!["LICENSE", "None", "None"]);

        // Verify rows count
        assert_eq!(table.rows.len(), 2);
        assert_eq!(table.headers[0], "File");
    }

    #[test]
    fn test_colorizer_fallbacks() {
        let active = TerminalColorizer { enabled: true };
        assert_eq!(active.success("OK"), "\x1b[32mOK\x1b[0m");

        let disabled = TerminalColorizer { enabled: false };
        assert_eq!(disabled.success("OK"), "OK");
    }
}
