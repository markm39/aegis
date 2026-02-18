//! Screen snapshot capture and comparison.
//!
//! A [`ScreenSnapshot`] captures the terminal state at a point in time,
//! including all visible text, cursor position, and terminal dimensions.
//! Useful for assertions, debugging, and tracking screen changes.

use std::fmt;
use std::time::Instant;

/// A frozen capture of the terminal screen state.
#[derive(Debug, Clone)]
pub struct ScreenSnapshot {
    /// The full screen text with rows joined by newlines.
    pub text: String,
    /// Each row of screen text, trimmed of trailing whitespace.
    pub rows: Vec<String>,
    /// Cursor position as (row, col), zero-indexed.
    pub cursor: (u16, u16),
    /// Terminal dimensions as (rows, cols).
    pub size: (u16, u16),
    /// When this snapshot was taken.
    pub timestamp: Instant,
}

impl ScreenSnapshot {
    /// Returns `true` if this snapshot differs from another in visible text
    /// or cursor position.
    pub fn differs_from(&self, other: &ScreenSnapshot) -> bool {
        self.text != other.text || self.cursor != other.cursor
    }

    /// Render a bordered text representation of the screen for debugging.
    ///
    /// Includes a top/bottom border matching the terminal width, the screen
    /// content, and a footer showing cursor position and dimensions.
    pub fn render(&self) -> String {
        let cols = self.size.1 as usize;
        let border = format!("+{}+", "-".repeat(cols));

        let mut lines = Vec::with_capacity(self.rows.len() + 4);
        lines.push(border.clone());

        for row in &self.rows {
            // Pad or truncate to exact column width
            let display: String = if row.len() >= cols {
                row.chars().take(cols).collect()
            } else {
                format!("{:<width$}", row, width = cols)
            };
            lines.push(format!("|{}|", display));
        }

        lines.push(border);
        lines.push(format!(
            "cursor=({},{}) size={}x{}",
            self.cursor.0, self.cursor.1, self.size.1, self.size.0
        ));

        lines.join("\n")
    }
}

impl fmt::Display for ScreenSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snapshot(rows: &[&str], cursor: (u16, u16), size: (u16, u16)) -> ScreenSnapshot {
        let rows: Vec<String> = rows.iter().map(|s| s.to_string()).collect();
        let text = rows.join("\n");
        ScreenSnapshot {
            text,
            rows,
            cursor,
            size,
            timestamp: Instant::now(),
        }
    }

    #[test]
    fn differs_when_text_changes() {
        let a = make_snapshot(&["hello"], (0, 5), (24, 80));
        let b = make_snapshot(&["world"], (0, 5), (24, 80));
        assert!(a.differs_from(&b));
    }

    #[test]
    fn differs_when_cursor_moves() {
        let a = make_snapshot(&["hello"], (0, 0), (24, 80));
        let b = make_snapshot(&["hello"], (0, 5), (24, 80));
        assert!(a.differs_from(&b));
    }

    #[test]
    fn same_snapshot_does_not_differ() {
        let a = make_snapshot(&["hello"], (0, 5), (24, 80));
        let b = make_snapshot(&["hello"], (0, 5), (24, 80));
        assert!(!a.differs_from(&b));
    }

    #[test]
    fn render_includes_border_and_cursor() {
        let snap = make_snapshot(&["hi"], (0, 2), (2, 10));
        let rendered = snap.render();
        assert!(rendered.contains("+----------+"));
        assert!(rendered.contains("cursor=(0,2)"));
        assert!(rendered.contains("size=10x2"));
    }
}
