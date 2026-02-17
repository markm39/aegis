//! Rolling output buffer for recent agent output.
//!
//! Feeds raw PTY bytes, splits on newlines, and maintains a fixed-size
//! ring buffer of recent lines. Raw bytes are passed through for terminal
//! display; ANSI-stripped lines are provided for adapter pattern matching.

use std::collections::VecDeque;

use crate::ansi;

/// A ring buffer of recent output lines from the agent's terminal.
///
/// Accepts raw byte chunks from the PTY, splits them into lines, strips
/// ANSI escape codes, and retains only the most recent `capacity` lines.
pub struct OutputBuffer {
    /// Stripped lines (ring buffer).
    lines: VecDeque<String>,
    /// Maximum lines to retain.
    capacity: usize,
    /// Partial line accumulator for bytes that don't end with a newline.
    partial: Vec<u8>,
}

impl OutputBuffer {
    /// Create a new buffer that retains at most `capacity` lines.
    pub fn new(capacity: usize) -> Self {
        Self {
            lines: VecDeque::with_capacity(capacity),
            capacity,
            partial: Vec::new(),
        }
    }

    /// Feed raw bytes from the PTY and return newly completed, ANSI-stripped lines.
    ///
    /// Lines are split on `\n`. A trailing partial line (no newline at end) is
    /// buffered internally and will be completed on the next `feed()` call.
    pub fn feed(&mut self, data: &[u8]) -> Vec<String> {
        let mut completed = Vec::new();

        for &byte in data {
            if byte == b'\n' {
                let raw_line = std::mem::take(&mut self.partial);
                let stripped = ansi::strip_ansi(&raw_line);
                self.push_line(stripped.clone());
                completed.push(stripped);
            } else {
                self.partial.push(byte);
            }
        }

        completed
    }

    /// Flush the partial line buffer, returning the ANSI-stripped content if any.
    ///
    /// Useful when the agent exits without a trailing newline, or when we need
    /// to check a prompt that hasn't been terminated with a newline yet.
    pub fn flush_partial(&mut self) -> Option<String> {
        if self.partial.is_empty() {
            return None;
        }
        let raw = std::mem::take(&mut self.partial);
        let stripped = ansi::strip_ansi(&raw);
        self.push_line(stripped.clone());
        Some(stripped)
    }

    /// Get the most recent `n` lines (or all if fewer than `n`).
    pub fn recent(&self, n: usize) -> Vec<&str> {
        let start = self.lines.len().saturating_sub(n);
        self.lines.range(start..).map(String::as_str).collect()
    }

    /// Total number of lines currently in the buffer.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Returns true if there are pending partial bytes (no newline yet).
    pub fn has_partial(&self) -> bool {
        !self.partial.is_empty()
    }

    /// Peek at the current partial line content (ANSI-stripped).
    pub fn peek_partial(&self) -> Option<String> {
        if self.partial.is_empty() {
            None
        } else {
            Some(ansi::strip_ansi(&self.partial))
        }
    }

    fn push_line(&mut self, line: String) {
        if self.lines.len() >= self.capacity {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_line_splitting() {
        let mut buf = OutputBuffer::new(100);
        let lines = buf.feed(b"line1\nline2\nline3\n");
        assert_eq!(lines, vec!["line1", "line2", "line3"]);
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn partial_line_accumulation() {
        let mut buf = OutputBuffer::new(100);

        // First chunk ends without newline
        let lines = buf.feed(b"partial");
        assert!(lines.is_empty());
        assert!(buf.has_partial());

        // Second chunk completes the line
        let lines = buf.feed(b" line\n");
        assert_eq!(lines, vec!["partial line"]);
        assert!(!buf.has_partial());
    }

    #[test]
    fn ring_buffer_eviction() {
        let mut buf = OutputBuffer::new(3);
        buf.feed(b"a\nb\nc\nd\ne\n");
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.recent(10), vec!["c", "d", "e"]);
    }

    #[test]
    fn recent_returns_fewer_than_requested() {
        let mut buf = OutputBuffer::new(100);
        buf.feed(b"only\n");
        assert_eq!(buf.recent(10), vec!["only"]);
    }

    #[test]
    fn strips_ansi_from_lines() {
        let mut buf = OutputBuffer::new(100);
        let lines = buf.feed(b"\x1b[1;31merror\x1b[0m\n");
        assert_eq!(lines, vec!["error"]);
    }

    #[test]
    fn flush_partial() {
        let mut buf = OutputBuffer::new(100);
        buf.feed(b"incomplete");
        assert_eq!(buf.flush_partial(), Some("incomplete".into()));
        assert!(!buf.has_partial());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn flush_partial_empty() {
        let mut buf = OutputBuffer::new(100);
        assert_eq!(buf.flush_partial(), None);
    }

    #[test]
    fn peek_partial() {
        let mut buf = OutputBuffer::new(100);
        buf.feed(b"\x1b[32mhello");
        assert_eq!(buf.peek_partial(), Some("hello".into()));
        // peek doesn't consume
        assert!(buf.has_partial());
    }

    #[test]
    fn empty_buffer() {
        let buf = OutputBuffer::new(100);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.recent(10).len(), 0);
    }

    #[test]
    fn multiple_chunks_build_lines() {
        let mut buf = OutputBuffer::new(100);
        buf.feed(b"hel");
        buf.feed(b"lo ");
        buf.feed(b"world\nbye\n");
        assert_eq!(buf.recent(10), vec!["hello world", "bye"]);
    }
}
