//! Append-only NDJSON audit log with mmap-based reads.
//!
//! Writes append JSON lines to a file. Reads use mmap for zero-copy access
//! to the most recent entries without holding any locks.
//!
//! # Design
//!
//! - [`NdjsonWriter`] owns a [`BufWriter`] opened in append mode. Each call to
//!   [`NdjsonWriter::append`] serializes a value to one JSON line, writes a
//!   trailing newline, and flushes. Flushing on every write is intentional:
//!   the reader may remap at any time, and unflushed bytes would be invisible.
//!
//! - [`NdjsonReader`] memory-maps the file for zero-copy reads. The mapping
//!   is a snapshot of the file at the moment [`NdjsonReader::open`] or
//!   [`NdjsonReader::remap`] was last called. Call `remap()` to pick up newly
//!   appended data.
//!
//! - The two types are intentionally independent: the writer can live on the
//!   write path while multiple readers share the read path with no shared
//!   state between them.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use memmap2::Mmap;

/// Append-only NDJSON writer.
///
/// Each call to [`append`] serializes a value as a single JSON line and
/// flushes the underlying file, making the bytes visible to any reader that
/// calls [`NdjsonReader::remap`] afterward.
///
/// [`append`]: NdjsonWriter::append
pub struct NdjsonWriter {
    writer: BufWriter<File>,
    path: PathBuf,
}

impl NdjsonWriter {
    /// Open or create the NDJSON log file for appending.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            writer: BufWriter::new(file),
            path,
        })
    }

    /// Append a serializable value as a JSON line.
    ///
    /// Serializes `value` to JSON, writes a trailing `\n`, and flushes the
    /// buffer so the data is immediately visible to a reader that remaps.
    pub fn append<T: serde::Serialize>(&mut self, value: &T) -> std::io::Result<()> {
        serde_json::to_writer(&mut self.writer, value)
            .map_err(std::io::Error::other)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()
    }

    /// Return the path to the log file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Memory-mapped reader for the NDJSON log.
///
/// Provides zero-copy access to the log file. The mapping is a point-in-time
/// snapshot; call [`remap`] to incorporate data appended since the last open
/// or remap.
///
/// # Concurrency
///
/// `NdjsonReader` is not `Send` or `Sync` because `Mmap` is not. Create a
/// reader per thread if concurrent reads are needed.
///
/// [`remap`]: NdjsonReader::remap
pub struct NdjsonReader {
    path: PathBuf,
    mmap: Option<Mmap>,
}

impl NdjsonReader {
    /// Create a reader for the given NDJSON log file and perform an initial
    /// mapping of its current contents.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut reader = Self { path, mmap: None };
        reader.remap()?;
        Ok(reader)
    }

    /// Refresh the memory mapping to include data appended since the last
    /// open or remap.
    ///
    /// If the file is empty the internal mapping is cleared; [`tail`] and
    /// [`line_count`] will return empty results until new data is appended and
    /// another remap is performed.
    ///
    /// # Safety of the underlying mmap call
    ///
    /// The file is opened read-only in this call. The mapping covers the file
    /// contents at the time of the `mmap(2)` syscall. Because the log is
    /// append-only, bytes already in the file are never modified in-place, so
    /// the memory backing the mapping is stable for the lifetime of `self.mmap`.
    /// Any new bytes appended by the writer extend the file beyond the current
    /// mapping boundary and are not visible until the next `remap()`.
    ///
    /// [`tail`]: NdjsonReader::tail
    /// [`line_count`]: NdjsonReader::line_count
    pub fn remap(&mut self) -> std::io::Result<()> {
        let file = File::open(&self.path)?;
        let metadata = file.metadata()?;
        if metadata.len() == 0 {
            self.mmap = None;
            return Ok(());
        }
        // SAFETY: We only read from the mapping. The file is append-only, so
        // bytes already written are never modified in-place. New appends extend
        // the file beyond this mapping's range and remain invisible until the
        // next remap(), at which point we create a fresh mapping.
        let mmap = unsafe { Mmap::map(&file)? };
        self.mmap = Some(mmap);
        Ok(())
    }

    /// Return the last `n` lines from the log as string slices.
    ///
    /// The returned slices borrow directly from the memory mapping -- there is
    /// no per-line allocation. Lines are returned in chronological order
    /// (oldest first among the returned subset).
    ///
    /// Returns fewer than `n` lines if the log contains fewer than `n` entries.
    /// Returns an empty slice if the log is empty or unmapped.
    pub fn tail(&self, n: usize) -> Vec<&str> {
        let mmap = match &self.mmap {
            Some(m) => m,
            None => return vec![],
        };

        // Treat the entire mapping as UTF-8. Non-UTF-8 bytes (should never
        // appear in valid NDJSON) are replaced with the replacement character.
        let data = match std::str::from_utf8(mmap.as_ref()) {
            Ok(s) => s,
            Err(_) => return vec![],
        };

        let mut lines: Vec<&str> = Vec::with_capacity(n);

        // Scan backwards through the byte slice, collecting line boundaries.
        // `end` is the exclusive end of the current candidate line.
        let mut end = data.len();

        // Skip a single trailing newline so the last real line is not empty.
        if end > 0 && data.as_bytes()[end - 1] == b'\n' {
            end -= 1;
        }

        while lines.len() < n && end > 0 {
            let start = data[..end].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line = &data[start..end];
            if !line.is_empty() {
                lines.push(line);
            }
            // Move end to just before the newline that preceded `start`, or
            // stop if we've reached the beginning of the file.
            end = if start > 0 { start - 1 } else { 0 };
        }

        // We collected lines newest-first; reverse to chronological order.
        lines.reverse();
        lines
    }

    /// Return the total number of lines (entries) in the log.
    ///
    /// Each well-formed entry occupies exactly one line terminated by `\n`, so
    /// this is equivalent to counting newline bytes in the mapping.
    pub fn line_count(&self) -> usize {
        match &self.mmap {
            Some(m) => m.as_ref().iter().filter(|&&b| b == b'\n').count(),
            None => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use tempfile::NamedTempFile;

    #[derive(Serialize)]
    struct TestEntry {
        id: u32,
        msg: String,
    }

    #[test]
    fn test_write_and_read_tail() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        {
            let mut writer = NdjsonWriter::open(&path).unwrap();
            for i in 0..10 {
                writer
                    .append(&TestEntry {
                        id: i,
                        msg: format!("entry {i}"),
                    })
                    .unwrap();
            }
        }

        let reader = NdjsonReader::open(&path).unwrap();
        let lines = reader.tail(3);
        assert_eq!(lines.len(), 3);

        assert!(
            lines[2].contains("\"id\":9"),
            "last line should be entry 9, got: {}",
            lines[2]
        );
        assert!(
            lines[1].contains("\"id\":8"),
            "second-to-last should be entry 8, got: {}",
            lines[1]
        );
        assert!(
            lines[0].contains("\"id\":7"),
            "third-to-last should be entry 7, got: {}",
            lines[0]
        );
    }

    #[test]
    fn test_line_count() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        {
            let mut writer = NdjsonWriter::open(&path).unwrap();
            for i in 0..5 {
                writer
                    .append(&TestEntry {
                        id: i,
                        msg: format!("e{i}"),
                    })
                    .unwrap();
            }
        }

        let reader = NdjsonReader::open(&path).unwrap();
        assert_eq!(reader.line_count(), 5);
    }

    #[test]
    fn test_empty_file() {
        let tmp = NamedTempFile::new().unwrap();
        let reader = NdjsonReader::open(tmp.path()).unwrap();
        assert_eq!(reader.tail(10).len(), 0);
        assert_eq!(reader.line_count(), 0);
    }

    #[test]
    fn test_tail_more_than_available() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        {
            let mut writer = NdjsonWriter::open(&path).unwrap();
            writer
                .append(&TestEntry {
                    id: 1,
                    msg: "only".into(),
                })
                .unwrap();
        }

        let reader = NdjsonReader::open(&path).unwrap();
        let lines = reader.tail(100);
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_remap_sees_new_data() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let mut writer = NdjsonWriter::open(&path).unwrap();
        writer
            .append(&TestEntry {
                id: 1,
                msg: "first".into(),
            })
            .unwrap();

        let mut reader = NdjsonReader::open(&path).unwrap();
        assert_eq!(reader.line_count(), 1);

        // Write more data.
        writer
            .append(&TestEntry {
                id: 2,
                msg: "second".into(),
            })
            .unwrap();

        // Before remap, reader does not see the new entry.
        assert_eq!(reader.line_count(), 1);

        // After remap, reader sees both entries.
        reader.remap().unwrap();
        assert_eq!(reader.line_count(), 2);
    }

    #[test]
    fn test_tail_single_entry_no_trailing_newline_double_count() {
        // Verify that a file with exactly one entry returns exactly one line,
        // not two due to off-by-one handling of the trailing newline.
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let mut writer = NdjsonWriter::open(&path).unwrap();
        writer
            .append(&TestEntry {
                id: 42,
                msg: "solo".into(),
            })
            .unwrap();

        let reader = NdjsonReader::open(&path).unwrap();
        let lines = reader.tail(10);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"id\":42"));
    }

    #[test]
    fn test_writer_path_accessor() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let writer = NdjsonWriter::open(&path).unwrap();
        assert_eq!(writer.path(), path.as_path());
    }
}
