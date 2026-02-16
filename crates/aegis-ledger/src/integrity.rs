/// The result of verifying the audit ledger's hash chain integrity.
#[derive(Debug, Clone)]
pub struct IntegrityReport {
    /// Total number of entries inspected.
    pub total_entries: usize,
    /// Whether the entire chain is valid.
    pub valid: bool,
    /// Index of the first entry whose hash or chain link is invalid, if any.
    pub first_invalid_entry: Option<usize>,
    /// Human-readable summary of the verification result.
    pub message: String,
}
