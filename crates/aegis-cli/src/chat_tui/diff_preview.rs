//! Diff and content preview generation for tool approval prompts.

/// Maximum lines to show in a diff preview before truncating.
pub const MAX_DIFF_PREVIEW_LINES: usize = 30;

/// Generate a diff/content preview for a tool approval prompt.
///
/// Returns lines with prefix conventions: `+` addition (green), `-` removal
/// (red), `@` header (cyan), ` ` context (dim). The renderer colors them.
pub fn generate_diff_preview(name: &str, input: &serde_json::Value) -> Vec<String> {
    match name {
        "write_file" => generate_write_file_preview(input),
        "edit_file" => generate_edit_file_preview(input),
        "apply_patch" => generate_patch_preview(input),
        "bash" => {
            // Show full command (summarize_tool_input truncates at 80 chars)
            let cmd = input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if cmd.len() > 80 {
                vec![format!("  {cmd}")]
            } else {
                vec![] // summary already shows the full thing
            }
        }
        _ => vec![],
    }
}

/// Preview for write_file: unified diff if file exists, full content if new.
pub fn generate_write_file_preview(input: &serde_json::Value) -> Vec<String> {
    let path = input
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new_content = input
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if path.is_empty() || new_content.is_empty() {
        return vec![];
    }

    let new_lines: Vec<&str> = new_content.lines().collect();

    // Try to read existing file for a diff
    if let Ok(old_content) = std::fs::read_to_string(path) {
        let old_lines: Vec<&str> = old_content.lines().collect();
        generate_simple_diff(&old_lines, &new_lines)
    } else {
        // New file: show all lines as additions
        let mut preview = vec![format!("@ new file: {path}")];
        let total = new_lines.len();
        for line in new_lines.iter().take(MAX_DIFF_PREVIEW_LINES) {
            preview.push(format!("+{line}"));
        }
        if total > MAX_DIFF_PREVIEW_LINES {
            preview.push(format!("  ... ({} more lines)", total - MAX_DIFF_PREVIEW_LINES));
        }
        preview
    }
}

/// Preview for edit_file: show old_string as removals, new_string as additions.
pub fn generate_edit_file_preview(input: &serde_json::Value) -> Vec<String> {
    let path = input
        .get("file_path")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let old_str = input
        .get("old_string")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new_str = input
        .get("new_string")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut preview = vec![format!("@ {path}")];
    for line in old_str.lines().take(MAX_DIFF_PREVIEW_LINES / 2) {
        preview.push(format!("-{line}"));
    }
    for line in new_str.lines().take(MAX_DIFF_PREVIEW_LINES / 2) {
        preview.push(format!("+{line}"));
    }
    preview
}

/// Preview for apply_patch: show the patch content directly.
pub fn generate_patch_preview(input: &serde_json::Value) -> Vec<String> {
    let patch = input
        .get("patch")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let lines: Vec<&str> = patch.lines().collect();
    let total = lines.len();
    let mut preview: Vec<String> = lines
        .into_iter()
        .take(MAX_DIFF_PREVIEW_LINES)
        .map(|l| {
            // Patch lines already have +/- prefixes or *** markers
            if l.starts_with('+') || l.starts_with('-') || l.starts_with(' ') {
                l.to_string()
            } else if l.starts_with("***") || l.starts_with("@@") {
                format!("@{l}")
            } else {
                format!(" {l}")
            }
        })
        .collect();
    if total > MAX_DIFF_PREVIEW_LINES {
        preview.push(format!("  ... ({} more lines)", total - MAX_DIFF_PREVIEW_LINES));
    }
    preview
}

/// Simple line-level diff between old and new content.
///
/// Uses a basic longest-common-subsequence approach to produce a readable
/// diff. Capped at `MAX_DIFF_PREVIEW_LINES` output lines.
pub fn generate_simple_diff(old_lines: &[&str], new_lines: &[&str]) -> Vec<String> {
    let mut preview = Vec::new();

    // Build LCS table
    let m = old_lines.len();
    let n = new_lines.len();

    // For very large files, fall back to a summary
    if m + n > 2000 {
        let mut p = vec![format!("@ {m} lines -> {n} lines")];
        // Show first few removed and added lines
        for line in old_lines.iter().take(5) {
            p.push(format!("-{line}"));
        }
        p.push("  ...".to_string());
        for line in new_lines.iter().take(5) {
            p.push(format!("+{line}"));
        }
        return p;
    }

    // Standard LCS dp
    let mut dp = vec![vec![0u32; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if old_lines[i - 1] == new_lines[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }

    // Backtrack to produce diff
    let mut diff_lines = Vec::new();
    let (mut i, mut j) = (m, n);
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old_lines[i - 1] == new_lines[j - 1] {
            diff_lines.push(format!(" {}", old_lines[i - 1]));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            diff_lines.push(format!("+{}", new_lines[j - 1]));
            j -= 1;
        } else {
            diff_lines.push(format!("-{}", old_lines[i - 1]));
            i -= 1;
        }
    }
    diff_lines.reverse();

    // Filter to only show changed lines with a bit of context
    let total = diff_lines.len();
    let mut last_shown = 0usize;
    let mut shown_count = 0usize;

    for (idx, line) in diff_lines.iter().enumerate() {
        let is_change = line.starts_with('+') || line.starts_with('-');
        let near_change = is_change
            || (idx > 0
                && diff_lines
                    .get(idx.wrapping_sub(1))
                    .is_some_and(|l| l.starts_with('+') || l.starts_with('-')))
            || diff_lines
                .get(idx + 1)
                .is_some_and(|l| l.starts_with('+') || l.starts_with('-'));

        if near_change {
            if idx > last_shown + 1 && shown_count > 0 {
                preview.push(format!("  ... ({} unchanged lines)", idx - last_shown - 1));
            }
            preview.push(line.clone());
            last_shown = idx;
            shown_count += 1;
            if shown_count >= MAX_DIFF_PREVIEW_LINES {
                let remaining = total - idx - 1;
                if remaining > 0 {
                    preview.push(format!("  ... ({remaining} more lines)"));
                }
                break;
            }
        }
    }

    if preview.is_empty() && !diff_lines.is_empty() {
        // No changes detected (identical content)
        preview.push("  (no changes)".to_string());
    }

    preview
}
