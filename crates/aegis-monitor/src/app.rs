/// Application state machine for the monitor TUI.
///
/// Manages the current view mode, cached audit entries, aggregate
/// statistics, and keyboard navigation state. Data is refreshed from
/// the SQLite ledger on every tick via a read-only connection.
use std::path::PathBuf;

use chrono::DateTime;
use rusqlite::{params, Connection};
use tracing::warn;
use uuid::Uuid;

use aegis_ledger::AuditEntry;

/// The active view mode of the dashboard.
pub enum AppMode {
    /// Live audit feed -- the default view.
    AuditFeed,
    /// Policy summary view.
    PolicyView,
    /// Text filter input mode.
    FilterMode,
}

/// Top-level application state.
pub struct App {
    /// Current view mode.
    pub mode: AppMode,
    /// Cached audit entries (most recent first).
    pub entries: Vec<AuditEntry>,
    /// Total number of entries in the ledger.
    pub total_count: usize,
    /// Count of entries with decision "Allow".
    pub allow_count: usize,
    /// Count of entries with decision "Deny".
    pub deny_count: usize,
    /// Currently highlighted row in the audit feed.
    pub selected_index: usize,
    /// Whether the main loop should keep running.
    pub running: bool,
    /// Active filter text (empty means no filter).
    pub filter_text: String,
    /// Path to the SQLite ledger database.
    ledger_path: PathBuf,
}

impl App {
    /// Create a new application state pointing at the given ledger.
    pub fn new(ledger_path: PathBuf) -> Self {
        Self {
            mode: AppMode::AuditFeed,
            entries: Vec::new(),
            total_count: 0,
            allow_count: 0,
            deny_count: 0,
            selected_index: 0,
            running: true,
            filter_text: String::new(),
            ledger_path,
        }
    }

    /// Refresh cached data from the audit ledger.
    ///
    /// Opens a read-only connection to the SQLite database and queries the
    /// last 100 entries plus aggregate counts. Silently logs a warning and
    /// returns Ok(()) if the database cannot be opened (e.g. it does not
    /// exist yet).
    pub fn refresh(&mut self) -> anyhow::Result<()> {
        let conn = match Connection::open_with_flags(
            &self.ledger_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c) => c,
            Err(e) => {
                warn!(path = %self.ledger_path.display(), error = %e, "cannot open ledger for reading");
                return Ok(());
            }
        };

        // Total count
        self.total_count = conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as usize;

        // Allow count
        self.allow_count = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE decision = ?1",
                params!["Allow"],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0) as usize;

        // Deny count
        self.deny_count = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE decision = ?1",
                params!["Deny"],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0) as usize;

        // Last 100 entries (most recent first)
        let mut stmt = conn.prepare(
            "SELECT entry_id, timestamp, action_id, action_kind, principal, \
                    decision, reason, policy_id, prev_hash, entry_hash \
             FROM audit_log ORDER BY id DESC LIMIT 100",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(AuditEntry {
                entry_id: row
                    .get::<_, String>(0)
                    .map(|s| Uuid::parse_str(&s).expect("invalid uuid in ledger"))?,
                timestamp: row.get::<_, String>(1).map(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .expect("invalid timestamp in ledger")
                        .into()
                })?,
                action_id: row
                    .get::<_, String>(2)
                    .map(|s| Uuid::parse_str(&s).expect("invalid uuid in ledger"))?,
                action_kind: row.get(3)?,
                principal: row.get(4)?,
                decision: row.get(5)?,
                reason: row.get(6)?,
                policy_id: row.get(7)?,
                prev_hash: row.get(8)?,
                entry_hash: row.get(9)?,
            })
        })?;

        self.entries = rows.collect::<Result<Vec<_>, _>>()?;

        // Clamp selected_index to valid range
        if !self.entries.is_empty() && self.selected_index >= self.entries.len() {
            self.selected_index = self.entries.len() - 1;
        }

        Ok(())
    }

    /// Handle a key event based on the current mode.
    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        match self.mode {
            AppMode::AuditFeed => match key.code {
                KeyCode::Char('p') => self.mode = AppMode::PolicyView,
                KeyCode::Char('/') => {
                    self.mode = AppMode::FilterMode;
                    self.filter_text.clear();
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.selected_index > 0 {
                        self.selected_index -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.selected_index < self.entries.len().saturating_sub(1) {
                        self.selected_index += 1;
                    }
                }
                _ => {}
            },
            AppMode::PolicyView => match key.code {
                KeyCode::Char('a') | KeyCode::Esc => self.mode = AppMode::AuditFeed,
                _ => {}
            },
            AppMode::FilterMode => match key.code {
                KeyCode::Esc => self.mode = AppMode::AuditFeed,
                KeyCode::Enter => self.mode = AppMode::AuditFeed,
                KeyCode::Char(c) => self.filter_text.push(c),
                KeyCode::Backspace => {
                    self.filter_text.pop();
                }
                _ => {}
            },
        }
    }

    /// Return entries matching the current filter text.
    ///
    /// When the filter is empty, all entries are returned. Otherwise
    /// entries are matched against principal, action_kind, and decision.
    pub fn filtered_entries(&self) -> Vec<&AuditEntry> {
        if self.filter_text.is_empty() {
            self.entries.iter().collect()
        } else {
            self.entries
                .iter()
                .filter(|e| {
                    e.principal.contains(&self.filter_text)
                        || e.action_kind.contains(&self.filter_text)
                        || e.decision.contains(&self.filter_text)
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn make_key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn make_app() -> App {
        App::new(PathBuf::from("/tmp/nonexistent-test-ledger.db"))
    }

    fn sample_entry(principal: &str, decision: &str, action_kind: &str) -> AuditEntry {
        use chrono::Utc;
        AuditEntry {
            entry_id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            action_id: uuid::Uuid::new_v4(),
            action_kind: action_kind.to_string(),
            principal: principal.to_string(),
            decision: decision.to_string(),
            reason: "test reason".to_string(),
            policy_id: None,
            prev_hash: "genesis".to_string(),
            entry_hash: "abc123".to_string(),
        }
    }

    #[test]
    fn initial_mode_is_audit_feed() {
        let app = make_app();
        assert!(matches!(app.mode, AppMode::AuditFeed));
        assert!(app.running);
    }

    #[test]
    fn transition_audit_to_policy_and_back() {
        let mut app = make_app();
        app.handle_key(make_key(KeyCode::Char('p')));
        assert!(matches!(app.mode, AppMode::PolicyView));
        app.handle_key(make_key(KeyCode::Char('a')));
        assert!(matches!(app.mode, AppMode::AuditFeed));
    }

    #[test]
    fn transition_policy_to_audit_via_esc() {
        let mut app = make_app();
        app.handle_key(make_key(KeyCode::Char('p')));
        assert!(matches!(app.mode, AppMode::PolicyView));
        app.handle_key(make_key(KeyCode::Esc));
        assert!(matches!(app.mode, AppMode::AuditFeed));
    }

    #[test]
    fn filter_mode_entry_and_exit() {
        let mut app = make_app();
        app.handle_key(make_key(KeyCode::Char('/')));
        assert!(matches!(app.mode, AppMode::FilterMode));
        assert!(app.filter_text.is_empty());

        app.handle_key(make_key(KeyCode::Char('a')));
        app.handle_key(make_key(KeyCode::Char('b')));
        assert_eq!(app.filter_text, "ab");

        app.handle_key(make_key(KeyCode::Backspace));
        assert_eq!(app.filter_text, "a");

        app.handle_key(make_key(KeyCode::Enter));
        assert!(matches!(app.mode, AppMode::AuditFeed));
        assert_eq!(app.filter_text, "a");
    }

    #[test]
    fn filter_mode_exit_via_esc() {
        let mut app = make_app();
        app.handle_key(make_key(KeyCode::Char('/')));
        app.handle_key(make_key(KeyCode::Char('x')));
        app.handle_key(make_key(KeyCode::Esc));
        assert!(matches!(app.mode, AppMode::AuditFeed));
    }

    #[test]
    fn navigate_down_with_j() {
        let mut app = make_app();
        app.entries = vec![
            sample_entry("alice", "Allow", "FileRead"),
            sample_entry("bob", "Deny", "NetConnect"),
        ];
        assert_eq!(app.selected_index, 0);

        app.handle_key(make_key(KeyCode::Char('j')));
        assert_eq!(app.selected_index, 1);

        // Should not go past the last entry
        app.handle_key(make_key(KeyCode::Char('j')));
        assert_eq!(app.selected_index, 1);
    }

    #[test]
    fn navigate_up_with_k() {
        let mut app = make_app();
        app.entries = vec![
            sample_entry("alice", "Allow", "FileRead"),
            sample_entry("bob", "Deny", "NetConnect"),
        ];
        app.selected_index = 1;

        app.handle_key(make_key(KeyCode::Char('k')));
        assert_eq!(app.selected_index, 0);

        // Should not go below zero
        app.handle_key(make_key(KeyCode::Char('k')));
        assert_eq!(app.selected_index, 0);
    }

    #[test]
    fn navigate_with_arrow_keys() {
        let mut app = make_app();
        app.entries = vec![
            sample_entry("a", "Allow", "FileRead"),
            sample_entry("b", "Deny", "NetConnect"),
            sample_entry("c", "Allow", "FileWrite"),
        ];

        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.selected_index, 1);
        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.selected_index, 2);
        app.handle_key(make_key(KeyCode::Up));
        assert_eq!(app.selected_index, 1);
    }

    #[test]
    fn empty_app_does_not_panic_on_refresh() {
        let mut app = make_app();
        let result = app.refresh();
        assert!(result.is_ok());
        assert!(app.entries.is_empty());
        assert_eq!(app.total_count, 0);
    }

    #[test]
    fn filtered_entries_returns_all_when_no_filter() {
        let mut app = make_app();
        app.entries = vec![
            sample_entry("alice", "Allow", "FileRead"),
            sample_entry("bob", "Deny", "NetConnect"),
        ];

        let filtered = app.filtered_entries();
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn filtered_entries_filters_by_principal() {
        let mut app = make_app();
        app.entries = vec![
            sample_entry("alice", "Allow", "FileRead"),
            sample_entry("bob", "Deny", "NetConnect"),
            sample_entry("alice", "Deny", "FileWrite"),
        ];
        app.filter_text = "alice".to_string();

        let filtered = app.filtered_entries();
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|e| e.principal == "alice"));
    }

    #[test]
    fn filtered_entries_filters_by_decision() {
        let mut app = make_app();
        app.entries = vec![
            sample_entry("alice", "Allow", "FileRead"),
            sample_entry("bob", "Deny", "NetConnect"),
        ];
        app.filter_text = "Deny".to_string();

        let filtered = app.filtered_entries();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].decision, "Deny");
    }

    #[test]
    fn filtered_entries_filters_by_action_kind() {
        let mut app = make_app();
        app.entries = vec![
            sample_entry("alice", "Allow", "FileRead"),
            sample_entry("bob", "Deny", "NetConnect"),
        ];
        app.filter_text = "NetConnect".to_string();

        let filtered = app.filtered_entries();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].action_kind, "NetConnect");
    }

    #[test]
    fn refresh_with_real_db() {
        use aegis_ledger::AuditStore;
        use aegis_types::{Action, ActionKind, Verdict};

        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let mut store = AuditStore::open(tmp.path()).expect("failed to open store");

        let action = Action::new(
            "test-agent",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );
        let verdict = Verdict::allow(action.id, "ok", None);
        store.append(&action, &verdict).expect("failed to append");

        let action2 = Action::new(
            "test-agent",
            ActionKind::NetConnect {
                host: "example.com".into(),
                port: 443,
            },
        );
        let verdict2 = Verdict::deny(action2.id, "blocked", Some("pol-1".into()));
        store.append(&action2, &verdict2).expect("failed to append");

        // Drop the store to release the write lock
        drop(store);

        let mut app = App::new(tmp.path().to_path_buf());
        app.refresh().expect("refresh should succeed");

        assert_eq!(app.total_count, 2);
        assert_eq!(app.allow_count, 1);
        assert_eq!(app.deny_count, 1);
        assert_eq!(app.entries.len(), 2);
    }
}
