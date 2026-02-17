//! Application state machine for the monitor TUI.
//!
//! Manages the current view mode, cached audit entries, aggregate
//! statistics, and keyboard navigation state. Data is refreshed from
//! the SQLite ledger on every tick via a read-only connection.

use std::path::PathBuf;

use rusqlite::{params, Connection};
use tracing::warn;

use aegis_ledger::AuditEntry;

/// The active view mode of the dashboard.
pub enum AppMode {
    /// Live audit feed -- the default view.
    AuditFeed,
    /// Policy summary view.
    PolicyView,
    /// Text filter input mode.
    FilterMode,
    /// Session list view -- shows recent sessions.
    SessionList,
    /// Session detail view -- shows entries for one session.
    SessionDetail,
}

/// Minimal session data loaded from the DB by the monitor.
///
/// We avoid depending on `aegis_ledger::Session` directly because the
/// monitor opens its own read-only connection and maps rows itself.
#[derive(Clone)]
pub struct MonitorSession {
    pub session_id: String,
    #[allow(dead_code)] // populated from DB; will be rendered in session detail view
    pub config_name: String,
    pub command: String,
    pub start_time: String,
    #[allow(dead_code)] // populated from DB; will be rendered in session detail view
    pub end_time: Option<String>,
    pub exit_code: Option<i32>,
    pub total_actions: usize,
    pub denied_actions: usize,
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
    /// Cached sessions for the SessionList view.
    pub sessions: Vec<MonitorSession>,
    /// Highlighted row in the session list.
    pub session_selected: usize,
    /// Audit entries for the currently selected session (SessionDetail view).
    pub session_entries: Vec<AuditEntry>,
    /// The session being viewed in SessionDetail.
    pub session_detail: Option<MonitorSession>,
    /// Highlighted row in session detail entry list.
    pub session_detail_selected: usize,
    /// Action kind distribution: (action_kind, count), sorted by count DESC.
    pub action_distribution: Vec<(String, usize)>,
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
            sessions: Vec::new(),
            session_selected: 0,
            session_entries: Vec::new(),
            session_detail: None,
            session_detail_selected: 0,
            action_distribution: Vec::new(),
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

        let rows = stmt.query_map([], aegis_ledger::row_to_entry)?;

        self.entries = rows.collect::<Result<Vec<_>, _>>()?;

        // Clamp selected_index to valid range
        if !self.entries.is_empty() && self.selected_index >= self.entries.len() {
            self.selected_index = self.entries.len() - 1;
        }

        // Sessions (last 50)
        self.sessions = Self::load_sessions(&conn);

        if !self.sessions.is_empty() && self.session_selected >= self.sessions.len() {
            self.session_selected = self.sessions.len() - 1;
        }

        // Action kind distribution
        self.action_distribution = Self::load_action_distribution(&conn);

        Ok(())
    }

    /// Load recent sessions from the DB.
    fn load_sessions(conn: &Connection) -> Vec<MonitorSession> {
        let mut stmt = match conn.prepare(
            "SELECT session_id, config_name, command, start_time, end_time, \
                    exit_code, total_actions, denied_actions \
             FROM sessions ORDER BY id DESC LIMIT 50",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map([], |row| {
            Ok(MonitorSession {
                session_id: row.get(0)?,
                config_name: row.get(1)?,
                command: row.get(2)?,
                start_time: row.get(3)?,
                end_time: row.get(4)?,
                exit_code: row.get(5)?,
                total_actions: row.get::<_, i64>(6).map(|v| v as usize)?,
                denied_actions: row.get::<_, i64>(7).map(|v| v as usize)?,
            })
        }) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Load action kind distribution from the DB.
    fn load_action_distribution(conn: &Connection) -> Vec<(String, usize)> {
        let mut stmt = match conn.prepare(
            "SELECT action_kind, COUNT(*) as cnt FROM audit_log \
             GROUP BY action_kind ORDER BY cnt DESC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
        }) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Load entries for a specific session.
    fn load_session_entries(conn: &Connection, session_id: &str) -> Vec<AuditEntry> {
        let mut stmt = match conn.prepare(
            "SELECT entry_id, timestamp, action_id, action_kind, principal, \
                    decision, reason, policy_id, prev_hash, entry_hash \
             FROM audit_log WHERE session_id = ?1 ORDER BY id ASC",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map(params![session_id], aegis_ledger::row_to_entry) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Handle a key event based on the current mode.
    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        match self.mode {
            AppMode::AuditFeed => match key.code {
                KeyCode::Char('p') => self.mode = AppMode::PolicyView,
                KeyCode::Char('s') => {
                    self.session_selected = 0;
                    self.mode = AppMode::SessionList;
                }
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
            AppMode::SessionList => match key.code {
                KeyCode::Esc | KeyCode::Char('a') => self.mode = AppMode::AuditFeed,
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.session_selected > 0 {
                        self.session_selected -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.session_selected < self.sessions.len().saturating_sub(1) {
                        self.session_selected += 1;
                    }
                }
                KeyCode::Enter => {
                    if let Some(session) = self.sessions.get(self.session_selected) {
                        let sid = session.session_id.clone();
                        self.drill_into_session(&sid);
                    }
                }
                _ => {}
            },
            AppMode::SessionDetail => match key.code {
                KeyCode::Esc => self.mode = AppMode::SessionList,
                KeyCode::Char('a') => self.mode = AppMode::AuditFeed,
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.session_detail_selected > 0 {
                        self.session_detail_selected -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.session_detail_selected
                        < self.session_entries.len().saturating_sub(1)
                    {
                        self.session_detail_selected += 1;
                    }
                }
                _ => {}
            },
        }
    }

    /// Drill into a session, loading its entries and switching to detail view.
    fn drill_into_session(&mut self, session_id: &str) {
        // Open a read-only connection to load session entries
        let conn = match Connection::open_with_flags(
            &self.ledger_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "cannot open ledger to load session entries");
                return;
            }
        };

        self.session_entries = Self::load_session_entries(&conn, session_id);
        self.session_detail_selected = 0;

        // Build a MonitorSession for the header from cached data
        self.session_detail = self
            .sessions
            .iter()
            .find(|s| s.session_id == session_id)
            .cloned();

        self.mode = AppMode::SessionDetail;
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

    use crate::test_helpers::sample_entry;

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

    #[test]
    fn transition_audit_to_sessions_and_back() {
        let mut app = make_app();
        app.handle_key(make_key(KeyCode::Char('s')));
        assert!(matches!(app.mode, AppMode::SessionList));

        app.handle_key(make_key(KeyCode::Esc));
        assert!(matches!(app.mode, AppMode::AuditFeed));
    }

    #[test]
    fn transition_sessions_to_audit_via_a() {
        let mut app = make_app();
        app.handle_key(make_key(KeyCode::Char('s')));
        assert!(matches!(app.mode, AppMode::SessionList));

        app.handle_key(make_key(KeyCode::Char('a')));
        assert!(matches!(app.mode, AppMode::AuditFeed));
    }

    #[test]
    fn session_list_navigation() {
        let mut app = make_app();
        app.sessions = vec![
            MonitorSession {
                session_id: "aaaa".to_string(),
                config_name: "test".to_string(),
                command: "cmd1".to_string(),
                start_time: "2026-01-01T00:00:00Z".to_string(),
                end_time: None,
                exit_code: None,
                total_actions: 0,
                denied_actions: 0,
            },
            MonitorSession {
                session_id: "bbbb".to_string(),
                config_name: "test".to_string(),
                command: "cmd2".to_string(),
                start_time: "2026-01-01T00:01:00Z".to_string(),
                end_time: Some("2026-01-01T00:02:00Z".to_string()),
                exit_code: Some(0),
                total_actions: 5,
                denied_actions: 1,
            },
        ];
        app.mode = AppMode::SessionList;
        assert_eq!(app.session_selected, 0);

        app.handle_key(make_key(KeyCode::Char('j')));
        assert_eq!(app.session_selected, 1);

        // Should not go past the last session
        app.handle_key(make_key(KeyCode::Char('j')));
        assert_eq!(app.session_selected, 1);

        app.handle_key(make_key(KeyCode::Char('k')));
        assert_eq!(app.session_selected, 0);

        // Should not go below zero
        app.handle_key(make_key(KeyCode::Char('k')));
        assert_eq!(app.session_selected, 0);
    }

    #[test]
    fn session_detail_navigation() {
        let mut app = make_app();
        app.mode = AppMode::SessionDetail;
        app.session_entries = vec![
            sample_entry("alice", "Allow", "FileRead"),
            sample_entry("bob", "Deny", "NetConnect"),
            sample_entry("charlie", "Allow", "FileWrite"),
        ];
        app.session_detail_selected = 0;

        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.session_detail_selected, 1);
        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.session_detail_selected, 2);
        app.handle_key(make_key(KeyCode::Down));
        assert_eq!(app.session_detail_selected, 2);

        app.handle_key(make_key(KeyCode::Up));
        assert_eq!(app.session_detail_selected, 1);
    }

    #[test]
    fn session_detail_esc_returns_to_session_list() {
        let mut app = make_app();
        app.mode = AppMode::SessionDetail;

        app.handle_key(make_key(KeyCode::Esc));
        assert!(matches!(app.mode, AppMode::SessionList));
    }

    #[test]
    fn session_detail_a_returns_to_audit() {
        let mut app = make_app();
        app.mode = AppMode::SessionDetail;

        app.handle_key(make_key(KeyCode::Char('a')));
        assert!(matches!(app.mode, AppMode::AuditFeed));
    }

    #[test]
    fn refresh_with_sessions() {
        use aegis_ledger::AuditStore;
        use aegis_types::{Action, ActionKind, Verdict};

        let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
        let mut store = AuditStore::open(tmp.path()).expect("failed to open store");

        let session_id = store
            .begin_session("test-config", "echo", &["hello".into()], None)
            .expect("begin_session should succeed");

        let action = Action::new(
            "test-agent",
            ActionKind::FileRead {
                path: PathBuf::from("/tmp/test.txt"),
            },
        );
        let verdict = Verdict::allow(action.id, "ok", None);
        store
            .append_with_session(&action, &verdict, &session_id)
            .expect("failed to append");

        store.end_session(&session_id, 0).unwrap();
        drop(store);

        let mut app = App::new(tmp.path().to_path_buf());
        app.refresh().expect("refresh should succeed");

        assert_eq!(app.sessions.len(), 1);
        assert_eq!(app.sessions[0].command, "echo");
        assert_eq!(app.sessions[0].total_actions, 1);
        assert_eq!(app.sessions[0].exit_code, Some(0));

        assert_eq!(app.action_distribution.len(), 1);
        assert!(app.action_distribution[0].0.contains("FileRead"));
        assert_eq!(app.action_distribution[0].1, 1);
    }

    #[test]
    fn enter_on_session_list_with_no_sessions_stays() {
        let mut app = make_app();
        app.mode = AppMode::SessionList;
        app.handle_key(make_key(KeyCode::Enter));
        // Should stay in SessionList since there are no sessions to drill into
        assert!(matches!(app.mode, AppMode::SessionList));
    }

    #[test]
    fn s_key_resets_session_selected() {
        let mut app = make_app();
        app.session_selected = 5;
        app.handle_key(make_key(KeyCode::Char('s')));
        assert!(matches!(app.mode, AppMode::SessionList));
        assert_eq!(app.session_selected, 0);
    }
}
