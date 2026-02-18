//! Application state machine for the monitor TUI.
//!
//! Manages the current view mode, cached audit entries, aggregate
//! statistics, and keyboard navigation state. Data is refreshed from
//! the SQLite ledger on every tick via a read-only connection.

use std::path::PathBuf;

use rusqlite::{params, Connection};
use tracing::warn;

use aegis_ledger::AuditEntry;

/// Move a list selection index up or down, clamping to valid range.
fn navigate(selected: &mut usize, list_len: usize, up: bool) {
    if up {
        *selected = selected.saturating_sub(1);
    } else if *selected < list_len.saturating_sub(1) {
        *selected += 1;
    }
}

/// Maximum number of audit entries to load in the main feed.
const AUDIT_FEED_LIMIT: usize = 100;

/// Maximum number of sessions to load in the session list.
const SESSION_LIST_LIMIT: usize = 50;

/// Maximum recent entries to load per config in the home dashboard.
const HOME_RECENT_PER_CONFIG: usize = 10;

/// Maximum total merged recent entries shown on the home dashboard.
const HOME_RECENT_TOTAL: usize = 20;

/// The active view mode of the dashboard.
pub enum AppMode {
    /// Dashboard home -- config list and recent activity.
    Home,
    /// Live audit feed -- the default view for single-config monitor.
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

/// Configuration metadata for the dashboard home view.
#[derive(Clone)]
pub struct DashboardConfig {
    /// Display name of this configuration.
    pub name: String,
    /// Human-readable policy description (e.g. "permit-all", "custom").
    pub policy_desc: String,
    /// Isolation mode description (e.g. "Seatbelt", "Process").
    pub isolation: String,
    /// Path to the SQLite audit ledger.
    pub ledger_path: PathBuf,
}

/// Minimal session data loaded from the DB by the monitor.
///
/// We avoid depending on `aegis_ledger::Session` directly because the
/// monitor opens its own read-only connection and maps rows itself.
#[derive(Clone)]
pub struct MonitorSession {
    pub session_id: String,
    pub config_name: String,
    pub command: String,
    pub start_time: String,
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
    /// Cursor position within `filter_text` (byte offset).
    pub filter_cursor: usize,
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
    /// Whether running in dashboard mode (Home view available).
    pub dashboard_mode: bool,
    /// Config list for dashboard Home view.
    pub dashboard_configs: Vec<DashboardConfig>,
    /// Selected config index in Home view.
    pub home_selected: usize,
    /// Per-config stats for Home view: (total_actions, last_activity_timestamp).
    pub home_stats: Vec<(usize, Option<String>)>,
    /// Merged recent entries across all configs for Home view.
    pub home_recent: Vec<AuditEntry>,
    /// Name of the config currently being viewed (set when drilling in from Home).
    pub active_config_name: Option<String>,
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
            filter_cursor: 0,
            ledger_path,
            sessions: Vec::new(),
            session_selected: 0,
            session_entries: Vec::new(),
            session_detail: None,
            session_detail_selected: 0,
            action_distribution: Vec::new(),
            dashboard_mode: false,
            dashboard_configs: Vec::new(),
            home_selected: 0,
            home_stats: Vec::new(),
            home_recent: Vec::new(),
            active_config_name: None,
        }
    }

    /// Create a dashboard application with multiple configs.
    ///
    /// Starts in Home mode showing all configs. Enter drills into a
    /// specific config's audit feed; Esc returns to Home.
    pub fn new_dashboard(configs: Vec<DashboardConfig>) -> Self {
        let ledger_path = configs
            .first()
            .map(|c| c.ledger_path.clone())
            .unwrap_or_default();
        let mut app = Self::new(ledger_path);
        app.mode = AppMode::Home;
        app.dashboard_mode = true;
        app.dashboard_configs = configs;
        app
    }

    /// Refresh cached data from the audit ledger.
    ///
    /// Opens a read-only connection to the SQLite database and queries the
    /// last 100 entries plus aggregate counts. Silently logs a warning and
    /// returns Ok(()) if the database cannot be opened (e.g. it does not
    /// exist yet).
    pub fn refresh(&mut self) -> anyhow::Result<()> {
        if matches!(self.mode, AppMode::Home) {
            self.refresh_home();
            return Ok(());
        }

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
            .unwrap_or_else(|e| {
                warn!(error = %e, "failed to query total count");
                0
            }) as usize;

        // Allow count
        self.allow_count = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE decision = ?1",
                params!["Allow"],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|e| {
                warn!(error = %e, "failed to query allow count");
                0
            }) as usize;

        // Deny count
        self.deny_count = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE decision = ?1",
                params!["Deny"],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or_else(|e| {
                warn!(error = %e, "failed to query deny count");
                0
            }) as usize;

        // Most recent entries (most recent first)
        let mut stmt = conn.prepare(
            "SELECT entry_id, timestamp, action_id, action_kind, principal, \
                    decision, reason, policy_id, prev_hash, entry_hash \
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![AUDIT_FEED_LIMIT as i64], aegis_ledger::row_to_entry)?;

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
             FROM sessions ORDER BY id DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to prepare sessions query");
                return Vec::new();
            }
        };

        let rows = match stmt.query_map(params![SESSION_LIST_LIMIT as i64], |row| {
            Ok(MonitorSession {
                session_id: row.get(0)?,
                config_name: row.get(1)?,
                command: row.get(2)?,
                start_time: row.get(3)?,
                end_time: row.get(4)?,
                exit_code: row.get(5)?,
                total_actions: row.get::<_, i64>(6).map(|v| usize::try_from(v).unwrap_or(0))?,
                denied_actions: row.get::<_, i64>(7).map(|v| usize::try_from(v).unwrap_or(0))?,
            })
        }) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "failed to query sessions");
                return Vec::new();
            }
        };

        rows.filter_map(|r| match r {
            Ok(v) => Some(v),
            Err(e) => {
                warn!(error = %e, "failed to deserialize session row");
                None
            }
        })
        .collect()
    }

    /// Load action kind distribution from the DB.
    fn load_action_distribution(conn: &Connection) -> Vec<(String, usize)> {
        let mut stmt = match conn.prepare(
            "SELECT action_kind, COUNT(*) as cnt FROM audit_log \
             GROUP BY action_kind ORDER BY cnt DESC",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to prepare action distribution query");
                return Vec::new();
            }
        };

        let rows = match stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as usize))
        }) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "failed to query action distribution");
                return Vec::new();
            }
        };

        rows.filter_map(|r| match r {
            Ok(v) => Some(v),
            Err(e) => {
                warn!(error = %e, "failed to deserialize action distribution row");
                None
            }
        })
        .collect()
    }

    /// Refresh home view data by scanning all config ledgers.
    fn refresh_home(&mut self) {
        self.home_stats.clear();
        self.home_recent.clear();

        for config in &self.dashboard_configs {
            let conn = match Connection::open_with_flags(
                &config.ledger_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            ) {
                Ok(c) => c,
                Err(_) => {
                    self.home_stats.push((0, None));
                    continue;
                }
            };

            let total: usize = conn
                .query_row("SELECT COUNT(*) FROM audit_log", [], |r| {
                    r.get::<_, i64>(0)
                })
                .unwrap_or(0) as usize;

            let last: Option<String> = conn
                .query_row(
                    "SELECT timestamp FROM audit_log ORDER BY id DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .ok();

            // Grab recent entries from each config for the merged recent view
            let recent: Vec<AuditEntry> = conn
                .prepare(
                    "SELECT entry_id, timestamp, action_id, action_kind, principal, \
                            decision, reason, policy_id, prev_hash, entry_hash \
                     FROM audit_log ORDER BY id DESC LIMIT ?1",
                )
                .and_then(|mut stmt| {
                    let rows = stmt.query_map(
                        params![HOME_RECENT_PER_CONFIG as i64],
                        aegis_ledger::row_to_entry,
                    )?;
                    rows.collect()
                })
                .unwrap_or_default();

            self.home_stats.push((total, last));
            self.home_recent.extend(recent);
        }

        // Sort merged entries by timestamp (most recent first)
        self.home_recent.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        self.home_recent.truncate(HOME_RECENT_TOTAL);
    }

    /// Load entries for a specific session.
    fn load_session_entries(conn: &Connection, session_id: &str) -> Vec<AuditEntry> {
        let mut stmt = match conn.prepare(
            "SELECT entry_id, timestamp, action_id, action_kind, principal, \
                    decision, reason, policy_id, prev_hash, entry_hash \
             FROM audit_log WHERE session_id = ?1 ORDER BY id ASC",
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to prepare session entries query");
                return Vec::new();
            }
        };

        let rows = match stmt.query_map(params![session_id], aegis_ledger::row_to_entry) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "failed to query session entries");
                return Vec::new();
            }
        };

        rows.filter_map(|r| match r {
            Ok(v) => Some(v),
            Err(e) => {
                warn!(error = %e, "failed to deserialize session entry row");
                None
            }
        })
        .collect()
    }

    /// Handle a key event based on the current mode.
    ///
    /// The 'q' key quits from all modes except FilterMode (where it types
    /// the character). In dashboard mode, Esc from AuditFeed returns to Home.
    pub fn handle_key(&mut self, key: crossterm::event::KeyEvent) {
        use crossterm::event::KeyCode;
        match self.mode {
            AppMode::Home => match key.code {
                KeyCode::Char('q') => self.running = false,
                KeyCode::Up | KeyCode::Char('k') => {
                    navigate(&mut self.home_selected, self.dashboard_configs.len(), true);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    navigate(&mut self.home_selected, self.dashboard_configs.len(), false);
                }
                KeyCode::Enter => {
                    if let Some(config) = self.dashboard_configs.get(self.home_selected) {
                        self.ledger_path = config.ledger_path.clone();
                        self.active_config_name = Some(config.name.clone());
                        self.selected_index = 0;
                        self.filter_text.clear();
                        self.filter_cursor = 0;
                        self.mode = AppMode::AuditFeed;
                    }
                }
                _ => {}
            },
            AppMode::AuditFeed => match key.code {
                KeyCode::Char('q') => self.running = false,
                KeyCode::Esc if self.dashboard_mode => self.mode = AppMode::Home,
                KeyCode::Char('p') => self.mode = AppMode::PolicyView,
                KeyCode::Char('s') => {
                    self.session_selected = 0;
                    self.mode = AppMode::SessionList;
                }
                KeyCode::Char('/') => {
                    self.mode = AppMode::FilterMode;
                    self.filter_text.clear();
                    self.filter_cursor = 0;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    navigate(&mut self.selected_index, self.entries.len(), true);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    navigate(&mut self.selected_index, self.entries.len(), false);
                }
                _ => {}
            },
            AppMode::PolicyView => match key.code {
                KeyCode::Char('q') => self.running = false,
                KeyCode::Char('a') | KeyCode::Esc => self.mode = AppMode::AuditFeed,
                _ => {}
            },
            AppMode::FilterMode => match key.code {
                KeyCode::Esc => self.mode = AppMode::AuditFeed,
                KeyCode::Enter => self.mode = AppMode::AuditFeed,
                KeyCode::Char(c) => {
                    self.filter_text.insert(self.filter_cursor, c);
                    self.filter_cursor += c.len_utf8();
                }
                KeyCode::Backspace => {
                    if self.filter_cursor > 0 {
                        // Find the previous char boundary
                        let prev = self.filter_text[..self.filter_cursor]
                            .char_indices()
                            .next_back()
                            .map(|(i, _)| i)
                            .unwrap_or(0);
                        self.filter_text.remove(prev);
                        self.filter_cursor = prev;
                    }
                }
                KeyCode::Delete => {
                    if self.filter_cursor < self.filter_text.len() {
                        self.filter_text.remove(self.filter_cursor);
                    }
                }
                KeyCode::Left => {
                    if self.filter_cursor > 0 {
                        self.filter_cursor = self.filter_text[..self.filter_cursor]
                            .char_indices()
                            .next_back()
                            .map(|(i, _)| i)
                            .unwrap_or(0);
                    }
                }
                KeyCode::Right => {
                    if self.filter_cursor < self.filter_text.len() {
                        self.filter_cursor = self.filter_text[self.filter_cursor..]
                            .char_indices()
                            .nth(1)
                            .map(|(i, _)| self.filter_cursor + i)
                            .unwrap_or(self.filter_text.len());
                    }
                }
                KeyCode::Home => self.filter_cursor = 0,
                KeyCode::End => self.filter_cursor = self.filter_text.len(),
                _ => {}
            },
            AppMode::SessionList => match key.code {
                KeyCode::Char('q') => self.running = false,
                KeyCode::Esc | KeyCode::Char('a') => self.mode = AppMode::AuditFeed,
                KeyCode::Up | KeyCode::Char('k') => {
                    navigate(&mut self.session_selected, self.sessions.len(), true);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    navigate(&mut self.session_selected, self.sessions.len(), false);
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
                KeyCode::Char('q') => self.running = false,
                KeyCode::Esc => self.mode = AppMode::SessionList,
                KeyCode::Char('a') => self.mode = AppMode::AuditFeed,
                KeyCode::Up | KeyCode::Char('k') => {
                    navigate(&mut self.session_detail_selected, self.session_entries.len(), true);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    navigate(&mut self.session_detail_selected, self.session_entries.len(), false);
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

    #[test]
    fn q_quits_from_audit_feed() {
        let mut app = make_app();
        assert!(app.running);
        app.handle_key(make_key(KeyCode::Char('q')));
        assert!(!app.running);
    }

    #[test]
    fn q_types_in_filter_mode() {
        let mut app = make_app();
        app.mode = AppMode::FilterMode;
        app.handle_key(make_key(KeyCode::Char('q')));
        assert!(app.running);
        assert_eq!(app.filter_text, "q");
    }

    #[test]
    fn q_quits_from_session_list() {
        let mut app = make_app();
        app.mode = AppMode::SessionList;
        app.handle_key(make_key(KeyCode::Char('q')));
        assert!(!app.running);
    }

    fn make_dashboard_app() -> App {
        App::new_dashboard(vec![
            DashboardConfig {
                name: "config-a".into(),
                policy_desc: "permit-all".into(),
                isolation: "Process".into(),
                ledger_path: PathBuf::from("/tmp/a.db"),
            },
            DashboardConfig {
                name: "config-b".into(),
                policy_desc: "read-only".into(),
                isolation: "Seatbelt".into(),
                ledger_path: PathBuf::from("/tmp/b.db"),
            },
        ])
    }

    #[test]
    fn dashboard_starts_in_home_mode() {
        let app = make_dashboard_app();
        assert!(matches!(app.mode, AppMode::Home));
        assert!(app.dashboard_mode);
        assert_eq!(app.dashboard_configs.len(), 2);
    }

    #[test]
    fn home_navigate_and_enter() {
        let mut app = make_dashboard_app();
        assert_eq!(app.home_selected, 0);

        app.handle_key(make_key(KeyCode::Char('j')));
        assert_eq!(app.home_selected, 1);

        // Should not go past last config
        app.handle_key(make_key(KeyCode::Char('j')));
        assert_eq!(app.home_selected, 1);

        app.handle_key(make_key(KeyCode::Char('k')));
        assert_eq!(app.home_selected, 0);

        // Enter drills into AuditFeed for selected config
        app.handle_key(make_key(KeyCode::Enter));
        assert!(matches!(app.mode, AppMode::AuditFeed));
        assert_eq!(app.ledger_path, PathBuf::from("/tmp/a.db"));
    }

    #[test]
    fn esc_from_audit_to_home_in_dashboard() {
        let mut app = make_dashboard_app();
        app.handle_key(make_key(KeyCode::Enter)); // Home -> AuditFeed
        assert!(matches!(app.mode, AppMode::AuditFeed));

        app.handle_key(make_key(KeyCode::Esc));
        assert!(matches!(app.mode, AppMode::Home));
    }

    #[test]
    fn esc_does_nothing_in_audit_without_dashboard() {
        let mut app = make_app();
        assert!(matches!(app.mode, AppMode::AuditFeed));
        app.handle_key(make_key(KeyCode::Esc));
        // Should stay in AuditFeed (no dashboard mode)
        assert!(matches!(app.mode, AppMode::AuditFeed));
    }

    #[test]
    fn q_quits_from_home() {
        let mut app = make_dashboard_app();
        assert!(app.running);
        app.handle_key(make_key(KeyCode::Char('q')));
        assert!(!app.running);
    }

    #[test]
    fn home_enter_with_no_configs_stays() {
        let app_empty = App::new_dashboard(vec![]);
        let mut app = app_empty;
        app.handle_key(make_key(KeyCode::Enter));
        assert!(matches!(app.mode, AppMode::Home));
    }

    #[test]
    fn filter_cursor_movement() {
        let mut app = make_app();
        app.handle_key(make_key(KeyCode::Char('/')));
        assert!(matches!(app.mode, AppMode::FilterMode));
        assert_eq!(app.filter_cursor, 0);

        // Type "abc"
        app.handle_key(make_key(KeyCode::Char('a')));
        app.handle_key(make_key(KeyCode::Char('b')));
        app.handle_key(make_key(KeyCode::Char('c')));
        assert_eq!(app.filter_text, "abc");
        assert_eq!(app.filter_cursor, 3);

        // Left moves cursor back
        app.handle_key(make_key(KeyCode::Left));
        assert_eq!(app.filter_cursor, 2);

        // Insert at cursor
        app.handle_key(make_key(KeyCode::Char('X')));
        assert_eq!(app.filter_text, "abXc");
        assert_eq!(app.filter_cursor, 3);

        // Home goes to start
        app.handle_key(make_key(KeyCode::Home));
        assert_eq!(app.filter_cursor, 0);

        // End goes to end
        app.handle_key(make_key(KeyCode::End));
        assert_eq!(app.filter_cursor, 4);

        // Right at end stays at end
        app.handle_key(make_key(KeyCode::Right));
        assert_eq!(app.filter_cursor, 4);

        // Left at start stays at start
        app.handle_key(make_key(KeyCode::Home));
        app.handle_key(make_key(KeyCode::Left));
        assert_eq!(app.filter_cursor, 0);
    }

    #[test]
    fn filter_backspace_at_cursor() {
        let mut app = make_app();
        app.mode = AppMode::FilterMode;
        app.filter_text = "abcd".to_string();
        app.filter_cursor = 2; // cursor after 'b'

        app.handle_key(make_key(KeyCode::Backspace));
        assert_eq!(app.filter_text, "acd");
        assert_eq!(app.filter_cursor, 1);

        // Backspace at start does nothing
        app.handle_key(make_key(KeyCode::Home));
        app.handle_key(make_key(KeyCode::Backspace));
        assert_eq!(app.filter_text, "acd");
        assert_eq!(app.filter_cursor, 0);
    }

    #[test]
    fn filter_delete_at_cursor() {
        let mut app = make_app();
        app.mode = AppMode::FilterMode;
        app.filter_text = "abcd".to_string();
        app.filter_cursor = 1; // cursor on 'b'

        app.handle_key(make_key(KeyCode::Delete));
        assert_eq!(app.filter_text, "acd");
        assert_eq!(app.filter_cursor, 1);

        // Delete at end does nothing
        app.handle_key(make_key(KeyCode::End));
        app.handle_key(make_key(KeyCode::Delete));
        assert_eq!(app.filter_text, "acd");
    }
}
