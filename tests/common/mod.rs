//! Shared helpers for integration tests.
//!
//! Each integration test file compiles common/ as its own module, so not
//! every helper is used in every file.
#![allow(dead_code)]

use std::path::PathBuf;

use tempfile::NamedTempFile;

use aegis_ledger::AuditStore;
use aegis_types::{Action, ActionKind};

/// Create a temporary file for use as a test database.
pub fn temp_db() -> NamedTempFile {
    NamedTempFile::new().expect("should create temp file for ledger database")
}

/// Open an AuditStore on the given temp file.
pub fn open_test_store(tmp: &NamedTempFile) -> AuditStore {
    AuditStore::open(tmp.path()).expect("should open audit store")
}

/// Create a FileRead action.
pub fn file_read_action(principal: &str, path: &str) -> Action {
    Action::new(
        principal,
        ActionKind::FileRead {
            path: PathBuf::from(path),
        },
    )
}

/// Create a FileWrite action.
pub fn file_write_action(principal: &str, path: &str) -> Action {
    Action::new(
        principal,
        ActionKind::FileWrite {
            path: PathBuf::from(path),
        },
    )
}

/// Create a DirList action.
pub fn dir_list_action(principal: &str, path: &str) -> Action {
    Action::new(
        principal,
        ActionKind::DirList {
            path: PathBuf::from(path),
        },
    )
}

/// Create a NetConnect action.
pub fn net_connect_action(principal: &str, host: &str, port: u16) -> Action {
    Action::new(
        principal,
        ActionKind::NetConnect {
            host: host.to_string(),
            port,
        },
    )
}
