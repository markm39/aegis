/// Sidecar: lifecycle coordinator for the FUSE filesystem and network proxy.
///
/// Manages mounting/unmounting the AegisFuse filesystem and starting/stopping
/// the network proxy as a single unit.
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fuser::{BackgroundSession, MountOption};

use aegis_ledger::AuditStore;
use aegis_policy::PolicyEngine;
use aegis_types::AegisError;

use crate::fs::AegisFuse;

/// The sidecar coordinator that manages FUSE mount and network proxy lifecycle.
pub struct Sidecar {
    policy: Arc<Mutex<PolicyEngine>>,
    store: Arc<Mutex<AuditStore>>,
    principal: String,
    mount_point: PathBuf,
    passthrough_dir: PathBuf,
    fuse_session: Option<BackgroundSession>,
}

impl Sidecar {
    /// Create a new sidecar coordinator.
    ///
    /// - `policy`: shared policy engine for authorization decisions
    /// - `store`: shared audit store for logging verdicts
    /// - `principal`: agent name used as the Action principal
    /// - `mount_point`: where to mount the FUSE filesystem
    /// - `passthrough_dir`: the real directory being protected
    pub fn new(
        policy: Arc<Mutex<PolicyEngine>>,
        store: Arc<Mutex<AuditStore>>,
        principal: String,
        mount_point: PathBuf,
        passthrough_dir: PathBuf,
    ) -> Self {
        Self {
            policy,
            store,
            principal,
            mount_point,
            passthrough_dir,
            fuse_session: None,
        }
    }

    /// Mount the FUSE filesystem in the background.
    ///
    /// Uses `fuser::spawn_mount2` to start the filesystem on a background thread.
    /// Returns an error if the filesystem is already mounted or if mounting fails.
    pub fn start(&mut self) -> Result<(), AegisError> {
        if self.fuse_session.is_some() {
            return Err(AegisError::FsError(
                "FUSE filesystem is already mounted".to_string(),
            ));
        }

        let fuse = AegisFuse::new(
            Arc::clone(&self.policy),
            Arc::clone(&self.store),
            self.passthrough_dir.clone(),
            self.principal.clone(),
        );

        let options = vec![
            MountOption::AutoUnmount,
            MountOption::AllowOther,
            MountOption::RO,
        ];

        tracing::info!(
            mount_point = %self.mount_point.display(),
            passthrough_dir = %self.passthrough_dir.display(),
            principal = %self.principal,
            "mounting FUSE filesystem"
        );

        let session = fuser::spawn_mount2(fuse, &self.mount_point, &options)
            .map_err(|e| AegisError::FsError(format!("failed to mount FUSE: {e}")))?;

        self.fuse_session = Some(session);
        Ok(())
    }

    /// Unmount the FUSE filesystem by dropping the background session.
    ///
    /// Returns an error if no filesystem is currently mounted.
    pub fn stop(&mut self) -> Result<(), AegisError> {
        match self.fuse_session.take() {
            Some(session) => {
                tracing::info!(
                    mount_point = %self.mount_point.display(),
                    "unmounting FUSE filesystem"
                );
                drop(session);
                Ok(())
            }
            None => Err(AegisError::FsError(
                "no FUSE filesystem is mounted".to_string(),
            )),
        }
    }

    /// Check whether the FUSE filesystem is currently mounted.
    pub fn is_mounted(&self) -> bool {
        self.fuse_session.is_some()
    }

    /// Return the mount point path.
    pub fn mount_point(&self) -> &PathBuf {
        &self.mount_point
    }

    /// Return the passthrough directory path.
    pub fn passthrough_dir(&self) -> &PathBuf {
        &self.passthrough_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_ledger::AuditStore;
    use aegis_policy::PolicyEngine;
    use tempfile::NamedTempFile;

    fn make_sidecar() -> Sidecar {
        let engine = PolicyEngine::from_policies(
            r#"permit(principal, action, resource);"#,
            None,
        )
        .expect("should create policy engine");
        let db_file = NamedTempFile::new().expect("should create temp file");
        let store = AuditStore::open(db_file.path()).expect("should open audit store");

        Sidecar::new(
            Arc::new(Mutex::new(engine)),
            Arc::new(Mutex::new(store)),
            "test-agent".to_string(),
            PathBuf::from("/tmp/aegis-mount"),
            PathBuf::from("/tmp/aegis-real"),
        )
    }

    #[test]
    fn sidecar_creation() {
        let sidecar = make_sidecar();
        assert_eq!(sidecar.principal, "test-agent");
        assert_eq!(sidecar.mount_point, PathBuf::from("/tmp/aegis-mount"));
        assert_eq!(sidecar.passthrough_dir, PathBuf::from("/tmp/aegis-real"));
        assert!(!sidecar.is_mounted());
    }

    #[test]
    fn sidecar_not_mounted_initially() {
        let sidecar = make_sidecar();
        assert!(!sidecar.is_mounted());
    }

    #[test]
    fn sidecar_stop_without_start_errors() {
        let mut sidecar = make_sidecar();
        let result = sidecar.stop();
        assert!(result.is_err());
    }

    #[test]
    fn sidecar_accessors() {
        let sidecar = make_sidecar();
        assert_eq!(sidecar.mount_point(), &PathBuf::from("/tmp/aegis-mount"));
        assert_eq!(sidecar.passthrough_dir(), &PathBuf::from("/tmp/aegis-real"));
    }
}
