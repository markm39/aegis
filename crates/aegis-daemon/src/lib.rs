//! Aegis daemon: persistent multi-agent lifecycle management.
//!
//! The daemon runs as a single persistent process managing a "fleet" of
//! supervised AI agent processes. Each agent runs in its own thread with
//! its own PTY, policy engine, adapter, and audit session.
//!
//! # Architecture
//!
//! - [`fleet::Fleet`]: owns all agent slots, handles spawning/stopping
//! - [`slot::AgentSlot`]: runtime state for one agent
//! - [`lifecycle`]: per-agent thread body (PTY + supervisor + audit)
//! - [`persistence`]: launchd integration, PID files, caffeinate
//! - [`state`]: crash recovery via persistent state.json

pub mod fleet;
pub mod lifecycle;
pub mod persistence;
pub mod slot;
pub mod state;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::info;

use aegis_types::daemon::DaemonConfig;
use aegis_types::AegisConfig;

use crate::fleet::Fleet;
use crate::state::DaemonState;

/// The daemon runtime: main loop managing the fleet and control plane.
pub struct DaemonRuntime {
    /// Fleet of managed agents.
    pub fleet: Fleet,
    /// Daemon configuration.
    pub config: DaemonConfig,
    /// Shutdown signal.
    pub shutdown: Arc<AtomicBool>,
    /// When the daemon started.
    pub started_at: Instant,
}

impl DaemonRuntime {
    /// Create a new daemon runtime from configuration.
    pub fn new(config: DaemonConfig, aegis_config: AegisConfig) -> Self {
        let fleet = Fleet::new(&config, aegis_config);

        Self {
            fleet,
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            started_at: Instant::now(),
        }
    }

    /// Run the daemon main loop. Blocks until shutdown is signaled.
    ///
    /// 1. Write PID file
    /// 2. Recover from previous crash (if applicable)
    /// 3. Start all enabled agents
    /// 4. Enter tick loop (health checks, restart logic, output draining)
    /// 5. On shutdown: stop all agents, clean up
    pub fn run(&mut self) -> Result<(), String> {
        // Write PID file
        let _pid_path = persistence::write_pid_file()?;

        // Check for previous state and recover
        if let Some(prev_state) = DaemonState::load() {
            state::recover_from_crash(&prev_state);
        }

        // Optionally start caffeinate
        let _caffeinate_pid = if self.config.persistence.prevent_sleep {
            Some(persistence::start_caffeinate()?)
        } else {
            None
        };

        info!(
            agents = self.fleet.agent_count(),
            "daemon starting"
        );

        // Start all enabled agents
        self.fleet.start_all();

        // Main loop
        let tick_interval = Duration::from_secs(1);
        let state_save_interval = Duration::from_secs(30);
        let mut last_state_save = Instant::now();

        while !self.shutdown.load(Ordering::Relaxed) {
            // Tick the fleet (check for exits, apply restart policies)
            self.fleet.tick();

            // Periodically save state
            if last_state_save.elapsed() >= state_save_interval {
                self.save_state();
                last_state_save = Instant::now();
            }

            // Sleep until next tick
            std::thread::sleep(tick_interval);
        }

        info!("daemon shutting down");

        // Save final state
        self.save_state();

        // Clean up
        persistence::remove_pid_file();
        DaemonState::remove();

        info!("daemon shutdown complete");
        Ok(())
    }

    /// Signal the daemon to shut down.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Get the shutdown flag for external signal handlers.
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Daemon uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Save current state to disk.
    fn save_state(&self) {
        let mut daemon_state = DaemonState::new(std::process::id());
        daemon_state.started_at = chrono::Utc::now()
            - chrono::Duration::seconds(self.started_at.elapsed().as_secs() as i64);

        for name in self.fleet.agent_names() {
            if let Some(slot) = self.fleet.slot(&name) {
                daemon_state.agents.push(state::AgentState {
                    name: name.clone(),
                    was_running: slot.is_thread_alive(),
                    session_id: None, // Could be populated from lifecycle
                    restart_count: slot.restart_count,
                });
            }
        }

        if let Err(e) = daemon_state.save() {
            tracing::warn!(error = e, "failed to save daemon state");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::daemon::{DaemonControlConfig, PersistenceConfig};
    use std::path::PathBuf;

    #[test]
    fn daemon_runtime_creation() {
        let config = DaemonConfig {
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            alerts: vec![],
            agents: vec![],
            channel: None,
        };
        let aegis_config = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));

        let runtime = DaemonRuntime::new(config, aegis_config);
        assert_eq!(runtime.fleet.agent_count(), 0);
        assert!(!runtime.shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn shutdown_flag() {
        let config = DaemonConfig {
            persistence: PersistenceConfig::default(),
            control: DaemonControlConfig::default(),
            alerts: vec![],
            agents: vec![],
            channel: None,
        };
        let aegis_config = AegisConfig::default_for("test", &PathBuf::from("/tmp/aegis"));

        let runtime = DaemonRuntime::new(config, aegis_config);
        let flag = runtime.shutdown_flag();

        assert!(!flag.load(Ordering::Relaxed));
        runtime.request_shutdown();
        assert!(flag.load(Ordering::Relaxed));
    }
}
