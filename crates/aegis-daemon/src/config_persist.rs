//! Config reload, atomic config persistence, and state save.

use std::sync::atomic::Ordering;

use tracing::{info, warn};

use aegis_control::daemon::DaemonResponse;
use aegis_types::daemon::DaemonConfig;

use crate::state::DaemonState;
use crate::DaemonRuntime;

impl DaemonRuntime {
    /// Reload configuration from daemon.toml.
    ///
    /// Adds new agents, updates config for existing agents, and removes
    /// agents no longer in the config file. Running agents are NOT
    /// automatically restarted -- config changes take effect on next start.
    pub(crate) fn reload_config(&mut self) -> DaemonResponse {
        let config_path = aegis_types::daemon::daemon_config_path();
        let content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) => return DaemonResponse::error(format!("failed to read daemon.toml: {e}")),
        };
        let new_config = match DaemonConfig::from_toml(&content) {
            Ok(c) => c,
            Err(e) => return DaemonResponse::error(format!("failed to parse daemon.toml: {e}")),
        };

        let mut added = 0usize;
        let mut updated = 0usize;
        let mut removed = 0usize;

        // Collect current agent names
        let current_names: std::collections::HashSet<String> =
            self.fleet.agent_names().into_iter().collect();
        let new_names: std::collections::HashSet<String> =
            new_config.agents.iter().map(|a| a.name.to_string()).collect();

        // Remove agents no longer in config
        for name in current_names.difference(&new_names) {
            if self.fleet.agent_status(name).is_none() {
                continue;
            }
            self.remove_subagent_descendants(name);
            self.cleanup_agent_runtime_state(name);
            self.fleet.remove_agent(name);
            self.subagents.remove(name);
            removed += 1;
        }

        // Add or update agents
        let mut started = 0;
        for agent_config in &new_config.agents {
            if current_names.contains(agent_config.name.as_str()) {
                self.fleet.update_agent_config(agent_config);
                updated += 1;
            } else {
                self.fleet.add_agent(agent_config.clone());
                // Auto-start newly added enabled agents
                if agent_config.enabled {
                    self.fleet.start_agent(&agent_config.name);
                    started += 1;
                }
                added += 1;
            }
        }

        // Update fleet goal
        self.fleet.fleet_goal = new_config.goal.clone();

        // Reload cron scheduler with new job definitions, preserving last_fired
        // state for existing jobs so they don't fire again immediately.
        {
            let new_jobs: Vec<crate::cron::CronJob> = new_config
                .cron
                .jobs
                .iter()
                .filter_map(|jc| {
                    let schedule = match crate::cron::Schedule::parse(&jc.schedule) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(
                                name = %jc.name,
                                error = %e,
                                "skipping cron job with invalid schedule on reload"
                            );
                            return None;
                        }
                    };
                    Some(crate::cron::CronJob {
                        name: jc.name.clone(),
                        schedule,
                        command: jc.command.clone(),
                        enabled: jc.enabled,
                    })
                })
                .collect();
            let new_count = new_jobs.len();
            self.cron_scheduler.reload_jobs(new_jobs);
            info!(count = new_count, "cron scheduler reloaded");
        }

        // Update stored config
        self.config = new_config;

        // Reload policy engine (picks up new/changed .cedar files)
        let mut policy_warning: Option<String> = None;
        let policy_dir = self
            .aegis_config
            .policy_paths
            .first()
            .filter(|dir| {
                dir.is_dir()
                    && std::fs::read_dir(dir)
                        .ok()
                        .map(|entries| {
                            entries
                                .filter_map(|e| e.ok())
                                .any(|e| e.path().extension().is_some_and(|ext| ext == "cedar"))
                        })
                        .unwrap_or(false)
            })
            .cloned();
        if let Some(ref dir) = policy_dir {
            match aegis_policy::PolicyEngine::new(dir, None) {
                Ok(engine) => {
                    info!(policy_dir = %dir.display(), "policy engine reloaded");
                    self.policy_engine = Some(engine);
                }
                Err(e) => {
                    warn!(?e, "failed to reload policy engine, keeping previous");
                    policy_warning = Some(format!(" (policy reload failed: {e})"));
                }
            }
        } else if self.policy_engine.is_some() {
            warn!(
                "no policy directory found, clearing policy engine (hook checks now fail-closed)"
            );
            self.policy_engine = None;
        }

        let warning = policy_warning.unwrap_or_default();
        let msg = if started > 0 {
            format!("config reloaded: {added} added ({started} started), {updated} updated, {removed} removed{warning}")
        } else {
            format!("config reloaded: {added} added, {updated} updated, {removed} removed{warning}")
        };
        DaemonResponse::ok(msg)
    }

    /// Persist a config to daemon.toml.
    ///
    /// Uses atomic write (write to temp file, then rename) to prevent
    /// corruption if the process is interrupted mid-write.
    ///
    /// Accepts the config to write explicitly so callers can build a
    /// candidate config, persist it, and only then update in-memory state.
    /// This prevents memory/disk divergence if the write fails.
    pub(crate) fn persist_config_to_disk(config: &DaemonConfig) -> Result<(), String> {
        use std::sync::atomic::AtomicU64;
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let toml_str = config.to_toml().map_err(|e| e.to_string())?;
        let config_path = aegis_types::daemon::daemon_config_path();

        // Ensure the daemon directory exists (handles fresh installs, CI,
        // and recovery if someone deletes the config dir while running).
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create config directory: {e}"))?;
        }

        // Write to a uniquely-named sibling temp file, fsync, then rename for
        // crash safety. Without fsync, a power loss between write and rename could
        // leave the temp file empty/truncated, and rename would replace the good
        // config with a corrupt one.
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = config_path.with_extension(format!("toml.{n}.tmp"));

        let file = std::fs::File::create(&tmp_path)
            .map_err(|e| format!("failed to create temp config: {e}"))?;
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(toml_str.as_bytes())
            .map_err(|e| format!("failed to write temp config: {e}"))?;
        writer
            .flush()
            .map_err(|e| format!("failed to flush temp config: {e}"))?;
        writer
            .into_inner()
            .map_err(|e| format!("failed to finalize temp config: {e}"))?
            .sync_all()
            .map_err(|e| format!("failed to sync temp config to disk: {e}"))?;

        std::fs::rename(&tmp_path, &config_path)
            .map_err(|e| format!("failed to atomically replace config: {e}"))?;

        Ok(())
    }

    /// Save current state to disk.
    pub(crate) fn save_state(&self) {
        let mut daemon_state = DaemonState::new(std::process::id());
        daemon_state.started_at = chrono::Utc::now()
            - chrono::Duration::seconds(self.started_at.elapsed().as_secs() as i64);

        for name in self.fleet.agent_names() {
            if let Some(slot) = self.fleet.slot(&name) {
                let sid = *slot.session_id.lock();
                daemon_state.agents.push(crate::state::AgentState {
                    name: name.clone(),
                    was_running: slot.is_thread_alive(),
                    session_id: sid,
                    restart_count: slot.restart_count,
                    session_state: slot.session_state,
                    suspended_at: slot.suspended_at,
                    last_active_at: slot.last_active_at,
                    accumulated_active_secs: slot.accumulated_active_secs,
                    last_message_id: self.message_router.last_message_id(&name),
                });
            }
        }

        if let Err(e) = daemon_state.save() {
            tracing::warn!(error = %e, "failed to save daemon state, retrying");
            std::thread::sleep(std::time::Duration::from_millis(100));
            if let Err(e2) = daemon_state.save() {
                tracing::error!(error = %e2, "state save failed twice, persistence may be broken");
            }
        }
    }
}
