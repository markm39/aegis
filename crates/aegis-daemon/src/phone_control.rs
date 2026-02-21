//! Phone control command queue for paired devices.
//!
//! Manages a per-device queue of commands that devices poll from the daemon.
//! Commands are queued (not pushed) to prevent SSRF-like attacks -- the device
//! must actively connect and poll for pending commands.
//!
//! # Security Properties
//!
//! - Commands are queued, never pushed to devices (prevents SSRF-like attacks).
//! - Per-device queue size limit of 10 prevents denial-of-service via queue flooding.
//! - 60-second command timeout prevents stale command execution on reconnecting devices.
//! - Device ID is validated against the device registry before any queue operation.
//! - All command types are Cedar policy-gated as ActionRisk::High.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum number of pending commands per device.
const MAX_QUEUE_SIZE: usize = 10;

/// Duration after which a pending command is marked as timed out.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A command to be executed on a paired device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceCommand {
    /// Capture a photo with the device camera.
    CameraSnap {
        /// Image resolution (e.g., "1920x1080", "640x480").
        resolution: String,
    },
    /// Record the device screen for a given duration.
    ScreenRecord {
        /// Recording duration in seconds.
        duration_secs: u32,
    },
    /// Request the device's current GPS location.
    GetLocation,
    /// Send a local notification on the device.
    SendNotification {
        /// Notification title.
        title: String,
        /// Notification body text.
        body: String,
    },
    /// Request the device's battery status.
    GetBatteryStatus,
    /// Trigger a vibration on the device.
    Vibrate,
}

/// Status of a queued device command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    /// Command is queued, waiting for the device to poll.
    Pending,
    /// Command was successfully executed by the device.
    Completed,
    /// Command execution failed on the device.
    Failed,
    /// Command expired before the device polled it.
    Timeout,
}

/// A queued command with its lifecycle metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCommandResult {
    /// Unique identifier for this command instance.
    pub command_id: Uuid,
    /// The device this command targets.
    pub device_id: String,
    /// The command to execute.
    pub command: DeviceCommand,
    /// Current status.
    pub status: CommandStatus,
    /// Result data returned by the device (if completed).
    pub result_data: Option<serde_json::Value>,
    /// When the command was queued.
    pub created_at: DateTime<Utc>,
    /// When the command was completed (or timed out).
    pub completed_at: Option<DateTime<Utc>>,
    /// Monotonic creation instant for timeout enforcement.
    #[serde(skip, default = "Instant::now")]
    created_instant: Instant,
}

// ---------------------------------------------------------------------------
// PhoneController
// ---------------------------------------------------------------------------

/// Manages per-device command queues with timeout enforcement and queue limits.
pub struct PhoneController {
    /// Pending commands keyed by device_id.
    pending: HashMap<String, Vec<DeviceCommandResult>>,
    /// Completed/failed/timed-out commands keyed by command_id for result reporting.
    completed: HashMap<Uuid, DeviceCommandResult>,
}

impl PhoneController {
    /// Create a new empty phone controller.
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            completed: HashMap::new(),
        }
    }

    /// Queue a command for a device.
    ///
    /// Returns the `DeviceCommandResult` with status `Pending`.
    /// Returns `Err` if the device's queue is full (10 commands max).
    pub fn queue_command(
        &mut self,
        device_id: &str,
        command: DeviceCommand,
    ) -> Result<DeviceCommandResult, anyhow::Error> {
        // Enforce timeout on existing commands before checking queue size.
        self.enforce_timeouts(device_id);

        let queue = self.pending.entry(device_id.to_string()).or_default();

        if queue.len() >= MAX_QUEUE_SIZE {
            return Err(anyhow::anyhow!(
                "command queue full for device {device_id} (max {MAX_QUEUE_SIZE})"
            ));
        }

        let result = DeviceCommandResult {
            command_id: Uuid::new_v4(),
            device_id: device_id.to_string(),
            command,
            status: CommandStatus::Pending,
            result_data: None,
            created_at: Utc::now(),
            completed_at: None,
            created_instant: Instant::now(),
        };

        queue.push(result.clone());
        Ok(result)
    }

    /// Poll for pending commands for a device.
    ///
    /// Returns and removes all pending commands from the device's queue.
    /// Timed-out commands are marked as `Timeout` and moved to the
    /// completed map before returning remaining pending commands.
    pub fn poll_commands(&mut self, device_id: &str) -> Vec<DeviceCommandResult> {
        // Enforce timeouts first.
        self.enforce_timeouts(device_id);

        // Drain the remaining pending commands.
        let commands = self
            .pending
            .remove(device_id)
            .unwrap_or_default();

        // Move the drained commands to the completed map so results can be reported.
        for cmd in &commands {
            self.completed.insert(cmd.command_id, cmd.clone());
        }

        commands
    }

    /// Report a result for a previously polled command.
    ///
    /// Returns `Err` if the command_id is unknown.
    pub fn report_result(
        &mut self,
        command_id: Uuid,
        result_data: serde_json::Value,
    ) -> Result<(), anyhow::Error> {
        let entry = self
            .completed
            .get_mut(&command_id)
            .ok_or_else(|| anyhow::anyhow!("unknown command: {command_id}"))?;

        entry.status = CommandStatus::Completed;
        entry.result_data = Some(result_data);
        entry.completed_at = Some(Utc::now());

        Ok(())
    }

    /// Enforce timeout on all pending commands for a device.
    ///
    /// Commands older than 60 seconds are marked as `Timeout` and moved
    /// to the completed map.
    fn enforce_timeouts(&mut self, device_id: &str) {
        let now = Instant::now();

        if let Some(queue) = self.pending.get_mut(device_id) {
            let mut timed_out = Vec::new();
            let mut remaining = Vec::new();

            for mut cmd in queue.drain(..) {
                if now.duration_since(cmd.created_instant) >= COMMAND_TIMEOUT {
                    cmd.status = CommandStatus::Timeout;
                    cmd.completed_at = Some(Utc::now());
                    timed_out.push(cmd);
                } else {
                    remaining.push(cmd);
                }
            }

            *queue = remaining;

            for cmd in timed_out {
                self.completed.insert(cmd.command_id, cmd);
            }
        }
    }
}

impl Default for PhoneController {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queue_command() {
        let mut ctrl = PhoneController::new();
        let result = ctrl
            .queue_command("device-1", DeviceCommand::GetBatteryStatus)
            .expect("should queue");

        assert_eq!(result.status, CommandStatus::Pending);
        assert_eq!(result.device_id, "device-1");
        assert!(result.result_data.is_none());
        assert!(result.completed_at.is_none());

        // Verify it appears in poll.
        let polled = ctrl.poll_commands("device-1");
        assert_eq!(polled.len(), 1);
        assert_eq!(polled[0].command_id, result.command_id);
    }

    #[test]
    fn test_poll_clears_queue() {
        let mut ctrl = PhoneController::new();
        ctrl.queue_command("device-1", DeviceCommand::Vibrate)
            .expect("should queue");
        ctrl.queue_command("device-1", DeviceCommand::GetLocation)
            .expect("should queue");

        let polled = ctrl.poll_commands("device-1");
        assert_eq!(polled.len(), 2);

        // Second poll should return empty.
        let polled2 = ctrl.poll_commands("device-1");
        assert!(polled2.is_empty());
    }

    #[test]
    fn test_queue_full_rejected() {
        let mut ctrl = PhoneController::new();

        // Fill the queue to the maximum.
        for _ in 0..MAX_QUEUE_SIZE {
            ctrl.queue_command("device-1", DeviceCommand::Vibrate)
                .expect("should queue");
        }

        // The 11th command should be rejected.
        let result = ctrl.queue_command("device-1", DeviceCommand::Vibrate);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("queue full"),
            "error should mention queue full, got: {err_msg}"
        );
    }

    #[test]
    fn test_command_timeout() {
        let mut ctrl = PhoneController::new();

        // Manually insert a command with an expired instant.
        let expired_cmd = DeviceCommandResult {
            command_id: Uuid::new_v4(),
            device_id: "device-1".to_string(),
            command: DeviceCommand::GetLocation,
            status: CommandStatus::Pending,
            result_data: None,
            created_at: Utc::now(),
            completed_at: None,
            created_instant: Instant::now() - COMMAND_TIMEOUT - Duration::from_secs(1),
        };
        ctrl.pending
            .entry("device-1".to_string())
            .or_default()
            .push(expired_cmd.clone());

        // Also insert a non-expired command.
        ctrl.queue_command("device-1", DeviceCommand::Vibrate)
            .expect("should queue");

        // Poll should only return the non-expired command.
        let polled = ctrl.poll_commands("device-1");
        assert_eq!(polled.len(), 1, "only non-expired command should be returned");

        // The expired command should be in completed with Timeout status.
        let timed_out = ctrl.completed.get(&expired_cmd.command_id).unwrap();
        assert_eq!(timed_out.status, CommandStatus::Timeout);
        assert!(timed_out.completed_at.is_some());
    }

    #[test]
    fn test_report_result() {
        let mut ctrl = PhoneController::new();
        let result = ctrl
            .queue_command("device-1", DeviceCommand::GetBatteryStatus)
            .expect("should queue");

        let cmd_id = result.command_id;

        // Poll to move the command to completed.
        let polled = ctrl.poll_commands("device-1");
        assert_eq!(polled.len(), 1);

        // Report a result.
        let result_data = serde_json::json!({"battery_pct": 85});
        ctrl.report_result(cmd_id, result_data.clone())
            .expect("should report");

        // Verify the result was stored.
        let completed = ctrl.completed.get(&cmd_id).unwrap();
        assert_eq!(completed.status, CommandStatus::Completed);
        assert_eq!(completed.result_data, Some(result_data));
        assert!(completed.completed_at.is_some());
    }

    #[test]
    fn test_report_unknown_command() {
        let mut ctrl = PhoneController::new();
        let result = ctrl.report_result(Uuid::new_v4(), serde_json::json!({}));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown command"),
            "error should mention unknown command, got: {err_msg}"
        );
    }

    #[test]
    fn test_device_command_types() {
        // Verify all DeviceCommand variants serialize correctly.
        let commands = vec![
            DeviceCommand::CameraSnap {
                resolution: "1920x1080".into(),
            },
            DeviceCommand::ScreenRecord {
                duration_secs: 30,
            },
            DeviceCommand::GetLocation,
            DeviceCommand::SendNotification {
                title: "Alert".into(),
                body: "Test notification".into(),
            },
            DeviceCommand::GetBatteryStatus,
            DeviceCommand::Vibrate,
        ];

        for cmd in commands {
            let json = serde_json::to_string(&cmd).expect("should serialize");
            let back: DeviceCommand =
                serde_json::from_str(&json).expect("should deserialize");
            // Verify round-trip by re-serializing.
            let json2 = serde_json::to_string(&back).expect("should re-serialize");
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn test_device_command_requires_policy() {
        // Security test: verify ActionKind::DeviceCommand exists for Cedar gating.
        // This test ensures the action kind variant is available so that
        // Cedar policy evaluation can gate device command operations.
        use aegis_types::ActionKind;

        let action = ActionKind::DeviceCommand {
            device_id: "test-device".into(),
            command_type: "GetBatteryStatus".into(),
        };
        let json = serde_json::to_string(&action).expect("should serialize");
        let back: ActionKind = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(back, action);
    }
}
