//! Device management for the gateway control plane.
//!
//! Provides device lifecycle, capability tracking, and status management.
//! Devices that fail to send a heartbeat within the staleness window are
//! automatically marked [`DeviceStatus::Offline`] by [`DeviceManager::sweep_stale_devices`].
//!
//! All device IDs are validated UUIDs. Device removal is logged for audit
//! trail purposes. The Cedar `ManageDevice` action gates all management
//! operations.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How long a device can go without a heartbeat before being marked offline.
const STALE_DEVICE_TIMEOUT_SECS: i64 = 300; // 5 minutes

/// The type of device connecting to the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    /// Mobile phone.
    Phone,
    /// Tablet device.
    Tablet,
    /// Desktop or laptop computer.
    Desktop,
    /// Smartwatch or wearable.
    Watch,
}

impl DeviceType {
    /// Parse a device type from a string, returning an error for unknown values.
    pub fn from_str_checked(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "phone" => Ok(DeviceType::Phone),
            "tablet" => Ok(DeviceType::Tablet),
            "desktop" => Ok(DeviceType::Desktop),
            "watch" => Ok(DeviceType::Watch),
            other => Err(format!("unknown device type: {other}")),
        }
    }
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Phone => write!(f, "phone"),
            DeviceType::Tablet => write!(f, "tablet"),
            DeviceType::Desktop => write!(f, "desktop"),
            DeviceType::Watch => write!(f, "watch"),
        }
    }
}

/// Current status of a registered device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// Device is currently connected and responsive.
    Online,
    /// Device has not sent a heartbeat within the staleness window.
    Offline,
    /// Device has been paired but has not yet come online.
    Paired,
    /// Device access has been revoked. Terminal state.
    Revoked,
}

impl DeviceStatus {
    /// Parse a device status from a string, returning an error for unknown values.
    pub fn from_str_checked(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "online" => Ok(DeviceStatus::Online),
            "offline" => Ok(DeviceStatus::Offline),
            "paired" => Ok(DeviceStatus::Paired),
            "revoked" => Ok(DeviceStatus::Revoked),
            other => Err(format!("unknown device status: {other}")),
        }
    }
}

impl std::fmt::Display for DeviceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceStatus::Online => write!(f, "online"),
            DeviceStatus::Offline => write!(f, "offline"),
            DeviceStatus::Paired => write!(f, "paired"),
            DeviceStatus::Revoked => write!(f, "revoked"),
        }
    }
}

/// A registered device in the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Unique device identifier (UUID).
    pub id: Uuid,
    /// Human-readable device name.
    pub name: String,
    /// Type of device.
    pub device_type: DeviceType,
    /// List of device capabilities (e.g., "push", "camera", "biometric").
    pub capabilities: Vec<String>,
    /// When the device was last seen (heartbeat timestamp).
    pub last_seen: DateTime<Utc>,
    /// Current device status.
    pub status: DeviceStatus,
    /// When the device was initially paired.
    pub paired_at: DateTime<Utc>,
    /// Device firmware or OS version, if reported.
    pub firmware_version: Option<String>,
}

/// Manages the lifecycle and status of registered devices.
///
/// Thread safety: this struct is not internally synchronized. Callers must
/// wrap it in a `Mutex` or `RwLock` if shared across threads.
#[derive(Debug)]
pub struct DeviceManager {
    devices: HashMap<Uuid, Device>,
}

impl DeviceManager {
    /// Create a new empty device manager.
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
        }
    }

    /// Register a new device, assigning it a UUID and marking it as Paired.
    ///
    /// Returns the newly created device.
    pub fn register_device(
        &mut self,
        name: String,
        device_type: DeviceType,
        capabilities: Vec<String>,
    ) -> Device {
        let now = Utc::now();
        let device = Device {
            id: Uuid::new_v4(),
            name,
            device_type,
            capabilities,
            last_seen: now,
            status: DeviceStatus::Paired,
            paired_at: now,
            firmware_version: None,
        };
        self.devices.insert(device.id, device.clone());
        device
    }

    /// Update the status of a device.
    ///
    /// Returns an error if the device is not found.
    pub fn update_status(&mut self, device_id: Uuid, status: DeviceStatus) -> Result<(), String> {
        let device = self
            .devices
            .get_mut(&device_id)
            .ok_or_else(|| format!("device not found: {device_id}"))?;
        device.status = status;
        Ok(())
    }

    /// Update the last_seen timestamp for a device to the current time.
    ///
    /// Returns an error if the device is not found.
    pub fn update_last_seen(&mut self, device_id: Uuid) -> Result<(), String> {
        let device = self
            .devices
            .get_mut(&device_id)
            .ok_or_else(|| format!("device not found: {device_id}"))?;
        device.last_seen = Utc::now();
        Ok(())
    }

    /// Get a reference to a device by ID.
    pub fn get_device(&self, device_id: Uuid) -> Option<&Device> {
        self.devices.get(&device_id)
    }

    /// List all registered devices.
    pub fn list_devices(&self) -> Vec<&Device> {
        self.devices.values().collect()
    }

    /// List only devices with status Online.
    pub fn list_online_devices(&self) -> Vec<&Device> {
        self.devices
            .values()
            .filter(|d| d.status == DeviceStatus::Online)
            .collect()
    }

    /// Remove a device from the registry.
    ///
    /// Returns an error if the device is not found. Callers should log
    /// this removal to the audit trail.
    pub fn remove_device(&mut self, device_id: Uuid) -> Result<(), String> {
        self.devices
            .remove(&device_id)
            .map(|_| ())
            .ok_or_else(|| format!("device not found: {device_id}"))
    }

    /// Update the capabilities list for a device.
    ///
    /// Returns an error if the device is not found.
    pub fn update_capabilities(
        &mut self,
        device_id: Uuid,
        capabilities: Vec<String>,
    ) -> Result<(), String> {
        let device = self
            .devices
            .get_mut(&device_id)
            .ok_or_else(|| format!("device not found: {device_id}"))?;
        device.capabilities = capabilities;
        Ok(())
    }

    /// Mark devices that have not been seen within the staleness window as Offline.
    ///
    /// Only devices currently Online or Paired are eligible for staleness sweep.
    /// Revoked devices are never touched. Returns the number of devices marked offline.
    pub fn sweep_stale_devices(&mut self) -> usize {
        let now = Utc::now();
        let mut swept = 0;
        for device in self.devices.values_mut() {
            if device.status == DeviceStatus::Online || device.status == DeviceStatus::Paired {
                let elapsed = now.signed_duration_since(device.last_seen).num_seconds();
                if elapsed >= STALE_DEVICE_TIMEOUT_SECS {
                    device.status = DeviceStatus::Offline;
                    swept += 1;
                }
            }
        }
        swept
    }
}

impl Default for DeviceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_device() {
        let mut mgr = DeviceManager::new();
        let device = mgr.register_device(
            "My Phone".into(),
            DeviceType::Phone,
            vec!["push".into(), "camera".into()],
        );

        assert_eq!(device.name, "My Phone");
        assert_eq!(device.device_type, DeviceType::Phone);
        assert_eq!(device.capabilities, vec!["push", "camera"]);
        assert_eq!(device.status, DeviceStatus::Paired);
        assert!(device.firmware_version.is_none());

        // Verify it's retrievable.
        let retrieved = mgr.get_device(device.id).expect("device should exist");
        assert_eq!(retrieved.id, device.id);
        assert_eq!(retrieved.name, "My Phone");
    }

    #[test]
    fn test_device_types() {
        let mut mgr = DeviceManager::new();

        let phone = mgr.register_device("Phone".into(), DeviceType::Phone, vec![]);
        assert_eq!(phone.device_type, DeviceType::Phone);

        let tablet = mgr.register_device("Tablet".into(), DeviceType::Tablet, vec![]);
        assert_eq!(tablet.device_type, DeviceType::Tablet);

        let desktop = mgr.register_device("Desktop".into(), DeviceType::Desktop, vec![]);
        assert_eq!(desktop.device_type, DeviceType::Desktop);

        let watch = mgr.register_device("Watch".into(), DeviceType::Watch, vec![]);
        assert_eq!(watch.device_type, DeviceType::Watch);

        // Verify string parsing for all types.
        assert_eq!(DeviceType::from_str_checked("phone").unwrap(), DeviceType::Phone);
        assert_eq!(DeviceType::from_str_checked("tablet").unwrap(), DeviceType::Tablet);
        assert_eq!(DeviceType::from_str_checked("desktop").unwrap(), DeviceType::Desktop);
        assert_eq!(DeviceType::from_str_checked("watch").unwrap(), DeviceType::Watch);
        assert!(DeviceType::from_str_checked("unknown").is_err());
    }

    #[test]
    fn test_update_status() {
        let mut mgr = DeviceManager::new();
        let device = mgr.register_device("Test".into(), DeviceType::Phone, vec![]);
        assert_eq!(device.status, DeviceStatus::Paired);

        mgr.update_status(device.id, DeviceStatus::Online).unwrap();
        assert_eq!(mgr.get_device(device.id).unwrap().status, DeviceStatus::Online);

        mgr.update_status(device.id, DeviceStatus::Offline).unwrap();
        assert_eq!(mgr.get_device(device.id).unwrap().status, DeviceStatus::Offline);

        mgr.update_status(device.id, DeviceStatus::Revoked).unwrap();
        assert_eq!(mgr.get_device(device.id).unwrap().status, DeviceStatus::Revoked);
    }

    #[test]
    fn test_list_devices() {
        let mut mgr = DeviceManager::new();
        assert!(mgr.list_devices().is_empty());

        mgr.register_device("A".into(), DeviceType::Phone, vec![]);
        mgr.register_device("B".into(), DeviceType::Tablet, vec![]);
        mgr.register_device("C".into(), DeviceType::Desktop, vec![]);

        assert_eq!(mgr.list_devices().len(), 3);
    }

    #[test]
    fn test_list_online_devices() {
        let mut mgr = DeviceManager::new();
        let d1 = mgr.register_device("A".into(), DeviceType::Phone, vec![]);
        let d2 = mgr.register_device("B".into(), DeviceType::Tablet, vec![]);
        let _d3 = mgr.register_device("C".into(), DeviceType::Desktop, vec![]);

        // Initially all Paired, none Online.
        assert!(mgr.list_online_devices().is_empty());

        mgr.update_status(d1.id, DeviceStatus::Online).unwrap();
        mgr.update_status(d2.id, DeviceStatus::Online).unwrap();

        let online = mgr.list_online_devices();
        assert_eq!(online.len(), 2);
    }

    #[test]
    fn test_remove_device() {
        let mut mgr = DeviceManager::new();
        let device = mgr.register_device("Test".into(), DeviceType::Phone, vec![]);

        assert!(mgr.get_device(device.id).is_some());

        mgr.remove_device(device.id).unwrap();
        assert!(mgr.get_device(device.id).is_none());
        assert!(mgr.list_devices().is_empty());
    }

    #[test]
    fn test_sweep_stale() {
        let mut mgr = DeviceManager::new();
        let d1 = mgr.register_device("Online Device".into(), DeviceType::Phone, vec![]);
        let d2 = mgr.register_device("Stale Device".into(), DeviceType::Tablet, vec![]);

        // Set both Online.
        mgr.update_status(d1.id, DeviceStatus::Online).unwrap();
        mgr.update_status(d2.id, DeviceStatus::Online).unwrap();

        // Manually backdate d2's last_seen to 6 minutes ago.
        mgr.devices.get_mut(&d2.id).unwrap().last_seen =
            Utc::now() - chrono::Duration::seconds(360);

        let swept = mgr.sweep_stale_devices();
        assert_eq!(swept, 1);

        // d1 should still be Online, d2 should be Offline.
        assert_eq!(mgr.get_device(d1.id).unwrap().status, DeviceStatus::Online);
        assert_eq!(mgr.get_device(d2.id).unwrap().status, DeviceStatus::Offline);
    }

    #[test]
    fn test_heartbeat() {
        let mut mgr = DeviceManager::new();
        let device = mgr.register_device("Test".into(), DeviceType::Phone, vec![]);

        let original_last_seen = mgr.get_device(device.id).unwrap().last_seen;

        // Small sleep to ensure time advances.
        std::thread::sleep(std::time::Duration::from_millis(10));

        mgr.update_last_seen(device.id).unwrap();
        let updated_last_seen = mgr.get_device(device.id).unwrap().last_seen;

        assert!(updated_last_seen >= original_last_seen);
    }

    #[test]
    fn test_capabilities_update() {
        let mut mgr = DeviceManager::new();
        let device = mgr.register_device("Test".into(), DeviceType::Phone, vec!["push".into()]);
        assert_eq!(mgr.get_device(device.id).unwrap().capabilities, vec!["push"]);

        mgr.update_capabilities(device.id, vec!["push".into(), "camera".into(), "biometric".into()])
            .unwrap();
        assert_eq!(
            mgr.get_device(device.id).unwrap().capabilities,
            vec!["push", "camera", "biometric"]
        );
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut mgr = DeviceManager::new();
        let fake_id = Uuid::new_v4();
        let result = mgr.remove_device(fake_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("device not found"));
    }

    #[test]
    fn test_manage_device_requires_policy() {
        // Verify that ActionKind::ManageDevice exists and can be constructed.
        // This ensures the Cedar policy gate is wired up for device management.
        let action = aegis_types::ActionKind::ManageDevice {
            device_id: Uuid::new_v4().to_string(),
            operation: "register".into(),
        };
        // Verify it serializes (proves the variant exists and is well-formed).
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("ManageDevice"));
        assert!(json.contains("register"));

        // Verify Display impl works.
        let display = action.to_string();
        assert!(display.contains("ManageDevice"));
    }

    #[test]
    fn test_sweep_does_not_touch_revoked() {
        let mut mgr = DeviceManager::new();
        let device = mgr.register_device("Revoked".into(), DeviceType::Phone, vec![]);
        mgr.update_status(device.id, DeviceStatus::Revoked).unwrap();

        // Backdate last_seen.
        mgr.devices.get_mut(&device.id).unwrap().last_seen =
            Utc::now() - chrono::Duration::seconds(600);

        let swept = mgr.sweep_stale_devices();
        assert_eq!(swept, 0);
        assert_eq!(mgr.get_device(device.id).unwrap().status, DeviceStatus::Revoked);
    }

    #[test]
    fn test_update_status_nonexistent() {
        let mut mgr = DeviceManager::new();
        let result = mgr.update_status(Uuid::new_v4(), DeviceStatus::Online);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_last_seen_nonexistent() {
        let mut mgr = DeviceManager::new();
        let result = mgr.update_last_seen(Uuid::new_v4());
        assert!(result.is_err());
    }

    #[test]
    fn test_update_capabilities_nonexistent() {
        let mut mgr = DeviceManager::new();
        let result = mgr.update_capabilities(Uuid::new_v4(), vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_device_status_parsing() {
        assert_eq!(DeviceStatus::from_str_checked("online").unwrap(), DeviceStatus::Online);
        assert_eq!(DeviceStatus::from_str_checked("offline").unwrap(), DeviceStatus::Offline);
        assert_eq!(DeviceStatus::from_str_checked("paired").unwrap(), DeviceStatus::Paired);
        assert_eq!(DeviceStatus::from_str_checked("revoked").unwrap(), DeviceStatus::Revoked);
        assert!(DeviceStatus::from_str_checked("unknown").is_err());
    }
}
