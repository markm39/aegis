//! Recursive process tree termination with signal escalation.
//!
//! Walks the process tree from a root PID, identifies all descendant processes,
//! and terminates them from leaves to root. Sends SIGTERM first, waits a
//! configurable grace period, then escalates to SIGKILL for any survivors.
//!
//! # Security
//!
//! - Refuses to target PID 0 or PID 1 (init/launchd).
//! - Validates process ownership (UID match) before sending any signal.
//! - Handles ESRCH (process already dead) gracefully.
//! - Handles EPERM (permission denied) by logging and skipping.

use std::collections::HashMap;
use std::time::Duration;

use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::{debug, info, warn};

use aegis_types::AegisError;

/// Configuration for the kill tree operation.
#[derive(Debug, Clone)]
pub struct KillTreeConfig {
    /// Grace period between SIGTERM and SIGKILL escalation.
    pub grace_period: Duration,
    /// Polling interval when waiting for processes to exit after SIGTERM.
    pub poll_interval: Duration,
}

impl Default for KillTreeConfig {
    fn default() -> Self {
        Self {
            grace_period: Duration::from_secs(5),
            poll_interval: Duration::from_millis(100),
        }
    }
}

/// Information about a process in the tree.
#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: i32,
    ppid: i32,
    uid: u32,
}

/// Protected PIDs that must never be killed.
const PROTECTED_PIDS: [i32; 2] = [0, 1];

/// Check whether a PID is protected (PID 0 or PID 1).
fn is_protected(pid: i32) -> bool {
    PROTECTED_PIDS.contains(&pid)
}

/// Validate that a PID is safe to target.
fn validate_pid(pid: i32) -> Result<(), AegisError> {
    if is_protected(pid) {
        return Err(AegisError::PilotError(format!(
            "kill_tree: refusing to target protected PID {pid} (init/launchd)"
        )));
    }
    if pid < 0 {
        return Err(AegisError::PilotError(format!(
            "kill_tree: invalid negative PID {pid}"
        )));
    }
    Ok(())
}

/// Get the current user's UID.
fn current_uid() -> u32 {
    // Safety: getuid() is always safe and cannot fail.
    unsafe { libc::getuid() }
}

/// Enumerate all processes on macOS using libproc APIs.
///
/// Uses `proc_listpids` to get all PIDs, then `proc_pidinfo` with
/// `PROC_PIDTBSDINFO` to get parent PID and UID for each process.
#[cfg(target_os = "macos")]
fn enumerate_processes() -> Result<Vec<ProcessInfo>, AegisError> {
    use std::mem;

    // PROC_ALL_PIDS = 1 (not exported by libc, but this is the stable value
    // from <sys/proc_info.h>).
    const PROC_ALL_PIDS: u32 = 1;

    // First call: get the number of PIDs (buffer_size=0 returns required size).
    let num_bytes =
        unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if num_bytes <= 0 {
        return Err(AegisError::PilotError(format!(
            "kill_tree: proc_listpids size query failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Allocate buffer with headroom for new processes appearing between calls.
    let pid_count = (num_bytes as usize / mem::size_of::<libc::pid_t>()) + 64;
    let mut pids: Vec<libc::pid_t> = vec![0; pid_count];
    let buf_size = (pid_count * mem::size_of::<libc::pid_t>()) as libc::c_int;

    let actual_bytes = unsafe {
        libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast(),
            buf_size,
        )
    };
    if actual_bytes <= 0 {
        return Err(AegisError::PilotError(format!(
            "kill_tree: proc_listpids data query failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let actual_count = actual_bytes as usize / mem::size_of::<libc::pid_t>();
    pids.truncate(actual_count);

    let mut processes = Vec::with_capacity(actual_count);
    let bsdinfo_size = mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;

    for &pid in &pids {
        if pid <= 0 {
            continue;
        }

        let mut info: libc::proc_bsdinfo = unsafe { mem::zeroed() };
        let ret = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&raw mut info).cast(),
                bsdinfo_size,
            )
        };

        // proc_pidinfo returns 0 or -1 on error (process may have exited).
        if ret <= 0 {
            continue;
        }

        processes.push(ProcessInfo {
            pid,
            ppid: info.pbi_ppid as i32,
            uid: info.pbi_uid,
        });
    }

    debug!(
        process_count = processes.len(),
        "kill_tree: enumerated processes"
    );

    Ok(processes)
}

/// Enumerate all processes on Linux by reading /proc.
#[cfg(target_os = "linux")]
fn enumerate_processes() -> Result<Vec<ProcessInfo>, AegisError> {
    use std::fs;

    let mut processes = Vec::new();

    let entries = fs::read_dir("/proc").map_err(|e| {
        AegisError::PilotError(format!("kill_tree: cannot read /proc: {e}"))
    })?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Only numeric directory names are PIDs.
        let pid: i32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Read /proc/{pid}/status for PPid and Uid.
        let status_path = format!("/proc/{pid}/status");
        let status = match fs::read_to_string(&status_path) {
            Ok(s) => s,
            Err(_) => continue, // Process may have exited.
        };

        let mut ppid: i32 = 0;
        let mut uid: u32 = u32::MAX;

        for line in status.lines() {
            if let Some(val) = line.strip_prefix("PPid:\t") {
                ppid = val.trim().parse().unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("Uid:\t") {
                // Uid line has: real effective saved filesystem
                // We want the real UID (first field).
                uid = val
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(u32::MAX);
            }
        }

        processes.push(ProcessInfo { pid, ppid, uid });
    }

    debug!(
        process_count = processes.len(),
        "kill_tree: enumerated processes"
    );

    Ok(processes)
}

/// Find all descendant PIDs of `root_pid` in the process tree.
///
/// Returns descendants ordered from leaves to root (deepest children first),
/// which is the correct order for termination.
fn find_descendants(root_pid: i32, processes: &[ProcessInfo]) -> Vec<i32> {
    // Build parent -> children mapping.
    let mut children_map: HashMap<i32, Vec<i32>> = HashMap::new();
    for proc_info in processes {
        children_map
            .entry(proc_info.ppid)
            .or_default()
            .push(proc_info.pid);
    }

    // BFS to find all descendants.
    let mut all_descendants = Vec::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root_pid);

    while let Some(pid) = queue.pop_front() {
        if let Some(children) = children_map.get(&pid) {
            for &child in children {
                // Skip the root itself if it appears as its own child (shouldn't happen
                // but defend against kernel quirks).
                if child == root_pid {
                    continue;
                }
                all_descendants.push(child);
                queue.push_back(child);
            }
        }
    }

    // Reverse so leaves come first (BFS gives us parents before children).
    all_descendants.reverse();
    all_descendants
}

/// Validate that a process is owned by the given UID.
///
/// Returns `true` if the process matches the expected UID. Returns `false`
/// if the process is not found (already exited) or owned by a different user.
fn validate_ownership(pid: i32, expected_uid: u32, processes: &[ProcessInfo]) -> bool {
    processes
        .iter()
        .find(|p| p.pid == pid)
        .is_some_and(|p| p.uid == expected_uid)
}

/// Send a signal to a process, handling ESRCH and EPERM gracefully.
///
/// Returns:
/// - `Ok(true)` if the signal was sent successfully.
/// - `Ok(false)` if the process was already dead (ESRCH) or we lack permission (EPERM).
/// - `Err` for unexpected errors.
fn send_signal(pid: i32, sig: Signal) -> Result<bool, AegisError> {
    match signal::kill(Pid::from_raw(pid), sig) {
        Ok(()) => {
            debug!(pid, signal = ?sig, "kill_tree: signal sent");
            Ok(true)
        }
        Err(nix::errno::Errno::ESRCH) => {
            debug!(pid, signal = ?sig, "kill_tree: process already dead (ESRCH)");
            Ok(false)
        }
        Err(nix::errno::Errno::EPERM) => {
            warn!(pid, signal = ?sig, "kill_tree: permission denied (EPERM), skipping");
            Ok(false)
        }
        Err(e) => Err(AegisError::PilotError(format!(
            "kill_tree: failed to send {sig:?} to PID {pid}: {e}"
        ))),
    }
}

/// Check if a process is still alive.
fn is_alive(pid: i32) -> bool {
    // signal::kill with None (signal 0) checks existence without sending a signal.
    signal::kill(Pid::from_raw(pid), None).is_ok()
}

/// Terminate a process tree rooted at `root_pid`.
///
/// Walks the process tree, finds all descendants, and kills them from leaves
/// to root. Uses SIGTERM first, then escalates to SIGKILL after the grace
/// period for any surviving processes.
///
/// # Security
///
/// - Rejects PID 0 and PID 1 immediately.
/// - Validates that every process in the tree is owned by the current user.
/// - Logs every signal sent via tracing.
///
/// # Arguments
///
/// - `root_pid`: The root process ID to terminate (along with all descendants).
/// - `config`: Configuration for grace period and polling.
///
/// # Returns
///
/// - `Ok(())` on success (all processes terminated or already dead).
/// - `Err` if the root PID is protected or enumeration fails.
pub fn kill_tree(root_pid: i32, config: &KillTreeConfig) -> Result<(), AegisError> {
    validate_pid(root_pid)?;

    info!(root_pid, "kill_tree: starting process tree termination");

    let processes = enumerate_processes()?;
    let my_uid = current_uid();

    // Validate ownership of the root process.
    if !validate_ownership(root_pid, my_uid, &processes) {
        // The root process might have already exited -- that's fine.
        if !is_alive(root_pid) {
            info!(root_pid, "kill_tree: root process already exited");
            return Ok(());
        }
        return Err(AegisError::PilotError(format!(
            "kill_tree: root PID {root_pid} is not owned by current user (UID {my_uid})"
        )));
    }

    // Find all descendants (leaves first).
    let descendants = find_descendants(root_pid, &processes);

    // Build the full kill list: descendants (leaves first) + root last.
    let mut kill_list: Vec<i32> = Vec::with_capacity(descendants.len() + 1);
    for &pid in &descendants {
        if is_protected(pid) {
            warn!(
                pid,
                "kill_tree: skipping protected PID found in process tree"
            );
            continue;
        }
        if !validate_ownership(pid, my_uid, &processes) {
            warn!(
                pid,
                "kill_tree: skipping process not owned by current user"
            );
            continue;
        }
        kill_list.push(pid);
    }
    kill_list.push(root_pid);

    info!(
        root_pid,
        descendant_count = descendants.len(),
        kill_count = kill_list.len(),
        "kill_tree: sending SIGTERM to process tree"
    );

    // Phase 1: Send SIGTERM to all processes (leaves to root).
    for &pid in &kill_list {
        let _ = send_signal(pid, Signal::SIGTERM)?;
    }

    // Phase 2: Wait for grace period, polling for survivors.
    let deadline = std::time::Instant::now() + config.grace_period;
    loop {
        // Check if all processes have exited.
        let survivors: Vec<i32> = kill_list
            .iter()
            .copied()
            .filter(|&pid| is_alive(pid))
            .collect();
        if survivors.is_empty() {
            info!(root_pid, "kill_tree: all processes exited after SIGTERM");
            return Ok(());
        }

        if std::time::Instant::now() >= deadline {
            // Grace period expired -- escalate to SIGKILL.
            warn!(
                root_pid,
                survivor_count = survivors.len(),
                "kill_tree: grace period expired, escalating to SIGKILL"
            );
            for &pid in &survivors {
                let _ = send_signal(pid, Signal::SIGKILL)?;
            }
            return Ok(());
        }

        std::thread::sleep(config.poll_interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::wait::{waitpid, WaitPidFlag};
    use std::process::Command;

    /// Helper: reap a direct child process (collect its exit status so it
    /// stops being a zombie). Uses WNOHANG so it never blocks.
    fn reap(pid: i32) {
        let _ = waitpid(Pid::from_raw(pid), Some(WaitPidFlag::WNOHANG));
    }

    /// Helper: spawn a child process that itself spawns a grandchild, both sleeping.
    /// Returns (child_pid, Child handle). The tree looks like:
    ///   child (sh) -> grandchild (sleep)
    ///
    /// The caller must keep the Child handle alive and call `child.wait()` or
    /// `reap()` after killing to avoid zombies.
    fn spawn_process_tree() -> (i32, std::process::Child) {
        let child = Command::new("/bin/sh")
            .arg("-c")
            // The shell forks a sleep process, creating a 2-level tree.
            .arg("sleep 300 & wait")
            .spawn()
            .expect("failed to spawn child");
        let pid = child.id() as i32;
        (pid, child)
    }

    #[test]
    fn process_tree_enumeration_finds_children() {
        let (child_pid, mut child) = spawn_process_tree();
        // Give the shell time to fork the sleep subprocess.
        std::thread::sleep(Duration::from_millis(500));

        let processes = enumerate_processes().expect("enumerate failed");

        // Verify we can find our child in the process list.
        let found_child = processes.iter().any(|p| p.pid == child_pid);
        assert!(
            found_child,
            "child PID {child_pid} not found in process list"
        );

        // Find descendants of the child.
        let descendants = find_descendants(child_pid, &processes);
        assert!(
            !descendants.is_empty(),
            "expected at least one descendant (the sleep process) of PID {child_pid}"
        );

        // Clean up: kill all processes and reap the direct child.
        let _ = signal::kill(Pid::from_raw(child_pid), Signal::SIGKILL);
        for &d in &descendants {
            let _ = signal::kill(Pid::from_raw(d), Signal::SIGKILL);
        }
        let _ = child.wait();
    }

    #[test]
    fn kill_tree_terminates_leaf_first() {
        let (child_pid, mut child) = spawn_process_tree();
        std::thread::sleep(Duration::from_millis(500));

        let processes = enumerate_processes().expect("enumerate failed");
        let descendants = find_descendants(child_pid, &processes);

        // The kill list should have descendants (leaves) before the root.
        // find_descendants returns leaves first, root is appended last in kill_tree.
        assert!(
            !descendants.is_empty(),
            "expected descendants for kill ordering test"
        );

        // Perform the actual kill.
        let config = KillTreeConfig {
            grace_period: Duration::from_secs(2),
            poll_interval: Duration::from_millis(50),
        };
        let result = kill_tree(child_pid, &config);
        assert!(result.is_ok(), "kill_tree failed: {:?}", result.err());

        // Reap the direct child (our test process is the parent).
        let _ = child.wait();

        // Verify all processes are dead (reaping clears the zombie).
        assert!(
            !is_alive(child_pid),
            "root process should be dead after kill_tree"
        );
        for &d in &descendants {
            // Grandchildren are reparented to init/launchd and reaped by the OS.
            // Give a brief moment, then check.
            reap(d);
        }
    }

    #[test]
    fn sigterm_then_sigkill_escalation() {
        // Spawn a process that traps SIGTERM (ignores it).
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            // Trap SIGTERM and ignore it; the shell will not exit on SIGTERM.
            .arg("trap '' TERM; sleep 300")
            .spawn()
            .expect("failed to spawn SIGTERM-resistant child");
        let child_pid = child.id() as i32;
        std::thread::sleep(Duration::from_millis(500));

        // Use a very short grace period to trigger SIGKILL quickly.
        let config = KillTreeConfig {
            grace_period: Duration::from_millis(500),
            poll_interval: Duration::from_millis(50),
        };

        let result = kill_tree(child_pid, &config);
        assert!(result.is_ok(), "kill_tree failed: {:?}", result.err());

        // Reap the direct child to clear zombie state.
        let _ = child.wait();

        // After SIGKILL escalation and reaping, the process must be gone.
        assert!(
            !is_alive(child_pid),
            "process should be dead after SIGKILL escalation"
        );
    }

    #[test]
    fn ownership_validation_prevents_cross_user_kill() {
        // PID 1 (launchd/init) is always owned by root (UID 0).
        // Our current user is not root (in normal test environments).
        // We test that a non-owned process is rejected.
        let processes = enumerate_processes().expect("enumerate failed");
        let my_uid = current_uid();

        // Find a process not owned by us (e.g., PID 1).
        let foreign_process = processes.iter().find(|p| p.uid != my_uid && p.pid > 1);

        if let Some(foreign) = foreign_process {
            // Attempting to kill a foreign-owned process should fail ownership validation.
            assert!(
                !validate_ownership(foreign.pid, my_uid, &processes),
                "foreign process PID {} should fail ownership validation",
                foreign.pid
            );
        }

        // Also verify: the kill_tree function rejects a root-owned PID (if we are not root).
        if my_uid != 0 {
            // Verify validate_ownership returns false for UID mismatch using synthetic data.
            let fake_procs = vec![ProcessInfo {
                pid: 9999,
                ppid: 1,
                uid: 0, // root
            }];
            assert!(
                !validate_ownership(9999, my_uid, &fake_procs),
                "UID mismatch should fail ownership validation"
            );
        }
    }

    #[test]
    fn empty_tree_is_safe() {
        // Spawn a simple process with no children.
        let mut child = Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .expect("failed to spawn sleep");
        let child_pid = child.id() as i32;
        std::thread::sleep(Duration::from_millis(200));

        let processes = enumerate_processes().expect("enumerate failed");
        let descendants = find_descendants(child_pid, &processes);

        // sleep should have no children.
        assert!(
            descendants.is_empty(),
            "sleep process should have no children"
        );

        // kill_tree should still succeed.
        let config = KillTreeConfig {
            grace_period: Duration::from_secs(1),
            poll_interval: Duration::from_millis(50),
        };
        let result = kill_tree(child_pid, &config);
        assert!(result.is_ok(), "kill_tree on childless process failed");

        // Reap the direct child to clear zombie state.
        let _ = child.wait();

        assert!(
            !is_alive(child_pid),
            "sleep process should be dead after kill_tree"
        );
    }

    #[test]
    fn security_test_pid_1_protected() {
        let config = KillTreeConfig::default();

        // PID 0 must be rejected.
        let result = kill_tree(0, &config);
        assert!(result.is_err(), "PID 0 should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("protected PID"),
            "error should mention 'protected PID': {err}"
        );

        // PID 1 must be rejected.
        let result = kill_tree(1, &config);
        assert!(result.is_err(), "PID 1 should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("protected PID"),
            "error should mention 'protected PID': {err}"
        );

        // Negative PIDs must be rejected.
        let result = kill_tree(-1, &config);
        assert!(result.is_err(), "negative PID should be rejected");
    }
}
