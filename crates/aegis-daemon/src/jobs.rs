//! Agent job tracking with lifecycle management, progress reporting, and result storage.
//!
//! Each agent can have up to [`MAX_JOBS_PER_AGENT`] jobs tracked. Jobs follow a strict
//! state machine: Queued -> Running -> Completed|Failed, with Cancelled as a terminal
//! state reachable from Queued or Running.
//!
//! All state transitions are validated. Invalid transitions are rejected (fail-closed).
//! Agent names, descriptions, and results are sanitized to prevent injection attacks.

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum number of jobs allowed per agent to prevent unbounded memory growth.
pub const MAX_JOBS_PER_AGENT: usize = 100;

/// Maximum length for job descriptions (bytes).
const MAX_DESCRIPTION_LEN: usize = 1024;

/// Maximum length for job results (bytes).
const MAX_RESULT_LEN: usize = 64 * 1024;

/// Job lifecycle status.
///
/// Valid transitions:
/// - Queued -> Running (job starts executing)
/// - Queued -> Cancelled (job cancelled before execution)
/// - Running -> Completed (job finishes successfully)
/// - Running -> Failed (job encounters an error)
/// - Running -> Cancelled (job cancelled during execution)
///
/// Completed, Failed, and Cancelled are terminal states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl JobStatus {
    /// Whether this status is a terminal state (no further transitions possible).
    pub fn is_terminal(&self) -> bool {
        matches!(self, JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled)
    }
}

impl fmt::Display for JobStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JobStatus::Queued => write!(f, "queued"),
            JobStatus::Running => write!(f, "running"),
            JobStatus::Completed => write!(f, "completed"),
            JobStatus::Failed => write!(f, "failed"),
            JobStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// A tracked job belonging to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    /// Unique job identifier.
    pub id: Uuid,
    /// Agent name this job belongs to.
    pub agent: String,
    /// Human-readable job description.
    pub description: String,
    /// Current job status.
    pub status: JobStatus,
    /// Optional progress percentage (0-100).
    pub progress_pct: Option<u8>,
    /// Completion message or error details.
    pub result: Option<String>,
    /// When the job was created.
    pub created_at: DateTime<Utc>,
    /// When the job started executing.
    pub started_at: Option<DateTime<Utc>>,
    /// When the job completed, failed, or was cancelled.
    pub completed_at: Option<DateTime<Utc>>,
}

/// Validates an agent name, rejecting traversal characters and other injection vectors.
///
/// Returns an error message if the name is invalid.
pub fn validate_agent_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("agent name must not be empty".into());
    }
    if name.contains("..") {
        return Err("agent name must not contain '..'".into());
    }
    if name.contains('/') {
        return Err("agent name must not contain '/'".into());
    }
    if name.contains('\\') {
        return Err("agent name must not contain '\\'".into());
    }
    if name.bytes().any(|b| b == 0) {
        return Err("agent name must not contain null bytes".into());
    }
    // Reject control characters (bytes 0x00-0x1F, 0x7F)
    if name.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return Err("agent name must not contain control characters".into());
    }
    Ok(())
}

/// Strip control characters from a string, preserving printable content.
fn sanitize_text(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// Sanitize a job description: strip control characters and enforce max length.
fn sanitize_description(input: &str) -> Result<String, String> {
    let cleaned = sanitize_text(input);
    if cleaned.len() > MAX_DESCRIPTION_LEN {
        return Err(format!(
            "job description exceeds maximum length of {MAX_DESCRIPTION_LEN} bytes"
        ));
    }
    if cleaned.is_empty() {
        return Err("job description must not be empty".into());
    }
    Ok(cleaned)
}

/// Sanitize a job result: strip control characters and enforce max length.
fn sanitize_result(input: &str) -> Result<String, String> {
    let cleaned = sanitize_text(input);
    if cleaned.len() > MAX_RESULT_LEN {
        return Err(format!(
            "job result exceeds maximum length of {} bytes",
            MAX_RESULT_LEN
        ));
    }
    Ok(cleaned)
}

/// Tracks jobs across all agents.
///
/// Jobs are stored in per-agent vectors. The tracker enforces:
/// - Maximum jobs per agent ([`MAX_JOBS_PER_AGENT`])
/// - Valid state transitions (fail-closed)
/// - Input sanitization for all string fields
/// - Progress percentage range validation (0-100)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JobTracker {
    /// Per-agent job storage.
    jobs: HashMap<String, Vec<Job>>,
}

impl JobTracker {
    /// Create an empty job tracker.
    pub fn new() -> Self {
        Self {
            jobs: HashMap::new(),
        }
    }

    /// Create a new queued job for the given agent.
    ///
    /// Validates the agent name and description. Enforces the per-agent job limit.
    pub fn create_job(&mut self, agent: &str, description: &str) -> Result<Job, String> {
        validate_agent_name(agent)?;
        let description = sanitize_description(description)?;

        let agent_jobs = self.jobs.entry(agent.to_string()).or_default();
        if agent_jobs.len() >= MAX_JOBS_PER_AGENT {
            return Err(format!(
                "agent '{agent}' has reached the maximum of {MAX_JOBS_PER_AGENT} jobs"
            ));
        }

        let job = Job {
            id: Uuid::new_v4(),
            agent: agent.to_string(),
            description,
            status: JobStatus::Queued,
            progress_pct: None,
            result: None,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
        };

        agent_jobs.push(job.clone());
        Ok(job)
    }

    /// Transition a job from Queued to Running.
    pub fn start_job(&mut self, job_id: Uuid) -> Result<&Job, String> {
        let job = self.find_job_mut(job_id)?;
        if job.status != JobStatus::Queued {
            return Err(format!(
                "cannot start job {job_id}: current status is '{}', expected 'queued'",
                job.status
            ));
        }
        job.status = JobStatus::Running;
        job.started_at = Some(Utc::now());

        // Re-borrow immutably after mutation
        let job = self.find_job(job_id).expect("job just modified must exist");
        Ok(job)
    }

    /// Transition a job from Running to Completed with a result message.
    pub fn complete_job(&mut self, job_id: Uuid, result: Option<&str>) -> Result<&Job, String> {
        let sanitized = result.map(sanitize_result).transpose()?;

        let job = self.find_job_mut(job_id)?;
        if job.status != JobStatus::Running {
            return Err(format!(
                "cannot complete job {job_id}: current status is '{}', expected 'running'",
                job.status
            ));
        }
        job.status = JobStatus::Completed;
        job.completed_at = Some(Utc::now());
        job.result = sanitized;
        job.progress_pct = Some(100);

        let job = self.find_job(job_id).expect("job just modified must exist");
        Ok(job)
    }

    /// Transition a job from Running to Failed with an error message.
    pub fn fail_job(&mut self, job_id: Uuid, error: &str) -> Result<&Job, String> {
        let sanitized = sanitize_result(error)?;

        let job = self.find_job_mut(job_id)?;
        if job.status != JobStatus::Running {
            return Err(format!(
                "cannot fail job {job_id}: current status is '{}', expected 'running'",
                job.status
            ));
        }
        job.status = JobStatus::Failed;
        job.completed_at = Some(Utc::now());
        job.result = Some(sanitized);

        let job = self.find_job(job_id).expect("job just modified must exist");
        Ok(job)
    }

    /// Transition a job from Queued or Running to Cancelled.
    pub fn cancel_job(&mut self, job_id: Uuid) -> Result<&Job, String> {
        let job = self.find_job_mut(job_id)?;
        match job.status {
            JobStatus::Queued | JobStatus::Running => {}
            ref s => {
                return Err(format!(
                    "cannot cancel job {job_id}: current status is '{s}', expected 'queued' or 'running'"
                ));
            }
        }
        job.status = JobStatus::Cancelled;
        job.completed_at = Some(Utc::now());

        let job = self.find_job(job_id).expect("job just modified must exist");
        Ok(job)
    }

    /// Update the progress percentage for a running job.
    ///
    /// Validates that `pct` is in the range 0-100.
    pub fn update_progress(&mut self, job_id: Uuid, pct: u8) -> Result<&Job, String> {
        if pct > 100 {
            return Err(format!(
                "progress percentage must be 0-100, got {pct}"
            ));
        }

        let job = self.find_job_mut(job_id)?;
        if job.status != JobStatus::Running {
            return Err(format!(
                "cannot update progress for job {job_id}: current status is '{}', expected 'running'",
                job.status
            ));
        }
        job.progress_pct = Some(pct);

        let job = self.find_job(job_id).expect("job just modified must exist");
        Ok(job)
    }

    /// List all jobs for a specific agent.
    pub fn list_jobs(&self, agent: &str) -> Vec<&Job> {
        self.jobs
            .get(agent)
            .map(|jobs| jobs.iter().collect())
            .unwrap_or_default()
    }

    /// List all jobs across all agents.
    pub fn list_all_jobs(&self) -> Vec<&Job> {
        self.jobs.values().flat_map(|jobs| jobs.iter()).collect()
    }

    /// Get a single job by ID.
    pub fn get_job(&self, job_id: Uuid) -> Option<&Job> {
        self.find_job(job_id).ok()
    }

    /// Count the number of currently running jobs for an agent.
    pub fn active_job_count(&self, agent: &str) -> usize {
        self.jobs
            .get(agent)
            .map(|jobs| jobs.iter().filter(|j| j.status == JobStatus::Running).count())
            .unwrap_or(0)
    }

    /// Find a job by ID (immutable).
    fn find_job(&self, job_id: Uuid) -> Result<&Job, String> {
        for jobs in self.jobs.values() {
            if let Some(job) = jobs.iter().find(|j| j.id == job_id) {
                return Ok(job);
            }
        }
        Err(format!("job {job_id} not found"))
    }

    /// Find a job by ID (mutable).
    fn find_job_mut(&mut self, job_id: Uuid) -> Result<&mut Job, String> {
        for jobs in self.jobs.values_mut() {
            if let Some(job) = jobs.iter_mut().find(|j| j.id == job_id) {
                return Ok(job);
            }
        }
        Err(format!("job {job_id} not found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_lifecycle_create_to_complete() {
        let mut tracker = JobTracker::new();

        let job = tracker.create_job("agent-1", "Build the feature").unwrap();
        assert_eq!(job.status, JobStatus::Queued);
        assert!(job.started_at.is_none());
        assert!(job.completed_at.is_none());
        assert!(job.result.is_none());

        let job_id = job.id;

        let job = tracker.start_job(job_id).unwrap();
        assert_eq!(job.status, JobStatus::Running);
        assert!(job.started_at.is_some());

        let job = tracker
            .complete_job(job_id, Some("Feature shipped"))
            .unwrap();
        assert_eq!(job.status, JobStatus::Completed);
        assert!(job.completed_at.is_some());
        assert_eq!(job.result.as_deref(), Some("Feature shipped"));
        assert_eq!(job.progress_pct, Some(100));
    }

    #[test]
    fn job_progress_updates_tracked() {
        let mut tracker = JobTracker::new();
        let job = tracker.create_job("agent-1", "Long task").unwrap();
        let job_id = job.id;

        tracker.start_job(job_id).unwrap();

        let job = tracker.update_progress(job_id, 25).unwrap();
        assert_eq!(job.progress_pct, Some(25));

        let job = tracker.update_progress(job_id, 75).unwrap();
        assert_eq!(job.progress_pct, Some(75));

        let job = tracker.update_progress(job_id, 100).unwrap();
        assert_eq!(job.progress_pct, Some(100));
    }

    #[test]
    fn job_cancellation_stops_work() {
        let mut tracker = JobTracker::new();

        // Cancel from Queued state
        let job = tracker.create_job("agent-1", "Task A").unwrap();
        let id_a = job.id;
        let job = tracker.cancel_job(id_a).unwrap();
        assert_eq!(job.status, JobStatus::Cancelled);
        assert!(job.completed_at.is_some());

        // Cancel from Running state
        let job = tracker.create_job("agent-1", "Task B").unwrap();
        let id_b = job.id;
        tracker.start_job(id_b).unwrap();
        let job = tracker.cancel_job(id_b).unwrap();
        assert_eq!(job.status, JobStatus::Cancelled);

        // Cannot cancel a Completed job
        let job = tracker.create_job("agent-1", "Task C").unwrap();
        let id_c = job.id;
        tracker.start_job(id_c).unwrap();
        tracker.complete_job(id_c, None).unwrap();
        assert!(tracker.cancel_job(id_c).is_err());
    }

    #[test]
    fn job_persistence_across_restart() {
        let mut tracker = JobTracker::new();
        tracker.create_job("agent-1", "Persist me").unwrap();
        tracker.create_job("agent-2", "Another job").unwrap();

        // Serialize
        let json = serde_json::to_string(&tracker).unwrap();

        // Deserialize
        let restored: JobTracker = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.list_jobs("agent-1").len(), 1);
        assert_eq!(restored.list_jobs("agent-2").len(), 1);
        assert_eq!(restored.list_jobs("agent-1")[0].description, "Persist me");
        assert_eq!(
            restored.list_jobs("agent-2")[0].description,
            "Another job"
        );
    }

    #[test]
    fn job_listing_filters_by_agent() {
        let mut tracker = JobTracker::new();
        tracker.create_job("agent-1", "Task 1a").unwrap();
        tracker.create_job("agent-1", "Task 1b").unwrap();
        tracker.create_job("agent-2", "Task 2a").unwrap();

        assert_eq!(tracker.list_jobs("agent-1").len(), 2);
        assert_eq!(tracker.list_jobs("agent-2").len(), 1);
        assert_eq!(tracker.list_jobs("agent-3").len(), 0);
        assert_eq!(tracker.list_all_jobs().len(), 3);
    }

    #[test]
    fn security_test_invalid_agent_name_rejected() {
        let mut tracker = JobTracker::new();

        assert!(tracker.create_job("../etc/passwd", "bad").is_err());
        assert!(tracker.create_job("agent/sub", "bad").is_err());
        assert!(tracker.create_job("agent\\sub", "bad").is_err());
        assert!(tracker.create_job("agent\0name", "bad").is_err());
        assert!(tracker.create_job("", "bad").is_err());
        assert!(tracker.create_job("agent\x01", "bad").is_err());

        // Valid names should work
        assert!(tracker.create_job("agent-1", "good").is_ok());
        assert!(tracker.create_job("claude_code_2", "good").is_ok());
    }

    #[test]
    fn security_test_progress_out_of_range_rejected() {
        let mut tracker = JobTracker::new();
        let job = tracker.create_job("agent-1", "Test").unwrap();
        let job_id = job.id;
        tracker.start_job(job_id).unwrap();

        // Valid range
        assert!(tracker.update_progress(job_id, 0).is_ok());
        assert!(tracker.update_progress(job_id, 50).is_ok());
        assert!(tracker.update_progress(job_id, 100).is_ok());

        // Out of range
        assert!(tracker.update_progress(job_id, 101).is_err());
        assert!(tracker.update_progress(job_id, 255).is_err());
    }

    #[test]
    fn security_test_max_jobs_per_agent_enforced() {
        let mut tracker = JobTracker::new();

        for i in 0..MAX_JOBS_PER_AGENT {
            tracker
                .create_job("agent-1", &format!("Job {i}"))
                .unwrap();
        }

        // The next job should be rejected
        let result = tracker.create_job("agent-1", "One too many");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("maximum"));

        // But a different agent should still work
        assert!(tracker.create_job("agent-2", "No problem").is_ok());
    }

    #[test]
    fn job_fail_records_error() {
        let mut tracker = JobTracker::new();
        let job = tracker.create_job("agent-1", "Doomed task").unwrap();
        let job_id = job.id;
        tracker.start_job(job_id).unwrap();

        let job = tracker.fail_job(job_id, "out of memory").unwrap();
        assert_eq!(job.status, JobStatus::Failed);
        assert_eq!(job.result.as_deref(), Some("out of memory"));
        assert!(job.completed_at.is_some());
    }

    #[test]
    fn invalid_state_transitions_rejected() {
        let mut tracker = JobTracker::new();
        let job = tracker.create_job("agent-1", "Test").unwrap();
        let job_id = job.id;

        // Cannot complete a Queued job
        assert!(tracker.complete_job(job_id, None).is_err());
        // Cannot fail a Queued job
        assert!(tracker.fail_job(job_id, "error").is_err());
        // Cannot update progress on a Queued job
        assert!(tracker.update_progress(job_id, 50).is_err());

        tracker.start_job(job_id).unwrap();

        // Cannot start a Running job
        assert!(tracker.start_job(job_id).is_err());

        tracker.complete_job(job_id, None).unwrap();

        // Cannot start, fail, or cancel a Completed job
        assert!(tracker.start_job(job_id).is_err());
        assert!(tracker.fail_job(job_id, "late error").is_err());
        assert!(tracker.cancel_job(job_id).is_err());
        assert!(tracker.update_progress(job_id, 50).is_err());
    }

    #[test]
    fn active_job_count_tracks_running_only() {
        let mut tracker = JobTracker::new();

        assert_eq!(tracker.active_job_count("agent-1"), 0);

        let j1 = tracker.create_job("agent-1", "Job 1").unwrap().id;
        let j2 = tracker.create_job("agent-1", "Job 2").unwrap().id;
        let j3 = tracker.create_job("agent-1", "Job 3").unwrap().id;

        assert_eq!(tracker.active_job_count("agent-1"), 0);

        tracker.start_job(j1).unwrap();
        assert_eq!(tracker.active_job_count("agent-1"), 1);

        tracker.start_job(j2).unwrap();
        assert_eq!(tracker.active_job_count("agent-1"), 2);

        tracker.complete_job(j1, None).unwrap();
        assert_eq!(tracker.active_job_count("agent-1"), 1);

        tracker.cancel_job(j3).unwrap();
        assert_eq!(tracker.active_job_count("agent-1"), 1);
    }

    #[test]
    fn get_job_returns_none_for_missing() {
        let tracker = JobTracker::new();
        assert!(tracker.get_job(Uuid::new_v4()).is_none());
    }

    #[test]
    fn job_status_display() {
        assert_eq!(JobStatus::Queued.to_string(), "queued");
        assert_eq!(JobStatus::Running.to_string(), "running");
        assert_eq!(JobStatus::Completed.to_string(), "completed");
        assert_eq!(JobStatus::Failed.to_string(), "failed");
        assert_eq!(JobStatus::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn job_status_serde_roundtrip() {
        for status in [
            JobStatus::Queued,
            JobStatus::Running,
            JobStatus::Completed,
            JobStatus::Failed,
            JobStatus::Cancelled,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: JobStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn description_sanitized() {
        let mut tracker = JobTracker::new();

        // Control characters stripped
        let job = tracker
            .create_job("agent-1", "hello\x00world\x01test")
            .unwrap();
        assert_eq!(job.description, "helloworld\x01test".replace('\x01', ""));
        // Actually, the sanitize_text strips all control chars except \n and \t
        assert!(!job.description.contains('\x00'));
        assert!(!job.description.contains('\x01'));
    }

    #[test]
    fn description_length_enforced() {
        let mut tracker = JobTracker::new();
        let long_desc = "x".repeat(MAX_DESCRIPTION_LEN + 1);
        assert!(tracker.create_job("agent-1", &long_desc).is_err());

        let ok_desc = "x".repeat(MAX_DESCRIPTION_LEN);
        assert!(tracker.create_job("agent-1", &ok_desc).is_ok());
    }

    #[test]
    fn result_length_enforced() {
        let mut tracker = JobTracker::new();
        let job = tracker.create_job("agent-1", "Test").unwrap();
        let job_id = job.id;
        tracker.start_job(job_id).unwrap();

        let long_result = "x".repeat(MAX_RESULT_LEN + 1);
        assert!(tracker.complete_job(job_id, Some(&long_result)).is_err());
    }
}
