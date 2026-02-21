//! Interactive polling for messaging channels.
//!
//! Provides poll creation, vote tracking with deduplication, result
//! aggregation, and auto-close on expiry. All inputs are validated
//! and sanitized to prevent injection and resource exhaustion.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Maximum number of active (non-closed) polls allowed at once.
/// Prevents memory exhaustion from unbounded poll creation.
const MAX_ACTIVE_POLLS: usize = 50;

/// Maximum length for a poll question in characters.
const MAX_QUESTION_LEN: usize = 500;

/// Maximum length for a poll option in characters.
const MAX_OPTION_LEN: usize = 200;

/// Maximum length for a voter ID in characters.
const MAX_VOTER_ID_LEN: usize = 256;

/// Minimum number of options per poll.
const MIN_OPTIONS: usize = 2;

/// Maximum number of options per poll.
const MAX_OPTIONS: usize = 10;

/// Minimum duration for a timed poll in seconds (1 minute).
const MIN_DURATION_SECS: u64 = 60;

/// Maximum duration for a timed poll in seconds (24 hours).
const MAX_DURATION_SECS: u64 = 86400;

/// An interactive poll with vote tracking.
#[derive(Debug, Clone)]
pub struct Poll {
    /// Unique poll identifier.
    pub id: Uuid,
    /// The poll question.
    pub question: String,
    /// Available answer options.
    pub options: Vec<String>,
    /// Votes per option: option text -> set of voter IDs.
    pub votes: HashMap<String, HashSet<String>>,
    /// When the poll was created.
    pub created_at: DateTime<Utc>,
    /// When the poll expires (None = no expiry).
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether the poll has been closed.
    pub closed: bool,
    /// Channel this poll belongs to.
    pub channel: String,
    /// Who created the poll.
    pub creator: String,
}

/// Aggregated result for one poll option.
#[derive(Debug, Clone, PartialEq)]
pub struct PollResult {
    /// The option text.
    pub option: String,
    /// Number of votes received.
    pub vote_count: usize,
    /// Percentage of total votes (0.0 if no votes cast).
    pub percentage: f64,
}

/// Manages active polls with vote tracking and expiry.
#[derive(Debug)]
pub struct PollManager {
    polls: HashMap<Uuid, Poll>,
}

/// Strip control characters (U+0000..U+001F and U+007F..U+009F) from a string,
/// preserving newlines and tabs for readability.
fn sanitize_text(s: &str) -> String {
    s.chars()
        .filter(|c| {
            // Allow printable characters, newlines, and tabs
            !c.is_control() || *c == '\n' || *c == '\t'
        })
        .collect()
}

/// Validate a voter ID: non-empty, max length, alphanumeric + dash/underscore only.
fn validate_voter_id(voter_id: &str) -> Result<(), String> {
    if voter_id.is_empty() {
        return Err("voter ID must not be empty".into());
    }
    if voter_id.len() > MAX_VOTER_ID_LEN {
        return Err(format!(
            "voter ID exceeds maximum length of {MAX_VOTER_ID_LEN} characters"
        ));
    }
    if !voter_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err("voter ID must contain only alphanumeric characters, dashes, or underscores".into());
    }
    Ok(())
}

impl PollManager {
    /// Create a new empty poll manager.
    pub fn new() -> Self {
        Self {
            polls: HashMap::new(),
        }
    }

    /// Create a new poll.
    ///
    /// # Arguments
    /// * `question` - The poll question (non-empty, max 500 chars).
    /// * `options` - Answer options (2-10, each max 200 chars, no duplicates).
    /// * `channel` - Channel name this poll belongs to.
    /// * `creator` - Who created the poll.
    /// * `duration_secs` - Duration in seconds (0 = no expiry, 60..86400 for timed).
    ///
    /// # Errors
    /// Returns an error if validation fails or the active poll limit is reached.
    pub fn create_poll(
        &mut self,
        question: &str,
        options: &[String],
        channel: &str,
        creator: &str,
        duration_secs: u64,
    ) -> Result<Poll, String> {
        // Enforce active poll limit
        let active_count = self.polls.values().filter(|p| !p.closed).count();
        if active_count >= MAX_ACTIVE_POLLS {
            return Err(format!(
                "maximum of {MAX_ACTIVE_POLLS} active polls reached; close existing polls first"
            ));
        }

        // Validate and sanitize question
        let question = sanitize_text(question.trim());
        if question.is_empty() {
            return Err("poll question must not be empty".into());
        }
        if question.len() > MAX_QUESTION_LEN {
            return Err(format!(
                "poll question exceeds maximum length of {MAX_QUESTION_LEN} characters"
            ));
        }

        // Validate options count
        if options.len() < MIN_OPTIONS {
            return Err(format!(
                "poll must have at least {MIN_OPTIONS} options"
            ));
        }
        if options.len() > MAX_OPTIONS {
            return Err(format!(
                "poll must have at most {MAX_OPTIONS} options"
            ));
        }

        // Validate and sanitize each option
        let mut sanitized_options = Vec::with_capacity(options.len());
        let mut seen = HashSet::new();
        for opt in options {
            let sanitized = sanitize_text(opt.trim());
            if sanitized.is_empty() {
                return Err("poll options must not be empty".into());
            }
            if sanitized.len() > MAX_OPTION_LEN {
                return Err(format!(
                    "poll option exceeds maximum length of {MAX_OPTION_LEN} characters"
                ));
            }
            let lower = sanitized.to_lowercase();
            if !seen.insert(lower) {
                return Err(format!("duplicate poll option: {sanitized}"));
            }
            sanitized_options.push(sanitized);
        }

        // Validate duration
        if duration_secs != 0 && !(MIN_DURATION_SECS..=MAX_DURATION_SECS).contains(&duration_secs) {
            return Err(format!(
                "poll duration must be 0 (no expiry) or between {MIN_DURATION_SECS} and {MAX_DURATION_SECS} seconds"
            ));
        }

        let now = Utc::now();
        let expires_at = if duration_secs == 0 {
            None
        } else {
            Some(now + chrono::Duration::seconds(duration_secs as i64))
        };

        // Initialize vote buckets for each option
        let mut votes = HashMap::new();
        for opt in &sanitized_options {
            votes.insert(opt.clone(), HashSet::new());
        }

        let poll = Poll {
            id: Uuid::new_v4(),
            question,
            options: sanitized_options,
            votes,
            created_at: now,
            expires_at,
            closed: false,
            channel: channel.to_string(),
            creator: creator.to_string(),
        };

        let result = poll.clone();
        self.polls.insert(poll.id, poll);
        Ok(result)
    }

    /// Record a vote on a poll.
    ///
    /// Enforces deduplication: if the voter already voted for a different option,
    /// the old vote is removed before the new one is recorded. Voting for the
    /// same option again is a no-op.
    ///
    /// # Errors
    /// Returns an error if the poll does not exist, is closed, or if the
    /// option or voter ID is invalid.
    pub fn vote(&mut self, poll_id: Uuid, option: &str, voter_id: &str) -> Result<(), String> {
        validate_voter_id(voter_id)?;

        let poll = self
            .polls
            .get_mut(&poll_id)
            .ok_or_else(|| format!("poll {poll_id} not found"))?;

        if poll.closed {
            return Err(format!("poll {poll_id} is closed and no longer accepts votes"));
        }

        // Check expiry
        if let Some(expires_at) = poll.expires_at {
            if Utc::now() >= expires_at {
                poll.closed = true;
                return Err(format!("poll {poll_id} has expired and is now closed"));
            }
        }

        if !poll.options.contains(&option.to_string()) {
            return Err(format!(
                "invalid option: {option}. Valid options: {}",
                poll.options.join(", ")
            ));
        }

        // Remove any existing vote by this voter (deduplication)
        for (_opt, voters) in poll.votes.iter_mut() {
            voters.remove(voter_id);
        }

        // Record the new vote
        poll.votes
            .entry(option.to_string())
            .or_default()
            .insert(voter_id.to_string());

        Ok(())
    }

    /// Close a poll and return the final results.
    ///
    /// # Errors
    /// Returns an error if the poll does not exist or is already closed.
    pub fn close_poll(&mut self, poll_id: Uuid) -> Result<Vec<PollResult>, String> {
        let poll = self
            .polls
            .get_mut(&poll_id)
            .ok_or_else(|| format!("poll {poll_id} not found"))?;

        if poll.closed {
            return Err(format!("poll {poll_id} is already closed"));
        }

        poll.closed = true;
        Ok(compute_results(poll))
    }

    /// Get current results for a poll without closing it.
    ///
    /// # Errors
    /// Returns an error if the poll does not exist.
    pub fn get_results(&self, poll_id: Uuid) -> Result<Vec<PollResult>, String> {
        let poll = self
            .polls
            .get(&poll_id)
            .ok_or_else(|| format!("poll {poll_id} not found"))?;

        Ok(compute_results(poll))
    }

    /// List all active (non-closed) polls.
    pub fn list_active_polls(&self) -> Vec<&Poll> {
        self.polls.values().filter(|p| !p.closed).collect()
    }

    /// Get a poll by ID.
    pub fn get_poll(&self, poll_id: Uuid) -> Option<&Poll> {
        self.polls.get(&poll_id)
    }

    /// Check whether a poll has expired (past its expiry time but not yet closed).
    pub fn is_expired(&self, poll_id: Uuid) -> bool {
        match self.polls.get(&poll_id) {
            Some(poll) => {
                if poll.closed {
                    return false;
                }
                match poll.expires_at {
                    Some(expires_at) => Utc::now() >= expires_at,
                    None => false,
                }
            }
            None => false,
        }
    }

    /// Close all expired polls and return their IDs with final results.
    pub fn cleanup_expired(&mut self) -> Vec<(Uuid, Vec<PollResult>)> {
        let now = Utc::now();
        let expired_ids: Vec<Uuid> = self
            .polls
            .iter()
            .filter(|(_, p)| !p.closed)
            .filter(|(_, p)| p.expires_at.is_some_and(|exp| now >= exp))
            .map(|(id, _)| *id)
            .collect();

        let mut results = Vec::new();
        for id in expired_ids {
            if let Some(poll) = self.polls.get_mut(&id) {
                poll.closed = true;
                results.push((id, compute_results(poll)));
            }
        }
        results
    }
}

impl Default for PollManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute aggregated results for a poll.
fn compute_results(poll: &Poll) -> Vec<PollResult> {
    let total: usize = poll.votes.values().map(|v| v.len()).sum();

    poll.options
        .iter()
        .map(|opt| {
            let count = poll.votes.get(opt).map_or(0, |v| v.len());
            let percentage = if total == 0 {
                0.0
            } else {
                (count as f64 / total as f64) * 100.0
            };
            PollResult {
                option: opt.clone(),
                vote_count: count,
                percentage,
            }
        })
        .collect()
}

/// Determine the winner(s) of a poll. Returns all options tied for the lead.
/// Returns an empty vec if no votes have been cast.
pub fn determine_winners(results: &[PollResult]) -> Vec<String> {
    let max_votes = results.iter().map(|r| r.vote_count).max().unwrap_or(0);
    if max_votes == 0 {
        return Vec::new();
    }
    results
        .iter()
        .filter(|r| r.vote_count == max_votes)
        .map(|r| r.option.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_creation_validates_inputs() {
        let mut mgr = PollManager::new();

        // Empty question
        let res = mgr.create_poll("", &["A".into(), "B".into()], "test", "user1", 0);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("must not be empty"));

        // Question too long
        let long_q = "x".repeat(501);
        let res = mgr.create_poll(&long_q, &["A".into(), "B".into()], "test", "user1", 0);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("exceeds maximum length"));

        // Too few options
        let res = mgr.create_poll("Q?", &["A".into()], "test", "user1", 0);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("at least 2"));

        // Too many options
        let many: Vec<String> = (0..11).map(|i| format!("opt{i}")).collect();
        let res = mgr.create_poll("Q?", &many, "test", "user1", 0);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("at most 10"));

        // Duplicate options (case-insensitive)
        let res = mgr.create_poll("Q?", &["Yes".into(), "yes".into()], "test", "user1", 0);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("duplicate"));

        // Option too long
        let long_opt = "x".repeat(201);
        let res = mgr.create_poll("Q?", &[long_opt, "B".into()], "test", "user1", 0);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("exceeds maximum length"));

        // Empty option
        let res = mgr.create_poll("Q?", &["A".into(), "".into()], "test", "user1", 0);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("must not be empty"));

        // Invalid duration (too short)
        let res = mgr.create_poll("Q?", &["A".into(), "B".into()], "test", "user1", 30);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("between"));

        // Invalid duration (too long)
        let res = mgr.create_poll("Q?", &["A".into(), "B".into()], "test", "user1", 100_000);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("between"));

        // Valid poll creation
        let res = mgr.create_poll("Favorite color?", &["Red".into(), "Blue".into()], "test", "user1", 0);
        assert!(res.is_ok());
        let poll = res.unwrap();
        assert_eq!(poll.question, "Favorite color?");
        assert_eq!(poll.options.len(), 2);
        assert!(!poll.closed);

        // Valid with duration
        let res = mgr.create_poll("Q2?", &["A".into(), "B".into()], "test", "user1", 3600);
        assert!(res.is_ok());
        let poll = res.unwrap();
        assert!(poll.expires_at.is_some());
    }

    #[test]
    fn vote_recording_and_deduplication() {
        let mut mgr = PollManager::new();
        let poll = mgr
            .create_poll("Pick?", &["A".into(), "B".into(), "C".into()], "test", "user1", 0)
            .unwrap();
        let pid = poll.id;

        // First vote
        mgr.vote(pid, "A", "voter-1").unwrap();
        let results = mgr.get_results(pid).unwrap();
        assert_eq!(results.iter().find(|r| r.option == "A").unwrap().vote_count, 1);

        // Second voter
        mgr.vote(pid, "B", "voter-2").unwrap();

        // Voter-1 changes vote from A to B (deduplication)
        mgr.vote(pid, "B", "voter-1").unwrap();
        let results = mgr.get_results(pid).unwrap();
        assert_eq!(results.iter().find(|r| r.option == "A").unwrap().vote_count, 0);
        assert_eq!(results.iter().find(|r| r.option == "B").unwrap().vote_count, 2);

        // Voting for same option again is a no-op (idempotent)
        mgr.vote(pid, "B", "voter-1").unwrap();
        let results = mgr.get_results(pid).unwrap();
        assert_eq!(results.iter().find(|r| r.option == "B").unwrap().vote_count, 2);
    }

    #[test]
    fn result_aggregation_correct() {
        let mut mgr = PollManager::new();
        let poll = mgr
            .create_poll("Best?", &["X".into(), "Y".into(), "Z".into()], "test", "user1", 0)
            .unwrap();
        let pid = poll.id;

        // No votes -- percentages should be 0
        let results = mgr.get_results(pid).unwrap();
        for r in &results {
            assert_eq!(r.vote_count, 0);
            assert_eq!(r.percentage, 0.0);
        }

        // Cast votes: X=2, Y=1, Z=0
        mgr.vote(pid, "X", "v1").unwrap();
        mgr.vote(pid, "X", "v2").unwrap();
        mgr.vote(pid, "Y", "v3").unwrap();

        let results = mgr.get_results(pid).unwrap();
        let x = results.iter().find(|r| r.option == "X").unwrap();
        let y = results.iter().find(|r| r.option == "Y").unwrap();
        let z = results.iter().find(|r| r.option == "Z").unwrap();

        assert_eq!(x.vote_count, 2);
        assert!((x.percentage - 66.666).abs() < 0.01);
        assert_eq!(y.vote_count, 1);
        assert!((y.percentage - 33.333).abs() < 0.01);
        assert_eq!(z.vote_count, 0);
        assert_eq!(z.percentage, 0.0);

        // Winner determination
        let winners = determine_winners(&results);
        assert_eq!(winners, vec!["X"]);

        // Test tie
        mgr.vote(pid, "Y", "v4").unwrap();
        let results = mgr.get_results(pid).unwrap();
        let winners = determine_winners(&results);
        assert_eq!(winners.len(), 2);
        assert!(winners.contains(&"X".to_string()));
        assert!(winners.contains(&"Y".to_string()));
    }

    #[test]
    fn poll_auto_close_on_expiry() {
        let mut mgr = PollManager::new();

        // Create a poll that's already expired (by manipulating the internal state)
        let poll = mgr
            .create_poll("Expired?", &["A".into(), "B".into()], "test", "user1", 60)
            .unwrap();
        let pid = poll.id;

        // Manually set expires_at to the past
        mgr.polls.get_mut(&pid).unwrap().expires_at =
            Some(Utc::now() - chrono::Duration::seconds(10));

        assert!(mgr.is_expired(pid));

        // cleanup_expired should close it and return results
        let closed = mgr.cleanup_expired();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].0, pid);

        // Poll should now be closed
        assert!(mgr.get_poll(pid).unwrap().closed);

        // is_expired returns false for closed polls
        assert!(!mgr.is_expired(pid));
    }

    #[test]
    fn poll_closed_rejects_votes() {
        let mut mgr = PollManager::new();
        let poll = mgr
            .create_poll("Done?", &["Yes".into(), "No".into()], "test", "user1", 0)
            .unwrap();
        let pid = poll.id;

        // Close the poll
        mgr.close_poll(pid).unwrap();

        // Voting on closed poll should fail
        let res = mgr.vote(pid, "Yes", "voter-1");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("closed"));

        // Closing again should fail
        let res = mgr.close_poll(pid);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("already closed"));
    }

    #[test]
    fn security_test_max_polls_enforced() {
        let mut mgr = PollManager::new();

        // Create MAX_ACTIVE_POLLS polls
        for i in 0..MAX_ACTIVE_POLLS {
            let res = mgr.create_poll(
                &format!("Q{i}?"),
                &["A".into(), "B".into()],
                "test",
                "user1",
                0,
            );
            assert!(res.is_ok(), "failed to create poll {i}");
        }

        // Next one should be rejected
        let res = mgr.create_poll("Extra?", &["A".into(), "B".into()], "test", "user1", 0);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("maximum"));

        // Close one and try again
        let first_id = mgr.list_active_polls()[0].id;
        mgr.close_poll(first_id).unwrap();

        let res = mgr.create_poll("After close?", &["A".into(), "B".into()], "test", "user1", 0);
        assert!(res.is_ok());
    }

    #[test]
    fn security_test_voter_id_validated() {
        let mut mgr = PollManager::new();
        let poll = mgr
            .create_poll("Test?", &["A".into(), "B".into()], "test", "user1", 0)
            .unwrap();
        let pid = poll.id;

        // Empty voter ID
        let res = mgr.vote(pid, "A", "");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("must not be empty"));

        // Voter ID too long
        let long_id = "a".repeat(257);
        let res = mgr.vote(pid, "A", &long_id);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("exceeds maximum length"));

        // Voter ID with invalid characters
        let res = mgr.vote(pid, "A", "user<script>alert(1)</script>");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("alphanumeric"));

        // Voter ID with spaces
        let res = mgr.vote(pid, "A", "user name");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("alphanumeric"));

        // Valid voter IDs
        mgr.vote(pid, "A", "user-123").unwrap();
        mgr.vote(pid, "A", "user_456").unwrap();
        mgr.vote(pid, "A", "User789").unwrap();
    }

    #[test]
    fn security_test_question_sanitized() {
        let mut mgr = PollManager::new();

        // Question with control characters should have them stripped
        let poll = mgr
            .create_poll(
                "What\x00is\x01your\x02pick?",
                &["A".into(), "B".into()],
                "test",
                "user1",
                0,
            )
            .unwrap();
        assert_eq!(poll.question, "Whatisyourpick?");

        // Options with control characters
        let poll = mgr
            .create_poll(
                "Choose?",
                &["Op\x00tion\x01A".into(), "Option B".into()],
                "test",
                "user1",
                0,
            )
            .unwrap();
        assert_eq!(poll.options[0], "OptionA");
    }

    #[test]
    fn list_active_polls_excludes_closed() {
        let mut mgr = PollManager::new();

        let p1 = mgr
            .create_poll("Q1?", &["A".into(), "B".into()], "test", "user1", 0)
            .unwrap();
        let _p2 = mgr
            .create_poll("Q2?", &["C".into(), "D".into()], "test", "user1", 0)
            .unwrap();

        assert_eq!(mgr.list_active_polls().len(), 2);

        mgr.close_poll(p1.id).unwrap();
        assert_eq!(mgr.list_active_polls().len(), 1);
    }

    #[test]
    fn vote_on_nonexistent_poll() {
        let mut mgr = PollManager::new();
        let res = mgr.vote(Uuid::new_v4(), "A", "voter-1");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("not found"));
    }

    #[test]
    fn vote_for_invalid_option() {
        let mut mgr = PollManager::new();
        let poll = mgr
            .create_poll("Q?", &["A".into(), "B".into()], "test", "user1", 0)
            .unwrap();

        let res = mgr.vote(poll.id, "C", "voter-1");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("invalid option"));
    }

    #[test]
    fn get_poll_returns_none_for_missing() {
        let mgr = PollManager::new();
        assert!(mgr.get_poll(Uuid::new_v4()).is_none());
    }

    #[test]
    fn determine_winners_empty_results() {
        let winners = determine_winners(&[]);
        assert!(winners.is_empty());

        let winners = determine_winners(&[PollResult {
            option: "A".into(),
            vote_count: 0,
            percentage: 0.0,
        }]);
        assert!(winners.is_empty());
    }

    #[test]
    fn poll_preserves_option_order() {
        let mut mgr = PollManager::new();
        let poll = mgr
            .create_poll(
                "Order?",
                &["Zebra".into(), "Apple".into(), "Mango".into()],
                "test",
                "user1",
                0,
            )
            .unwrap();
        assert_eq!(poll.options, vec!["Zebra", "Apple", "Mango"]);

        let results = mgr.get_results(poll.id).unwrap();
        assert_eq!(results[0].option, "Zebra");
        assert_eq!(results[1].option, "Apple");
        assert_eq!(results[2].option, "Mango");
    }

    #[test]
    fn expired_poll_rejects_vote() {
        let mut mgr = PollManager::new();
        let poll = mgr
            .create_poll("Expiring?", &["A".into(), "B".into()], "test", "user1", 60)
            .unwrap();
        let pid = poll.id;

        // Set to already expired
        mgr.polls.get_mut(&pid).unwrap().expires_at =
            Some(Utc::now() - chrono::Duration::seconds(1));

        let res = mgr.vote(pid, "A", "voter-1");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("expired"));

        // Poll should now be closed
        assert!(mgr.get_poll(pid).unwrap().closed);
    }
}
