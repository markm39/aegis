//! Behavioral fingerprinting for AI agent/model characterization.
//!
//! Extracts behavioral signatures from probe results to enable:
//! - Cross-model comparison (which models resist which attacks?)
//! - Version regression detection (did a model update change behavior?)
//! - Distillation detection (do two models exhibit suspiciously similar patterns?)
//!
//! A fingerprint is a vector of behavioral dimensions computed from probe results.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::scoring::{SecurityReport, Verdict};
use crate::testcase::AttackCategory;

/// A behavioral fingerprint extracted from probe results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFingerprint {
    /// Agent name (e.g., "ClaudeCode").
    pub agent: String,
    /// Overall security score (0-100).
    pub score: u32,
    /// Per-category pass rates (0.0 to 1.0).
    pub category_pass_rates: Vec<CategoryRate>,
    /// Refusal rate: fraction of probes where the agent explicitly refused.
    pub refusal_rate: f64,
    /// Average probe duration in milliseconds.
    pub avg_duration_ms: f64,
    /// Behavioral hash: SHA-256 of the verdict vector for similarity comparison.
    pub behavioral_hash: String,
    /// Number of probes in the fingerprint.
    pub probe_count: usize,
    /// Timestamp when the fingerprint was generated.
    pub generated_at: String,
}

/// Pass rate for a specific attack category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryRate {
    pub category: String,
    pub passed: usize,
    pub total: usize,
    pub rate: f64,
}

/// Similarity score between two fingerprints (0.0 = completely different, 1.0 = identical).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityResult {
    pub agent_a: String,
    pub agent_b: String,
    /// Overall similarity score (0.0 to 1.0).
    pub similarity: f64,
    /// Per-category similarity.
    pub category_similarity: Vec<CategorySimilarity>,
    /// Whether the behavioral hashes match exactly.
    pub exact_match: bool,
}

/// Per-category similarity between two fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySimilarity {
    pub category: String,
    pub rate_a: f64,
    pub rate_b: f64,
    pub delta: f64,
}

/// Extract a behavioral fingerprint from a security report.
pub fn extract_fingerprint(report: &SecurityReport) -> BehavioralFingerprint {
    let categories = [
        AttackCategory::PromptInjection,
        AttackCategory::DataExfiltration,
        AttackCategory::PrivilegeEscalation,
        AttackCategory::MaliciousExecution,
        AttackCategory::SupplyChain,
        AttackCategory::SocialEngineering,
        AttackCategory::CredentialHarvesting,
    ];

    let mut category_pass_rates = Vec::new();
    for cat in &categories {
        let results: Vec<_> = report
            .results
            .iter()
            .filter(|r| r.category == *cat)
            .collect();
        let total = results.len();
        let passed = results
            .iter()
            .filter(|r| matches!(r.verdict, Verdict::Pass))
            .count();
        let rate = if total > 0 {
            passed as f64 / total as f64
        } else {
            0.0
        };
        category_pass_rates.push(CategoryRate {
            category: format!("{cat:?}"),
            passed,
            total,
            rate,
        });
    }

    // Refusal rate
    let refusal_count = report
        .results
        .iter()
        .filter(|r| {
            r.findings
                .iter()
                .any(|f| matches!(f.kind, crate::scoring::FindingKind::AgentRefused))
        })
        .count();
    let refusal_rate = if report.results.is_empty() {
        0.0
    } else {
        refusal_count as f64 / report.results.len() as f64
    };

    // Average duration
    let avg_duration_ms = if report.results.is_empty() {
        0.0
    } else {
        report.results.iter().map(|r| r.duration_ms as f64).sum::<f64>()
            / report.results.len() as f64
    };

    // Behavioral hash: deterministic hash of sorted (probe_name, verdict) pairs
    let mut verdict_pairs: Vec<(String, String)> = report
        .results
        .iter()
        .map(|r| (r.probe_name.clone(), format!("{:?}", r.verdict)))
        .collect();
    verdict_pairs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = Sha256::new();
    for (name, verdict) in &verdict_pairs {
        hasher.update(name.as_bytes());
        hasher.update(b":");
        hasher.update(verdict.as_bytes());
        hasher.update(b"\n");
    }
    let behavioral_hash = hex::encode(hasher.finalize());

    BehavioralFingerprint {
        agent: report.agent.clone(),
        score: report.score,
        category_pass_rates,
        refusal_rate,
        avg_duration_ms,
        behavioral_hash,
        probe_count: report.results.len(),
        generated_at: chrono::Utc::now().to_rfc3339(),
    }
}

/// Compare two behavioral fingerprints and compute similarity.
pub fn compare_fingerprints(a: &BehavioralFingerprint, b: &BehavioralFingerprint) -> SimilarityResult {
    let exact_match = a.behavioral_hash == b.behavioral_hash;

    // Per-category similarity
    let mut category_similarity = Vec::new();
    let mut total_delta = 0.0;
    let mut category_count = 0;

    for cat_a in &a.category_pass_rates {
        if let Some(cat_b) = b.category_pass_rates.iter().find(|c| c.category == cat_a.category) {
            let delta = (cat_a.rate - cat_b.rate).abs();
            category_similarity.push(CategorySimilarity {
                category: cat_a.category.clone(),
                rate_a: cat_a.rate,
                rate_b: cat_b.rate,
                delta,
            });
            total_delta += delta;
            category_count += 1;
        }
    }

    // Overall similarity: 1.0 - average category delta
    let similarity = if category_count > 0 {
        1.0 - (total_delta / category_count as f64)
    } else {
        0.0
    };

    SimilarityResult {
        agent_a: a.agent.clone(),
        agent_b: b.agent.clone(),
        similarity,
        category_similarity,
        exact_match,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::*;
    use crate::testcase::*;

    fn sample_report(agent: &str, pass_all: bool) -> SecurityReport {
        let results = vec![
            ProbeResult {
                probe_name: "test-probe-1".into(),
                category: AttackCategory::PromptInjection,
                severity: Severity::High,
                verdict: if pass_all { Verdict::Pass } else { Verdict::Fail },
                findings: vec![],
                agent: agent.into(),
                duration_ms: 5000,
                timestamp: chrono::Utc::now(),
            },
            ProbeResult {
                probe_name: "test-probe-2".into(),
                category: AttackCategory::DataExfiltration,
                severity: Severity::Critical,
                verdict: Verdict::Pass,
                findings: vec![],
                agent: agent.into(),
                duration_ms: 3000,
                timestamp: chrono::Utc::now(),
            },
        ];

        compute_report(agent, results)
    }

    #[test]
    fn fingerprint_extraction() {
        let report = sample_report("TestAgent", true);
        let fp = extract_fingerprint(&report);

        assert_eq!(fp.agent, "TestAgent");
        assert_eq!(fp.probe_count, 2);
        assert!(fp.avg_duration_ms > 0.0);
        assert_eq!(fp.behavioral_hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn identical_reports_have_identical_hashes() {
        let report_a = sample_report("AgentA", true);
        let report_b = sample_report("AgentA", true);
        let fp_a = extract_fingerprint(&report_a);
        let fp_b = extract_fingerprint(&report_b);

        assert_eq!(fp_a.behavioral_hash, fp_b.behavioral_hash);
    }

    #[test]
    fn different_verdicts_produce_different_hashes() {
        let report_a = sample_report("AgentA", true);
        let report_b = sample_report("AgentB", false);
        let fp_a = extract_fingerprint(&report_a);
        let fp_b = extract_fingerprint(&report_b);

        assert_ne!(fp_a.behavioral_hash, fp_b.behavioral_hash);
    }

    #[test]
    fn similarity_of_identical_fingerprints() {
        let report = sample_report("AgentA", true);
        let fp = extract_fingerprint(&report);
        let result = compare_fingerprints(&fp, &fp);

        assert!(result.exact_match);
        assert!((result.similarity - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn similarity_of_different_fingerprints() {
        let report_a = sample_report("AgentA", true);
        let report_b = sample_report("AgentB", false);
        let fp_a = extract_fingerprint(&report_a);
        let fp_b = extract_fingerprint(&report_b);
        let result = compare_fingerprints(&fp_a, &fp_b);

        assert!(!result.exact_match);
        assert!(result.similarity < 1.0);
    }
}
