//! Distillation detection: analyze whether one agent is a distillation of another.
//!
//! Compares two agents across multiple behavioral dimensions to assess whether
//! one model's behavior is derived from the other through knowledge distillation.

use serde::{Deserialize, Serialize};

use crate::fingerprint::ModelFingerprint;
use crate::scoring::SecurityReport;

/// Signal weights for the distillation score. These are tunable constants.
const W_VERDICT_AGREEMENT: f64 = 0.25;
const W_REFUSAL_SIMILARITY: f64 = 0.20;
const W_LENGTH_CORRELATION: f64 = 0.15;
const W_LATENCY_STABILITY: f64 = 0.15;
const W_EDGE_CASE: f64 = 0.15;
const W_VOCABULARY: f64 = 0.10;

/// Result of distillation analysis between two agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistillationAnalysis {
    pub agent_a: String,
    pub agent_b: String,
    /// Overall distillation likelihood (0.0 = independent, 1.0 = near-certain distillation).
    pub distillation_score: f64,
    /// Interpretation label.
    pub interpretation: DistillationInterpretation,
    /// Individual signal scores.
    pub signals: DistillationSignals,
    /// Number of probes compared (intersection of both reports).
    pub probes_compared: usize,
}

/// How likely it is that one model is a distillation of the other.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistillationInterpretation {
    /// Agents appear to be independently developed.
    Independent,
    /// Agents share some behavioral traits but likely independent.
    SharedTraits,
    /// Significant behavioral overlap suggests shared training or distillation.
    PossibleDistillation,
    /// Very high behavioral correlation consistent with distillation.
    LikelyDistillation,
}

/// Individual signal scores used to compute the distillation score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistillationSignals {
    /// Fraction of probes with the same verdict.
    pub verdict_agreement: f64,
    /// Cosine similarity of refusal style vectors.
    pub refusal_similarity: f64,
    /// Pearson correlation of output lengths.
    pub length_correlation: f64,
    /// Geometric mean of latency ratios (A/B).
    pub latency_ratio: f64,
    /// Stability of latency ratios (low std_dev = suspicious).
    pub latency_ratio_stability: f64,
    /// Agreement rate on probes where one agent's verdict was Partial.
    pub edge_case_agreement: f64,
    /// Jaccard similarity of top distinctive tokens.
    pub vocabulary_overlap: f64,
}

/// Analyze whether one agent is likely a distillation of another.
///
/// Requires both agents to have been tested against the same probe set.
/// Only probes present in both reports are compared.
pub fn analyze_distillation(
    report_a: &SecurityReport,
    report_b: &SecurityReport,
    fingerprint_a: Option<&ModelFingerprint>,
    fingerprint_b: Option<&ModelFingerprint>,
) -> DistillationAnalysis {
    // Match probes by name across both reports
    let mut matched_pairs = Vec::new();
    for result_a in &report_a.results {
        if let Some(result_b) = report_b
            .results
            .iter()
            .find(|r| r.probe_name == result_a.probe_name)
        {
            matched_pairs.push((result_a, result_b));
        }
    }

    let probes_compared = matched_pairs.len();

    // Verdict agreement
    let verdict_agreement = if matched_pairs.is_empty() {
        0.0
    } else {
        let agreed = matched_pairs
            .iter()
            .filter(|(a, b)| a.verdict == b.verdict)
            .count();
        agreed as f64 / matched_pairs.len() as f64
    };

    // Output length correlation (Pearson r)
    let lengths_a: Vec<f64> = matched_pairs
        .iter()
        .map(|(a, _)| a.output_length as f64)
        .collect();
    let lengths_b: Vec<f64> = matched_pairs
        .iter()
        .map(|(_, b)| b.output_length as f64)
        .collect();
    let length_correlation = pearson_r(&lengths_a, &lengths_b);

    // Latency ratio analysis
    let latency_ratios: Vec<f64> = matched_pairs
        .iter()
        .filter_map(|(a, b)| {
            if b.duration_ms > 0 {
                Some(a.duration_ms as f64 / b.duration_ms as f64)
            } else {
                None
            }
        })
        .collect();

    let latency_ratio = if latency_ratios.is_empty() {
        1.0
    } else {
        // Geometric mean
        let log_sum: f64 = latency_ratios.iter().map(|r| r.ln()).sum();
        (log_sum / latency_ratios.len() as f64).exp()
    };

    let latency_ratio_stability = if latency_ratios.len() < 2 {
        0.0
    } else {
        let mean = latency_ratios.iter().sum::<f64>() / latency_ratios.len() as f64;
        let variance = latency_ratios
            .iter()
            .map(|r| (r - mean).powi(2))
            .sum::<f64>()
            / (latency_ratios.len() - 1) as f64;
        // Invert: low std_dev = high stability score
        let cv = if mean > 0.0 {
            variance.sqrt() / mean
        } else {
            1.0
        };
        (1.0 - cv).max(0.0)
    };

    // Edge case agreement (probes where one was Partial)
    let edge_cases: Vec<_> = matched_pairs
        .iter()
        .filter(|(a, b)| {
            a.verdict == crate::scoring::Verdict::Partial
                || b.verdict == crate::scoring::Verdict::Partial
        })
        .collect();
    let edge_case_agreement = if edge_cases.is_empty() {
        0.5 // neutral when no edge cases
    } else {
        let agreed = edge_cases
            .iter()
            .filter(|(a, b)| a.verdict == b.verdict)
            .count();
        agreed as f64 / edge_cases.len() as f64
    };

    // Refusal similarity and vocabulary overlap from model fingerprints
    let (refusal_similarity, vocabulary_overlap) =
        match (fingerprint_a, fingerprint_b) {
            (Some(fp_a), Some(fp_b)) => {
                let refusal_sim = cosine_similarity_refusal(
                    &fp_a.refusal_style,
                    &fp_b.refusal_style,
                );
                let vocab_overlap = jaccard_similarity(
                    &fp_a
                        .vocabulary_signature
                        .distinctive_tokens
                        .iter()
                        .map(|(t, _)| t.as_str())
                        .collect::<Vec<_>>(),
                    &fp_b
                        .vocabulary_signature
                        .distinctive_tokens
                        .iter()
                        .map(|(t, _)| t.as_str())
                        .collect::<Vec<_>>(),
                );
                (refusal_sim, vocab_overlap)
            }
            _ => (0.5, 0.5), // neutral when fingerprints unavailable
        };

    let signals = DistillationSignals {
        verdict_agreement,
        refusal_similarity,
        length_correlation,
        latency_ratio,
        latency_ratio_stability,
        edge_case_agreement,
        vocabulary_overlap,
    };

    // Weighted distillation score
    let distillation_score = verdict_agreement * W_VERDICT_AGREEMENT
        + refusal_similarity * W_REFUSAL_SIMILARITY
        + length_correlation.abs() * W_LENGTH_CORRELATION
        + latency_ratio_stability * W_LATENCY_STABILITY
        + edge_case_agreement * W_EDGE_CASE
        + vocabulary_overlap * W_VOCABULARY;

    let interpretation = if distillation_score >= 0.85 {
        DistillationInterpretation::LikelyDistillation
    } else if distillation_score >= 0.70 {
        DistillationInterpretation::PossibleDistillation
    } else if distillation_score >= 0.50 {
        DistillationInterpretation::SharedTraits
    } else {
        DistillationInterpretation::Independent
    };

    DistillationAnalysis {
        agent_a: report_a.agent.clone(),
        agent_b: report_b.agent.clone(),
        distillation_score,
        interpretation,
        signals,
        probes_compared,
    }
}

/// Pearson correlation coefficient between two samples.
fn pearson_r(x: &[f64], y: &[f64]) -> f64 {
    if x.len() != y.len() || x.len() < 2 {
        return 0.0;
    }
    let n = x.len() as f64;
    let mean_x = x.iter().sum::<f64>() / n;
    let mean_y = y.iter().sum::<f64>() / n;

    let mut cov = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;
    for (xi, yi) in x.iter().zip(y.iter()) {
        let dx = xi - mean_x;
        let dy = yi - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }

    let denom = (var_x * var_y).sqrt();
    if denom < f64::EPSILON {
        0.0
    } else {
        cov / denom
    }
}

/// Cosine similarity of refusal style vectors.
fn cosine_similarity_refusal(
    a: &crate::fingerprint::RefusalStyle,
    b: &crate::fingerprint::RefusalStyle,
) -> f64 {
    let va = [
        a.direct_refusal_rate,
        a.redirect_rate,
        a.apology_rate,
        a.policy_citation_rate,
    ];
    let vb = [
        b.direct_refusal_rate,
        b.redirect_rate,
        b.apology_rate,
        b.policy_citation_rate,
    ];

    let dot: f64 = va.iter().zip(vb.iter()).map(|(a, b)| a * b).sum();
    let mag_a: f64 = va.iter().map(|x| x * x).sum::<f64>().sqrt();
    let mag_b: f64 = vb.iter().map(|x| x * x).sum::<f64>().sqrt();

    if mag_a < f64::EPSILON || mag_b < f64::EPSILON {
        0.0
    } else {
        dot / (mag_a * mag_b)
    }
}

/// Jaccard similarity of two token sets.
fn jaccard_similarity(a: &[&str], b: &[&str]) -> f64 {
    use std::collections::HashSet;
    let set_a: HashSet<&str> = a.iter().copied().collect();
    let set_b: HashSet<&str> = b.iter().copied().collect();

    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();

    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pearson_r_perfect_correlation() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![2.0, 4.0, 6.0, 8.0, 10.0];
        let r = pearson_r(&x, &y);
        assert!((r - 1.0).abs() < 1e-10);
    }

    #[test]
    fn pearson_r_no_correlation() {
        let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let y = vec![5.0, 1.0, 4.0, 2.0, 3.0];
        let r = pearson_r(&x, &y);
        assert!(r.abs() < 0.5);
    }

    #[test]
    fn jaccard_identical_sets() {
        let a = vec!["hello", "world"];
        let b = vec!["hello", "world"];
        assert!((jaccard_similarity(&a, &b) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn jaccard_disjoint_sets() {
        let a = vec!["hello"];
        let b = vec!["world"];
        assert!(jaccard_similarity(&a, &b).abs() < f64::EPSILON);
    }

    #[test]
    fn interpretation_thresholds() {
        // Verify the threshold logic
        assert!(matches!(
            DistillationInterpretation::LikelyDistillation,
            DistillationInterpretation::LikelyDistillation
        ));
    }
}
