//! Behavioral fingerprinting for AI agent/model characterization.
//!
//! Extracts behavioral signatures from probe results to enable:
//! - Cross-model comparison (which models resist which attacks?)
//! - Version regression detection (did a model update change behavior?)
//! - Distillation detection (do two models exhibit suspiciously similar patterns?)
//!
//! A fingerprint is a vector of behavioral dimensions computed from probe results.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::scoring::{FindingKind, SecurityReport, Verdict};
use crate::stats::DescriptiveStats;
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

/// Extended model fingerprint with text analysis signals.
///
/// Goes beyond verdict-based fingerprinting to analyze output characteristics
/// that can identify the underlying model powering an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelFingerprint {
    /// Base behavioral fingerprint (verdict-based).
    pub behavioral: BehavioralFingerprint,
    /// Refusal style analysis.
    pub refusal_style: RefusalStyle,
    /// Response latency profile.
    pub latency_profile: LatencyProfile,
    /// Output length profile.
    pub output_profile: OutputProfile,
    /// Vocabulary signature.
    pub vocabulary_signature: VocabularySignature,
    /// Indicator triggering pattern.
    pub indicator_pattern: IndicatorPattern,
}

/// How the model refuses adversarial requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefusalStyle {
    /// Fraction that use "I cannot" / "I can't" style (direct refusal).
    pub direct_refusal_rate: f64,
    /// Fraction that redirect ("instead, let me...").
    pub redirect_rate: f64,
    /// Fraction with verbose apology ("I apologize, but...").
    pub apology_rate: f64,
    /// Fraction that cite policy ("my guidelines...").
    pub policy_citation_rate: f64,
    /// Average refusal length in characters.
    pub avg_refusal_length: f64,
    /// Number of refusals analyzed.
    pub sample_count: usize,
}

/// Response latency distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyProfile {
    pub stats: DescriptiveStats,
    /// Latency distribution shape (ratio of p75/p25).
    pub skew_ratio: f64,
}

/// Output length distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputProfile {
    pub length_stats: DescriptiveStats,
    /// Ratio of output length on pass vs fail probes.
    pub pass_fail_length_ratio: f64,
}

/// Vocabulary-based signature for model identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VocabularySignature {
    /// Top 20 most distinctive words by frequency.
    pub distinctive_tokens: Vec<(String, f64)>,
    /// Average sentence length in words.
    pub avg_sentence_length: f64,
    /// Fraction of outputs containing markdown formatting.
    pub markdown_rate: f64,
    /// Fraction of outputs containing triple-backtick code blocks.
    pub code_block_rate: f64,
}

/// Which compromise indicators triggered and at what rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorPattern {
    /// Per-indicator trigger rates.
    pub indicator_rates: Vec<(String, f64)>,
    /// Average number of indicators triggered per fail.
    pub avg_indicators_per_fail: f64,
}

/// Similarity between two model fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSimilarity {
    pub agent_a: String,
    pub agent_b: String,
    pub overall_similarity: f64,
    pub behavioral_similarity: f64,
    pub refusal_similarity: f64,
    pub latency_similarity: f64,
    pub vocabulary_similarity: f64,
}

/// Extract an extended model fingerprint from a security report.
///
/// Requires `agent_output` to be populated in the probe results
/// (use `--capture-output` when running probes).
pub fn extract_model_fingerprint(report: &SecurityReport) -> ModelFingerprint {
    let behavioral = extract_fingerprint(report);

    // Collect outputs from results that have them
    let outputs_with_meta: Vec<_> = report
        .results
        .iter()
        .filter_map(|r| {
            r.agent_output.as_deref().map(|output| {
                (
                    output,
                    r.verdict,
                    r.duration_ms,
                    r.output_length,
                    &r.findings,
                )
            })
        })
        .collect();

    let refusal_style = analyze_refusal_style(&outputs_with_meta);
    let latency_profile = analyze_latency(report);
    let output_profile = analyze_output_lengths(report);
    let vocabulary_signature = compute_vocabulary_signature(
        &outputs_with_meta
            .iter()
            .map(|(output, _, _, _, _)| *output)
            .collect::<Vec<_>>(),
    );
    let indicator_pattern = analyze_indicators(report);

    ModelFingerprint {
        behavioral,
        refusal_style,
        latency_profile,
        output_profile,
        vocabulary_signature,
        indicator_pattern,
    }
}

/// Classify refusal style from agent outputs.
fn analyze_refusal_style(
    outputs: &[(&str, Verdict, u64, usize, &Vec<crate::scoring::Finding>)],
) -> RefusalStyle {
    let refusal_outputs: Vec<&str> = outputs
        .iter()
        .filter(|(_, _, _, _, findings)| {
            findings
                .iter()
                .any(|f| matches!(f.kind, FindingKind::AgentRefused))
        })
        .map(|(output, _, _, _, _)| *output)
        .collect();

    let sample_count = refusal_outputs.len();
    if sample_count == 0 {
        return RefusalStyle {
            direct_refusal_rate: 0.0,
            redirect_rate: 0.0,
            apology_rate: 0.0,
            policy_citation_rate: 0.0,
            avg_refusal_length: 0.0,
            sample_count: 0,
        };
    }

    let direct_patterns = [
        "i cannot",
        "i can't",
        "i won't",
        "i will not",
        "i'm unable",
        "i am unable",
        "cannot do that",
        "not able to",
    ];
    let redirect_patterns = [
        "instead",
        "let me",
        "how about",
        "alternatively",
        "i can help you with",
    ];
    let apology_patterns = ["i apologize", "i'm sorry", "sorry,", "apologies"];
    let policy_patterns = [
        "guidelines",
        "policy",
        "terms of service",
        "not allowed",
        "against my",
        "programmed to",
        "designed to",
    ];

    let mut direct = 0;
    let mut redirect = 0;
    let mut apology = 0;
    let mut policy = 0;
    let mut total_len = 0usize;

    for output in &refusal_outputs {
        let lower = output.to_lowercase();
        if direct_patterns.iter().any(|p| lower.contains(p)) {
            direct += 1;
        }
        if redirect_patterns.iter().any(|p| lower.contains(p)) {
            redirect += 1;
        }
        if apology_patterns.iter().any(|p| lower.contains(p)) {
            apology += 1;
        }
        if policy_patterns.iter().any(|p| lower.contains(p)) {
            policy += 1;
        }
        total_len += output.len();
    }

    let n = sample_count as f64;
    RefusalStyle {
        direct_refusal_rate: direct as f64 / n,
        redirect_rate: redirect as f64 / n,
        apology_rate: apology as f64 / n,
        policy_citation_rate: policy as f64 / n,
        avg_refusal_length: total_len as f64 / n,
        sample_count,
    }
}

/// Analyze response latency distribution.
fn analyze_latency(report: &SecurityReport) -> LatencyProfile {
    let durations: Vec<f64> = report
        .results
        .iter()
        .map(|r| r.duration_ms as f64)
        .collect();

    let stats = crate::stats::descriptive_stats(&durations);
    let skew_ratio = if stats.p25 > 0.0 {
        stats.p75 / stats.p25
    } else {
        1.0
    };

    LatencyProfile { stats, skew_ratio }
}

/// Analyze output length distribution.
fn analyze_output_lengths(report: &SecurityReport) -> OutputProfile {
    let lengths: Vec<f64> = report
        .results
        .iter()
        .map(|r| r.output_length as f64)
        .collect();

    let pass_lengths: Vec<f64> = report
        .results
        .iter()
        .filter(|r| r.verdict == Verdict::Pass)
        .map(|r| r.output_length as f64)
        .collect();

    let fail_lengths: Vec<f64> = report
        .results
        .iter()
        .filter(|r| r.verdict == Verdict::Fail)
        .map(|r| r.output_length as f64)
        .collect();

    let pass_mean = if pass_lengths.is_empty() {
        0.0
    } else {
        pass_lengths.iter().sum::<f64>() / pass_lengths.len() as f64
    };

    let fail_mean = if fail_lengths.is_empty() {
        0.0
    } else {
        fail_lengths.iter().sum::<f64>() / fail_lengths.len() as f64
    };

    let pass_fail_length_ratio = if fail_mean > 0.0 {
        pass_mean / fail_mean
    } else {
        0.0
    };

    OutputProfile {
        length_stats: crate::stats::descriptive_stats(&lengths),
        pass_fail_length_ratio,
    }
}

/// Compute a vocabulary signature from output texts.
fn compute_vocabulary_signature(outputs: &[&str]) -> VocabularySignature {
    if outputs.is_empty() {
        return VocabularySignature {
            distinctive_tokens: Vec::new(),
            avg_sentence_length: 0.0,
            markdown_rate: 0.0,
            code_block_rate: 0.0,
        };
    }

    // Word frequencies
    let mut word_counts: HashMap<String, usize> = HashMap::new();
    let mut total_words = 0usize;
    let mut total_sentences = 0usize;
    let mut markdown_count = 0;
    let mut code_block_count = 0;

    for output in outputs {
        // Count markdown/code features
        if output.contains('#') || output.contains("**") || output.contains("- ") {
            markdown_count += 1;
        }
        if output.contains("```") {
            code_block_count += 1;
        }

        // Simple sentence splitting
        let sentences: Vec<_> = output
            .split(['.', '!', '?'])
            .filter(|s| !s.trim().is_empty())
            .collect();
        total_sentences += sentences.len();

        // Tokenize by whitespace
        for word in output.split_whitespace() {
            let cleaned: String = word
                .chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
                .to_lowercase();
            if cleaned.len() >= 3 {
                *word_counts.entry(cleaned).or_insert(0) += 1;
                total_words += 1;
            }
        }
    }

    let n = outputs.len() as f64;
    let avg_sentence_length = if total_sentences > 0 {
        total_words as f64 / total_sentences as f64
    } else {
        0.0
    };

    // Extract top 20 words by frequency (TF score)
    let mut word_scores: Vec<(String, f64)> = word_counts
        .into_iter()
        .map(|(word, count)| {
            let tf = count as f64 / total_words.max(1) as f64;
            (word, tf)
        })
        .collect();
    word_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    word_scores.truncate(20);

    VocabularySignature {
        distinctive_tokens: word_scores,
        avg_sentence_length,
        markdown_rate: markdown_count as f64 / n,
        code_block_rate: code_block_count as f64 / n,
    }
}

/// Analyze which compromise indicators get triggered and at what rate.
fn analyze_indicators(report: &SecurityReport) -> IndicatorPattern {
    let mut indicator_counts: HashMap<String, usize> = HashMap::new();
    let mut total_fail_indicators = 0;
    let mut fail_count = 0;

    for result in &report.results {
        if result.verdict == Verdict::Fail {
            fail_count += 1;
            let indicators_in_result = result
                .findings
                .iter()
                .filter(|f| matches!(f.kind, FindingKind::CompromiseIndicator))
                .count();
            total_fail_indicators += indicators_in_result;
        }

        for finding in &result.findings {
            if matches!(finding.kind, FindingKind::CompromiseIndicator) {
                *indicator_counts
                    .entry(finding.description.clone())
                    .or_insert(0) += 1;
            }
        }
    }

    let total = report.results.len().max(1) as f64;
    let mut indicator_rates: Vec<(String, f64)> = indicator_counts
        .into_iter()
        .map(|(desc, count)| (desc, count as f64 / total))
        .collect();
    indicator_rates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let avg_indicators_per_fail = if fail_count > 0 {
        total_fail_indicators as f64 / fail_count as f64
    } else {
        0.0
    };

    IndicatorPattern {
        indicator_rates,
        avg_indicators_per_fail,
    }
}

/// Compare two model fingerprints across all dimensions.
pub fn compare_model_fingerprints(a: &ModelFingerprint, b: &ModelFingerprint) -> ModelSimilarity {
    let behavioral_similarity = compare_fingerprints(&a.behavioral, &b.behavioral).similarity;

    // Refusal style cosine similarity
    let refusal_similarity = {
        let va = [
            a.refusal_style.direct_refusal_rate,
            a.refusal_style.redirect_rate,
            a.refusal_style.apology_rate,
            a.refusal_style.policy_citation_rate,
        ];
        let vb = [
            b.refusal_style.direct_refusal_rate,
            b.refusal_style.redirect_rate,
            b.refusal_style.apology_rate,
            b.refusal_style.policy_citation_rate,
        ];
        let dot: f64 = va.iter().zip(vb.iter()).map(|(x, y)| x * y).sum();
        let mag_a: f64 = va.iter().map(|x| x * x).sum::<f64>().sqrt();
        let mag_b: f64 = vb.iter().map(|x| x * x).sum::<f64>().sqrt();
        if mag_a < f64::EPSILON || mag_b < f64::EPSILON {
            0.0
        } else {
            dot / (mag_a * mag_b)
        }
    };

    // Latency similarity (1 - normalized difference in means)
    let latency_similarity = {
        let max_lat = a
            .latency_profile
            .stats
            .mean
            .max(b.latency_profile.stats.mean);
        if max_lat < f64::EPSILON {
            1.0
        } else {
            1.0 - (a.latency_profile.stats.mean - b.latency_profile.stats.mean).abs() / max_lat
        }
    };

    // Vocabulary similarity (Jaccard of top tokens)
    let vocabulary_similarity = {
        use std::collections::HashSet;
        let tokens_a: HashSet<&str> = a
            .vocabulary_signature
            .distinctive_tokens
            .iter()
            .map(|(t, _)| t.as_str())
            .collect();
        let tokens_b: HashSet<&str> = b
            .vocabulary_signature
            .distinctive_tokens
            .iter()
            .map(|(t, _)| t.as_str())
            .collect();
        let intersection = tokens_a.intersection(&tokens_b).count();
        let union = tokens_a.union(&tokens_b).count();
        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    };

    let overall_similarity = behavioral_similarity * 0.35
        + refusal_similarity * 0.25
        + latency_similarity * 0.15
        + vocabulary_similarity * 0.25;

    ModelSimilarity {
        agent_a: a.behavioral.agent.clone(),
        agent_b: b.behavioral.agent.clone(),
        overall_similarity,
        behavioral_similarity,
        refusal_similarity,
        latency_similarity,
        vocabulary_similarity,
    }
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
        report
            .results
            .iter()
            .map(|r| r.duration_ms as f64)
            .sum::<f64>()
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
pub fn compare_fingerprints(
    a: &BehavioralFingerprint,
    b: &BehavioralFingerprint,
) -> SimilarityResult {
    let exact_match = a.behavioral_hash == b.behavioral_hash;

    // Per-category similarity
    let mut category_similarity = Vec::new();
    let mut total_delta = 0.0;
    let mut category_count = 0;

    for cat_a in &a.category_pass_rates {
        if let Some(cat_b) = b
            .category_pass_rates
            .iter()
            .find(|c| c.category == cat_a.category)
        {
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
                tags: vec![],
                category: AttackCategory::PromptInjection,
                severity: Severity::High,
                verdict: if pass_all {
                    Verdict::Pass
                } else {
                    Verdict::Fail
                },
                findings: vec![],
                agent: agent.into(),
                duration_ms: 5000,
                timestamp: chrono::Utc::now(),
                output_length: 0,
                agent_output: None,
            },
            ProbeResult {
                probe_name: "test-probe-2".into(),
                tags: vec![],
                category: AttackCategory::DataExfiltration,
                severity: Severity::Critical,
                verdict: Verdict::Pass,
                findings: vec![],
                agent: agent.into(),
                duration_ms: 3000,
                timestamp: chrono::Utc::now(),
                output_length: 0,
                agent_output: None,
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
