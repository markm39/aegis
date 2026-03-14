//! Statistical analysis for multi-run probe aggregation.
//!
//! Provides descriptive statistics, confidence intervals, hypothesis testing,
//! and multi-run aggregation for security probe results.

use serde::{Deserialize, Serialize};

use crate::scoring::{SecurityReport, Verdict};
use crate::testcase::AttackCategory;

/// Descriptive statistics for a numeric sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptiveStats {
    pub count: usize,
    pub mean: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub median: f64,
    pub p5: f64,
    pub p25: f64,
    pub p75: f64,
    pub p95: f64,
}

/// Aggregated statistics from multiple runs of the same probe set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiRunReport {
    pub agent: String,
    pub run_count: usize,
    pub probe_stats: Vec<ProbeStats>,
    pub aggregate: AggregateStats,
    pub generated_at: String,
}

/// Per-probe statistics across multiple runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeStats {
    pub probe_name: String,
    pub category: String,
    pub runs: usize,
    pub pass_rate: f64,
    pub fail_rate: f64,
    pub error_rate: f64,
    pub duration: DescriptiveStats,
    pub output_length: DescriptiveStats,
    /// 1.0 = same verdict every run, 0.0 = maximally unstable.
    pub verdict_stability: f64,
}

/// Aggregate statistics across all probes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateStats {
    pub score: DescriptiveStats,
    pub overall_pass_rate: DescriptiveStats,
    pub total_duration: DescriptiveStats,
    pub category_pass_rates: Vec<CategoryStats>,
    /// 95% confidence interval for the overall score.
    pub confidence_interval_95: (f64, f64),
}

/// Per-category aggregated statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryStats {
    pub category: String,
    pub pass_rate: DescriptiveStats,
}

/// Compute descriptive statistics from a sample of values.
///
/// Returns zero-valued stats for empty input.
pub fn descriptive_stats(samples: &[f64]) -> DescriptiveStats {
    if samples.is_empty() {
        return DescriptiveStats {
            count: 0,
            mean: 0.0,
            std_dev: 0.0,
            min: 0.0,
            max: 0.0,
            median: 0.0,
            p5: 0.0,
            p25: 0.0,
            p75: 0.0,
            p95: 0.0,
        };
    }

    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n = sorted.len();
    let mean = sorted.iter().sum::<f64>() / n as f64;

    let std_dev = if n > 1 {
        let variance = sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
        variance.sqrt()
    } else {
        0.0
    };

    DescriptiveStats {
        count: n,
        mean,
        std_dev,
        min: sorted[0],
        max: sorted[n - 1],
        median: percentile(&sorted, 50.0),
        p5: percentile(&sorted, 5.0),
        p25: percentile(&sorted, 25.0),
        p75: percentile(&sorted, 75.0),
        p95: percentile(&sorted, 95.0),
    }
}

/// Linear interpolation percentile on a pre-sorted slice.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let k = p / 100.0 * (sorted.len() - 1) as f64;
    let floor = k.floor() as usize;
    let ceil = k.ceil() as usize;
    if floor == ceil {
        sorted[floor]
    } else {
        let frac = k - floor as f64;
        sorted[floor] * (1.0 - frac) + sorted[ceil] * frac
    }
}

/// Compute a confidence interval for the mean of a sample.
///
/// Uses t-distribution critical values for small samples, z-approximation for large.
pub fn confidence_interval(samples: &[f64], confidence: f64) -> (f64, f64) {
    if samples.len() < 2 {
        let val = samples.first().copied().unwrap_or(0.0);
        return (val, val);
    }

    let n = samples.len();
    let mean = samples.iter().sum::<f64>() / n as f64;
    let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
    let se = variance.sqrt() / (n as f64).sqrt();

    let df = n - 1;
    let t = t_critical(df, confidence);
    let margin = t * se;

    (mean - margin, mean + margin)
}

/// T-distribution critical values (two-tailed).
///
/// Hardcoded lookup for common confidence levels and degrees of freedom.
/// Falls back to z-approximation for large df.
fn t_critical(df: usize, confidence: f64) -> f64 {
    // For 95% confidence (most common case)
    if (confidence - 0.95).abs() < 0.001 {
        match df {
            1 => 12.706,
            2 => 4.303,
            3 => 3.182,
            4 => 2.776,
            5 => 2.571,
            6 => 2.447,
            7 => 2.365,
            8 => 2.306,
            9 => 2.262,
            10 => 2.228,
            11 => 2.201,
            12 => 2.179,
            13 => 2.160,
            14 => 2.145,
            15 => 2.131,
            20 => 2.086,
            25 => 2.060,
            30 => 2.042,
            40 => 2.021,
            50 => 2.009,
            60 => 2.000,
            80 => 1.990,
            100 => 1.984,
            _ if df > 100 => 1.960, // z-approximation
            _ => {
                // Interpolate between nearest known values
                let lower = [
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 20, 25, 30, 40, 50, 60, 80,
                    100,
                ];
                let values = [
                    12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201,
                    2.179, 2.160, 2.145, 2.131, 2.086, 2.060, 2.042, 2.021, 2.009, 2.000, 1.990,
                    1.984,
                ];
                interpolate_lookup(&lower, &values, df)
            }
        }
    } else if (confidence - 0.99).abs() < 0.001 {
        match df {
            1 => 63.657,
            2 => 9.925,
            3 => 5.841,
            4 => 4.604,
            5 => 4.032,
            10 => 3.169,
            15 => 2.947,
            20 => 2.845,
            30 => 2.750,
            50 => 2.678,
            100 => 2.626,
            _ if df > 100 => 2.576,
            _ => 2.576, // z-approx fallback
        }
    } else if (confidence - 0.90).abs() < 0.001 {
        match df {
            1 => 6.314,
            2 => 2.920,
            3 => 2.353,
            4 => 2.132,
            5 => 2.015,
            10 => 1.812,
            15 => 1.753,
            20 => 1.725,
            30 => 1.697,
            50 => 1.676,
            100 => 1.660,
            _ if df > 100 => 1.645,
            _ => 1.645, // z-approx fallback
        }
    } else {
        // Default to 95% z-approximation
        1.960
    }
}

/// Linear interpolation between lookup table entries.
fn interpolate_lookup(keys: &[usize], values: &[f64], target: usize) -> f64 {
    for i in 0..keys.len() - 1 {
        if target >= keys[i] && target <= keys[i + 1] {
            let frac = (target - keys[i]) as f64 / (keys[i + 1] - keys[i]) as f64;
            return values[i] * (1.0 - frac) + values[i + 1] * frac;
        }
    }
    *values.last().unwrap_or(&1.96)
}

/// Measure how stable a probe's verdict is across runs.
///
/// Returns the fraction of runs that produced the most common verdict.
/// 1.0 = perfectly stable, 0.25 = all four verdicts equally likely.
pub fn verdict_stability(verdicts: &[Verdict]) -> f64 {
    if verdicts.is_empty() {
        return 0.0;
    }
    let mut pass = 0;
    let mut fail = 0;
    let mut partial = 0;
    let mut error = 0;
    for v in verdicts {
        match v {
            Verdict::Pass => pass += 1,
            Verdict::Fail => fail += 1,
            Verdict::Partial => partial += 1,
            Verdict::Error => error += 1,
        }
    }
    let max_count = pass.max(fail).max(partial).max(error);
    max_count as f64 / verdicts.len() as f64
}

/// Cohen's d effect size for comparing two groups.
///
/// Positive d means group_a has a higher mean than group_b.
/// |d| < 0.2 = negligible, 0.2-0.5 = small, 0.5-0.8 = medium, > 0.8 = large.
pub fn cohens_d(group_a: &[f64], group_b: &[f64]) -> f64 {
    if group_a.len() < 2 || group_b.len() < 2 {
        return 0.0;
    }
    let mean_a = group_a.iter().sum::<f64>() / group_a.len() as f64;
    let mean_b = group_b.iter().sum::<f64>() / group_b.len() as f64;
    let var_a =
        group_a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (group_a.len() - 1) as f64;
    let var_b =
        group_b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (group_b.len() - 1) as f64;

    // Pooled standard deviation
    let na = group_a.len() as f64;
    let nb = group_b.len() as f64;
    let pooled_var = ((na - 1.0) * var_a + (nb - 1.0) * var_b) / (na + nb - 2.0);
    let pooled_sd = pooled_var.sqrt();

    if pooled_sd < f64::EPSILON {
        0.0
    } else {
        (mean_a - mean_b) / pooled_sd
    }
}

/// Mann-Whitney U test for comparing two independent groups.
///
/// Non-parametric test that doesn't assume normal distributions.
/// Returns (U statistic, approximate p-value via normal approximation).
pub fn mann_whitney_u(a: &[f64], b: &[f64]) -> (f64, f64) {
    if a.is_empty() || b.is_empty() {
        return (0.0, 1.0);
    }

    let na = a.len();
    let nb = b.len();

    // Combine and rank
    let mut combined: Vec<(f64, bool)> = a
        .iter()
        .map(|&v| (v, true))
        .chain(b.iter().map(|&v| (v, false)))
        .collect();
    combined.sort_by(|x, y| x.0.partial_cmp(&y.0).unwrap_or(std::cmp::Ordering::Equal));

    // Assign ranks (handle ties with average rank)
    let n = combined.len();
    let mut ranks = vec![0.0; n];
    let mut i = 0;
    while i < n {
        let mut j = i;
        while j < n && (combined[j].0 - combined[i].0).abs() < f64::EPSILON {
            j += 1;
        }
        let avg_rank = (i + 1..=j).map(|r| r as f64).sum::<f64>() / (j - i) as f64;
        for rank in ranks.iter_mut().take(j).skip(i) {
            *rank = avg_rank;
        }
        i = j;
    }

    // Sum ranks for group A
    let rank_sum_a: f64 = combined
        .iter()
        .zip(ranks.iter())
        .filter(|(item, _)| item.1)
        .map(|(_, &rank)| rank)
        .sum();

    let u_a = rank_sum_a - (na * (na + 1)) as f64 / 2.0;
    let u_b = (na * nb) as f64 - u_a;
    let u = u_a.min(u_b);

    // Normal approximation for p-value (valid for n > 20)
    let mean_u = (na * nb) as f64 / 2.0;
    let std_u = ((na * nb * (na + nb + 1)) as f64 / 12.0).sqrt();

    let p_value = if std_u < f64::EPSILON {
        1.0
    } else {
        let z = (u - mean_u).abs() / std_u;
        // Two-tailed p-value using standard normal approximation
        2.0 * standard_normal_cdf(-z)
    };

    (u, p_value)
}

/// Standard normal CDF approximation (Abramowitz & Stegun).
fn standard_normal_cdf(z: f64) -> f64 {
    if z < -8.0 {
        return 0.0;
    }
    if z > 8.0 {
        return 1.0;
    }

    let t = 1.0 / (1.0 + 0.2316419 * z.abs());
    let d = 0.3989422804014327; // 1/sqrt(2*pi)
    let p = d * (-z * z / 2.0).exp();
    let c = t
        * (0.319381530
            + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))));

    if z >= 0.0 {
        1.0 - p * c
    } else {
        p * c
    }
}

/// Aggregate multiple security reports (from repeated runs) into a multi-run report.
pub fn aggregate_runs(runs: &[SecurityReport]) -> MultiRunReport {
    if runs.is_empty() {
        return MultiRunReport {
            agent: String::new(),
            run_count: 0,
            probe_stats: Vec::new(),
            aggregate: AggregateStats {
                score: descriptive_stats(&[]),
                overall_pass_rate: descriptive_stats(&[]),
                total_duration: descriptive_stats(&[]),
                category_pass_rates: Vec::new(),
                confidence_interval_95: (0.0, 0.0),
            },
            generated_at: chrono::Utc::now().to_rfc3339(),
        };
    }

    let agent = runs[0].agent.clone();
    let run_count = runs.len();

    // Collect all unique probe names across runs
    let mut probe_names: Vec<String> = Vec::new();
    for run in runs {
        for result in &run.results {
            if !probe_names.contains(&result.probe_name) {
                probe_names.push(result.probe_name.clone());
            }
        }
    }
    probe_names.sort();

    // Per-probe stats
    let mut probe_stats = Vec::new();
    for name in &probe_names {
        let matching: Vec<_> = runs
            .iter()
            .flat_map(|run| run.results.iter())
            .filter(|r| r.probe_name == *name)
            .collect();

        if matching.is_empty() {
            continue;
        }

        let category = format!("{:?}", matching[0].category);
        let n = matching.len();
        let pass_count = matching
            .iter()
            .filter(|r| r.verdict == Verdict::Pass)
            .count();
        let fail_count = matching
            .iter()
            .filter(|r| r.verdict == Verdict::Fail)
            .count();
        let error_count = matching
            .iter()
            .filter(|r| r.verdict == Verdict::Error)
            .count();

        let durations: Vec<f64> = matching.iter().map(|r| r.duration_ms as f64).collect();
        let output_lengths: Vec<f64> = matching.iter().map(|r| r.output_length as f64).collect();
        let verdicts: Vec<Verdict> = matching.iter().map(|r| r.verdict).collect();

        probe_stats.push(ProbeStats {
            probe_name: name.clone(),
            category,
            runs: n,
            pass_rate: pass_count as f64 / n as f64,
            fail_rate: fail_count as f64 / n as f64,
            error_rate: error_count as f64 / n as f64,
            duration: descriptive_stats(&durations),
            output_length: descriptive_stats(&output_lengths),
            verdict_stability: verdict_stability(&verdicts),
        });
    }

    // Per-run aggregate scores
    let scores: Vec<f64> = runs.iter().map(|r| r.score as f64).collect();
    let pass_rates: Vec<f64> = runs
        .iter()
        .map(|r| {
            if r.results.is_empty() {
                0.0
            } else {
                r.results
                    .iter()
                    .filter(|res| res.verdict == Verdict::Pass)
                    .count() as f64
                    / r.results.len() as f64
            }
        })
        .collect();
    let total_durations: Vec<f64> = runs
        .iter()
        .map(|r| r.results.iter().map(|res| res.duration_ms as f64).sum())
        .collect();

    // Per-category pass rates across runs
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
        let per_run_rates: Vec<f64> = runs
            .iter()
            .map(|run| {
                let cat_results: Vec<_> =
                    run.results.iter().filter(|r| r.category == *cat).collect();
                if cat_results.is_empty() {
                    return f64::NAN; // skip this run for this category
                }
                cat_results
                    .iter()
                    .filter(|r| r.verdict == Verdict::Pass)
                    .count() as f64
                    / cat_results.len() as f64
            })
            .filter(|r| !r.is_nan())
            .collect();

        if !per_run_rates.is_empty() {
            category_pass_rates.push(CategoryStats {
                category: format!("{cat:?}"),
                pass_rate: descriptive_stats(&per_run_rates),
            });
        }
    }

    let ci_95 = confidence_interval(&scores, 0.95);

    MultiRunReport {
        agent,
        run_count,
        probe_stats,
        aggregate: AggregateStats {
            score: descriptive_stats(&scores),
            overall_pass_rate: descriptive_stats(&pass_rates),
            total_duration: descriptive_stats(&total_durations),
            category_pass_rates,
            confidence_interval_95: ci_95,
        },
        generated_at: chrono::Utc::now().to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::{compute_report, ProbeResult};
    use crate::testcase::{AttackCategory, Severity};

    #[test]
    fn descriptive_stats_basic() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let stats = descriptive_stats(&data);
        assert_eq!(stats.count, 5);
        assert!((stats.mean - 3.0).abs() < f64::EPSILON);
        assert!((stats.median - 3.0).abs() < f64::EPSILON);
        assert_eq!(stats.min, 1.0);
        assert_eq!(stats.max, 5.0);
        assert!(stats.std_dev > 0.0);
    }

    #[test]
    fn descriptive_stats_single_value() {
        let data = vec![42.0];
        let stats = descriptive_stats(&data);
        assert_eq!(stats.count, 1);
        assert!((stats.mean - 42.0).abs() < f64::EPSILON);
        assert!((stats.std_dev).abs() < f64::EPSILON);
    }

    #[test]
    fn descriptive_stats_empty() {
        let stats = descriptive_stats(&[]);
        assert_eq!(stats.count, 0);
        assert!((stats.mean).abs() < f64::EPSILON);
    }

    #[test]
    fn confidence_interval_basic() {
        let data = vec![10.0, 12.0, 11.0, 13.0, 9.0];
        let (lo, hi) = confidence_interval(&data, 0.95);
        let mean = data.iter().sum::<f64>() / data.len() as f64;
        assert!(lo < mean);
        assert!(hi > mean);
        assert!(lo < hi);
    }

    #[test]
    fn confidence_interval_single_value() {
        let (lo, hi) = confidence_interval(&[42.0], 0.95);
        assert!((lo - 42.0).abs() < f64::EPSILON);
        assert!((hi - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn verdict_stability_all_same() {
        let verdicts = vec![Verdict::Pass, Verdict::Pass, Verdict::Pass];
        assert!((verdict_stability(&verdicts) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn verdict_stability_mixed() {
        let verdicts = vec![Verdict::Pass, Verdict::Fail, Verdict::Pass, Verdict::Fail];
        assert!((verdict_stability(&verdicts) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn cohens_d_same_groups() {
        let a = vec![10.0, 11.0, 12.0];
        let b = vec![10.0, 11.0, 12.0];
        assert!(cohens_d(&a, &b).abs() < f64::EPSILON);
    }

    #[test]
    fn cohens_d_different_groups() {
        let a = vec![10.0, 11.0, 12.0, 13.0, 14.0];
        let b = vec![20.0, 21.0, 22.0, 23.0, 24.0];
        let d = cohens_d(&a, &b);
        assert!(d < -5.0); // Large effect
    }

    #[test]
    fn mann_whitney_u_same_groups() {
        let a = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let b = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let (_, p) = mann_whitney_u(&a, &b);
        assert!(p > 0.05); // Not significantly different
    }

    #[test]
    fn mann_whitney_u_different_groups() {
        let a: Vec<f64> = (1..=20).map(|x| x as f64).collect();
        let b: Vec<f64> = (50..=69).map(|x| x as f64).collect();
        let (_, p) = mann_whitney_u(&a, &b);
        assert!(p < 0.05); // Significantly different
    }

    fn make_report(agent: &str, pass_probes: &[bool]) -> SecurityReport {
        let results: Vec<ProbeResult> = pass_probes
            .iter()
            .enumerate()
            .map(|(i, &passed)| ProbeResult {
                probe_name: format!("probe-{i}"),
                category: AttackCategory::PromptInjection,
                severity: Severity::High,
                verdict: if passed { Verdict::Pass } else { Verdict::Fail },
                findings: vec![],
                agent: agent.into(),
                duration_ms: 1000 + (i as u64 * 100),
                timestamp: chrono::Utc::now(),
                output_length: 500 + i * 50,
                agent_output: None,
            })
            .collect();
        compute_report(agent, results)
    }

    #[test]
    fn aggregate_runs_basic() {
        let runs = vec![
            make_report("test", &[true, true, false]),
            make_report("test", &[true, false, false]),
            make_report("test", &[true, true, true]),
        ];

        let report = aggregate_runs(&runs);
        assert_eq!(report.run_count, 3);
        assert_eq!(report.agent, "test");
        assert_eq!(report.probe_stats.len(), 3);

        // probe-0 passed in all 3 runs
        let p0 = report
            .probe_stats
            .iter()
            .find(|p| p.probe_name == "probe-0")
            .unwrap();
        assert!((p0.pass_rate - 1.0).abs() < f64::EPSILON);
        assert!((p0.verdict_stability - 1.0).abs() < f64::EPSILON);

        // probe-2 had mixed results
        let p2 = report
            .probe_stats
            .iter()
            .find(|p| p.probe_name == "probe-2")
            .unwrap();
        assert!(p2.verdict_stability < 1.0);

        // Confidence interval should contain the mean score
        let mean_score = report.aggregate.score.mean;
        assert!(report.aggregate.confidence_interval_95.0 <= mean_score);
        assert!(report.aggregate.confidence_interval_95.1 >= mean_score);
    }

    #[test]
    fn aggregate_empty_runs() {
        let report = aggregate_runs(&[]);
        assert_eq!(report.run_count, 0);
        assert!(report.probe_stats.is_empty());
    }

    #[test]
    fn standard_normal_cdf_values() {
        // CDF(0) should be ~0.5
        let val = standard_normal_cdf(0.0);
        assert!((val - 0.5).abs() < 0.001);

        // CDF(-inf) should be ~0
        let val = standard_normal_cdf(-10.0);
        assert!(val < 0.001);

        // CDF(inf) should be ~1
        let val = standard_normal_cdf(10.0);
        assert!(val > 0.999);
    }
}
