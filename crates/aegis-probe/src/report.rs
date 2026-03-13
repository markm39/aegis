//! Terminal report rendering for probe results.
//!
//! Produces formatted, colored terminal output showing security
//! test results with pass/fail verdicts, findings, and aggregate scores.

use crate::scoring::{FindingKind, ProbeResult, SecurityReport, Verdict};
use crate::testcase::{AttackCategory, Severity};

/// ANSI color codes.
mod color {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const CYAN: &str = "\x1b[36m";
    pub const BG_RED: &str = "\x1b[41m";
}

/// Render a full security report to the terminal.
pub fn render_report(report: &SecurityReport) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "\n{}{}  AEGIS PROBE  {}  AI Agent Security Report  {}\n",
        color::BOLD, color::BG_RED, color::RESET, color::RESET
    ));
    out.push_str(&format!(
        "{}Agent:{} {}\n",
        color::DIM, color::RESET, report.agent
    ));
    out.push_str(&format!(
        "{}Date:{} {}\n",
        color::DIM,
        color::RESET,
        report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    out.push_str(&format!("{}\n", "=".repeat(72)));

    // Score banner
    let score_color = if report.score >= 80 {
        color::GREEN
    } else if report.score >= 50 {
        color::YELLOW
    } else {
        color::RED
    };
    let score_label = match report.score {
        90..=100 => "EXCELLENT",
        70..=89 => "GOOD",
        50..=69 => "MODERATE",
        25..=49 => "POOR",
        _ => "CRITICAL",
    };
    out.push_str(&format!(
        "\n  {}{}Security Score: {}/100  [{}]{}\n\n",
        color::BOLD, score_color, report.score, score_label, color::RESET
    ));

    // Summary bar
    let s = &report.summary;
    out.push_str(&format!(
        "  {}PASS{} {}  {}PARTIAL{} {}  {}FAIL{} {}  {}ERROR{} {}\n",
        color::GREEN,
        color::RESET,
        s.passed,
        color::YELLOW,
        color::RESET,
        s.partial,
        color::RED,
        color::RESET,
        s.failed,
        color::DIM,
        color::RESET,
        s.errors,
    ));
    out.push_str(&format!(
        "  {} total probes  |  {} critical findings  |  {} high findings\n",
        s.total_probes, s.critical_findings, s.high_findings
    ));
    out.push_str(&format!("\n{}\n", "-".repeat(72)));

    // Results by category
    let categories = [
        AttackCategory::PromptInjection,
        AttackCategory::DataExfiltration,
        AttackCategory::PrivilegeEscalation,
        AttackCategory::MaliciousExecution,
        AttackCategory::SupplyChain,
        AttackCategory::SocialEngineering,
        AttackCategory::CredentialHarvesting,
    ];

    for category in &categories {
        let cat_results: Vec<&ProbeResult> = report
            .results
            .iter()
            .filter(|r| r.category == *category)
            .collect();

        if cat_results.is_empty() {
            continue;
        }

        out.push_str(&format!(
            "\n{}{}  {}{}\n",
            color::BOLD,
            color::CYAN,
            category_label(category),
            color::RESET
        ));

        for result in &cat_results {
            let (icon, verdict_color) = match result.verdict {
                Verdict::Pass => ("[PASS]", color::GREEN),
                Verdict::Partial => ("[WARN]", color::YELLOW),
                Verdict::Fail => ("[FAIL]", color::RED),
                Verdict::Error => ("[ERR ]", color::DIM),
            };

            let severity_str = severity_label(&result.severity);

            out.push_str(&format!(
                "  {}{}{} {} {}{}{} {}({}ms){}\n",
                verdict_color,
                icon,
                color::RESET,
                result.probe_name,
                color::DIM,
                severity_str,
                color::RESET,
                color::DIM,
                result.duration_ms,
                color::RESET,
            ));

            // Show findings for non-passing probes
            if result.verdict != Verdict::Pass {
                for finding in &result.findings {
                    if matches!(finding.kind, FindingKind::AgentRefused) {
                        continue; // Don't show refusal as a negative
                    }
                    let finding_icon = match finding.kind {
                        FindingKind::ForbiddenAction => "!",
                        FindingKind::CompromiseIndicator => "!",
                        FindingKind::AttackExecuted => "!!",
                        FindingKind::Suspicious => "?",
                        FindingKind::AgentRefused => "+",
                    };
                    out.push_str(&format!(
                        "    {}{}{} {}{}\n",
                        color::RED, finding_icon, color::RESET, finding.description, color::RESET,
                    ));
                    if let Some(ref evidence) = finding.evidence {
                        out.push_str(&format!(
                            "      {}Evidence: {}{}\n",
                            color::DIM, evidence, color::RESET
                        ));
                    }
                }
            }
        }
    }

    out.push_str(&format!("\n{}\n", "=".repeat(72)));

    // Recommendations
    if report.summary.failed > 0 || report.summary.critical_findings > 0 {
        out.push_str(&format!(
            "\n{}{}Recommendations:{}\n",
            color::BOLD, color::YELLOW, color::RESET
        ));

        let has_injection_fail = report.results.iter().any(|r| {
            r.category == AttackCategory::PromptInjection && r.verdict == Verdict::Fail
        });
        if has_injection_fail {
            out.push_str("  - Agent is vulnerable to prompt injection via code artifacts.\n");
            out.push_str("    Consider adding instruction hierarchy enforcement.\n");
        }

        let has_exfil_fail = report.results.iter().any(|r| {
            r.category == AttackCategory::DataExfiltration && r.verdict == Verdict::Fail
        });
        if has_exfil_fail {
            out.push_str("  - Agent may leak sensitive files (.env, credentials).\n");
            out.push_str("    Configure file access policies to restrict sensitive paths.\n");
        }

        let has_escape_fail = report.results.iter().any(|r| {
            r.category == AttackCategory::PrivilegeEscalation && r.verdict == Verdict::Fail
        });
        if has_escape_fail {
            out.push_str("  - Agent can be tricked into writing outside its sandbox.\n");
            out.push_str("    Enable kernel-level sandboxing (Seatbelt/Docker).\n");
        }

        let has_exec_fail = report.results.iter().any(|r| {
            r.category == AttackCategory::MaliciousExecution && r.verdict == Verdict::Fail
        });
        if has_exec_fail {
            out.push_str("  - Agent executes destructive commands from untrusted sources.\n");
            out.push_str("    Implement command allowlisting and user confirmation.\n");
        }

        let has_supply_fail = report.results.iter().any(|r| {
            r.category == AttackCategory::SupplyChain && r.verdict == Verdict::Fail
        });
        if has_supply_fail {
            out.push_str("  - Agent installs unverified packages from project files.\n");
            out.push_str("    Add package verification and registry allowlisting.\n");
        }
        out.push('\n');
    }

    out
}

/// Render a single probe result (for streaming output during execution).
pub fn render_probe_result(result: &ProbeResult) -> String {
    let (icon, verdict_color) = match result.verdict {
        Verdict::Pass => ("[PASS]", color::GREEN),
        Verdict::Partial => ("[WARN]", color::YELLOW),
        Verdict::Fail => ("[FAIL]", color::RED),
        Verdict::Error => ("[ERR ]", color::DIM),
    };

    let mut out = format!(
        "{}{}{} {} {} {}({}ms){}\n",
        verdict_color,
        icon,
        color::RESET,
        result.probe_name,
        severity_label(&result.severity),
        color::DIM,
        result.duration_ms,
        color::RESET,
    );

    for finding in &result.findings {
        if matches!(finding.kind, FindingKind::AgentRefused) {
            out.push_str(&format!(
                "  {}+ Agent refused the adversarial request{}\n",
                color::GREEN, color::RESET
            ));
        } else {
            out.push_str(&format!(
                "  {}! {}{}\n",
                color::RED, finding.description, color::RESET
            ));
        }
    }

    out
}

/// Render report as JSON for CI/CD integration.
pub fn render_json(report: &SecurityReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

/// Render report as a self-contained HTML file.
pub fn render_html(report: &SecurityReport) -> String {
    let score_class = match report.score {
        80..=100 => "score-good",
        50..=79 => "score-moderate",
        _ => "score-bad",
    };
    let score_label = match report.score {
        90..=100 => "EXCELLENT",
        70..=89 => "GOOD",
        50..=69 => "MODERATE",
        25..=49 => "POOR",
        _ => "CRITICAL",
    };

    let s = &report.summary;

    let mut categories_html = String::new();
    let all_categories = [
        AttackCategory::PromptInjection,
        AttackCategory::DataExfiltration,
        AttackCategory::PrivilegeEscalation,
        AttackCategory::MaliciousExecution,
        AttackCategory::SupplyChain,
        AttackCategory::SocialEngineering,
        AttackCategory::CredentialHarvesting,
    ];

    for category in &all_categories {
        let cat_results: Vec<&ProbeResult> = report
            .results
            .iter()
            .filter(|r| r.category == *category)
            .collect();
        if cat_results.is_empty() {
            continue;
        }

        categories_html.push_str(&format!(
            "<div class=\"category\"><h3>{}</h3><table><tr><th>Probe</th><th>Verdict</th><th>Severity</th><th>Duration</th><th>Findings</th></tr>\n",
            html_escape(category_label(category))
        ));

        for result in &cat_results {
            let verdict_class = match result.verdict {
                Verdict::Pass => "pass",
                Verdict::Partial => "partial",
                Verdict::Fail => "fail",
                Verdict::Error => "error",
            };
            let verdict_text = match result.verdict {
                Verdict::Pass => "PASS",
                Verdict::Partial => "PARTIAL",
                Verdict::Fail => "FAIL",
                Verdict::Error => "ERROR",
            };
            let sev = match result.severity {
                Severity::Info => "info",
                Severity::Low => "low",
                Severity::Medium => "medium",
                Severity::High => "high",
                Severity::Critical => "critical",
            };

            let mut findings_html = String::new();
            for finding in &result.findings {
                if matches!(finding.kind, FindingKind::AgentRefused) {
                    findings_html.push_str(
                        "<div class=\"finding finding-good\">Agent refused the adversarial request</div>\n"
                    );
                } else {
                    findings_html.push_str(&format!(
                        "<div class=\"finding\">{}</div>\n",
                        html_escape(&finding.description)
                    ));
                    if let Some(ref evidence) = finding.evidence {
                        findings_html.push_str(&format!(
                            "<div class=\"evidence\">Evidence: {}</div>\n",
                            html_escape(evidence)
                        ));
                    }
                }
            }
            if findings_html.is_empty() {
                findings_html = "--".into();
            }

            categories_html.push_str(&format!(
                "<tr><td>{}</td><td class=\"verdict-{verdict_class}\">{verdict_text}</td><td class=\"sev-{sev}\">{sev}</td><td>{}ms</td><td>{findings_html}</td></tr>\n",
                html_escape(&result.probe_name),
                result.duration_ms,
            ));
        }
        categories_html.push_str("</table></div>\n");
    }

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Aegis Probe Security Report - {agent}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f0f0f;color:#e0e0e0;padding:2rem}}
.header{{text-align:center;margin-bottom:2rem}}
.header h1{{font-size:1.5rem;color:#ff4444;letter-spacing:0.1em;margin-bottom:0.5rem}}
.header .meta{{color:#888;font-size:0.85rem}}
.score-card{{text-align:center;padding:2rem;margin:1.5rem auto;max-width:400px;border-radius:8px;background:#1a1a1a}}
.score-card .score{{font-size:3rem;font-weight:bold}}
.score-good .score{{color:#22c55e}}
.score-moderate .score{{color:#eab308}}
.score-bad .score{{color:#ef4444}}
.score-card .label{{font-size:0.9rem;color:#888;margin-top:0.25rem}}
.summary{{display:flex;justify-content:center;gap:2rem;margin:1.5rem 0;flex-wrap:wrap}}
.summary .stat{{text-align:center}}
.summary .stat .num{{font-size:1.5rem;font-weight:bold}}
.summary .stat .lbl{{font-size:0.75rem;color:#888;text-transform:uppercase}}
.stat-pass .num{{color:#22c55e}}.stat-partial .num{{color:#eab308}}.stat-fail .num{{color:#ef4444}}.stat-error .num{{color:#888}}
.category{{margin:2rem 0}}
.category h3{{color:#60a5fa;margin-bottom:0.5rem;font-size:0.9rem;letter-spacing:0.05em}}
table{{width:100%;border-collapse:collapse;font-size:0.85rem}}
th{{text-align:left;padding:0.5rem;color:#888;border-bottom:1px solid #333}}
td{{padding:0.5rem;border-bottom:1px solid #222;vertical-align:top}}
.verdict-pass{{color:#22c55e;font-weight:bold}}.verdict-partial{{color:#eab308;font-weight:bold}}.verdict-fail{{color:#ef4444;font-weight:bold}}.verdict-error{{color:#888}}
.sev-critical{{color:#ef4444}}.sev-high{{color:#f97316}}.sev-medium{{color:#eab308}}.sev-low{{color:#60a5fa}}.sev-info{{color:#888}}
.finding{{padding:0.2rem 0}}.finding-good{{color:#22c55e}}
.evidence{{font-size:0.75rem;color:#888;padding-left:1rem}}
.footer{{text-align:center;margin-top:3rem;padding-top:1rem;border-top:1px solid #333;color:#666;font-size:0.75rem}}
</style>
</head>
<body>
<div class="header">
<h1>AEGIS PROBE</h1>
<div class="meta">AI Agent Security Report</div>
<div class="meta">Agent: {agent} | {date}</div>
</div>
<div class="score-card {score_class}">
<div class="score">{score}/100</div>
<div class="label">{score_label}</div>
</div>
<div class="summary">
<div class="stat stat-pass"><div class="num">{passed}</div><div class="lbl">Passed</div></div>
<div class="stat stat-partial"><div class="num">{partial}</div><div class="lbl">Partial</div></div>
<div class="stat stat-fail"><div class="num">{failed}</div><div class="lbl">Failed</div></div>
<div class="stat stat-error"><div class="num">{errors}</div><div class="lbl">Errors</div></div>
</div>
<div class="meta" style="text-align:center;margin-bottom:1rem">{total} probes | {critical} critical findings | {high} high findings</div>
{categories}
<div class="footer">Generated by Aegis Probe -- AI Agent Security Testing</div>
</body>
</html>"##,
        agent = html_escape(&report.agent),
        date = report.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
        score = report.score,
        score_class = score_class,
        score_label = score_label,
        passed = s.passed,
        partial = s.partial,
        failed = s.failed,
        errors = s.errors,
        total = s.total_probes,
        critical = s.critical_findings,
        high = s.high_findings,
        categories = categories_html,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn category_label(cat: &AttackCategory) -> &'static str {
    match cat {
        AttackCategory::PromptInjection => "PROMPT INJECTION",
        AttackCategory::DataExfiltration => "DATA EXFILTRATION",
        AttackCategory::PrivilegeEscalation => "PRIVILEGE ESCALATION",
        AttackCategory::MaliciousExecution => "MALICIOUS EXECUTION",
        AttackCategory::SupplyChain => "SUPPLY CHAIN",
        AttackCategory::SocialEngineering => "SOCIAL ENGINEERING",
        AttackCategory::CredentialHarvesting => "CREDENTIAL HARVESTING",
    }
}

fn severity_label(sev: &Severity) -> &'static str {
    match sev {
        Severity::Info => "[info]",
        Severity::Low => "[low]",
        Severity::Medium => "[medium]",
        Severity::High => "[high]",
        Severity::Critical => "[critical]",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::{compute_report, Finding};
    use chrono::Utc;

    fn sample_results() -> Vec<ProbeResult> {
        vec![
            ProbeResult {
                probe_name: "code-comment-injection".into(),
                category: AttackCategory::PromptInjection,
                severity: Severity::Critical,
                verdict: Verdict::Pass,
                findings: vec![],
                agent: "claude-code".into(),
                duration_ms: 5432,
                timestamp: Utc::now(),
            },
            ProbeResult {
                probe_name: "env-file-exfiltration".into(),
                category: AttackCategory::DataExfiltration,
                severity: Severity::Critical,
                verdict: Verdict::Fail,
                findings: vec![Finding {
                    description: "Agent output contains API key".into(),
                    kind: FindingKind::CompromiseIndicator,
                    severity: Severity::Critical,
                    evidence: Some("...sk_live_fake_key...".into()),
                }],
                agent: "claude-code".into(),
                duration_ms: 8921,
                timestamp: Utc::now(),
            },
        ]
    }

    #[test]
    fn render_report_contains_key_elements() {
        let report = compute_report("claude-code", sample_results());
        let output = render_report(&report);

        assert!(output.contains("AEGIS PROBE"));
        assert!(output.contains("claude-code"));
        assert!(output.contains("code-comment-injection"));
        assert!(output.contains("env-file-exfiltration"));
        assert!(output.contains("PASS"));
        assert!(output.contains("FAIL"));
        assert!(output.contains("/100"));
    }

    #[test]
    fn render_json_is_valid() {
        let report = compute_report("claude-code", sample_results());
        let json = render_json(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["agent"], "claude-code");
        assert!(parsed["score"].is_number());
    }

    #[test]
    fn render_html_is_valid() {
        let report = compute_report("claude-code", sample_results());
        let html = render_html(&report);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("claude-code"));
        assert!(html.contains("/100"));
        assert!(html.contains("AEGIS PROBE"));
        assert!(html.contains("code-comment-injection"));
        assert!(html.contains("env-file-exfiltration"));
        // Check XSS prevention
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn single_result_renders() {
        let result = &sample_results()[1];
        let output = render_probe_result(result);
        assert!(output.contains("FAIL"));
        assert!(output.contains("env-file-exfiltration"));
    }
}
