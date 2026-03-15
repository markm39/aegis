//! Named probe profiles.
//!
//! Profiles are a thin convenience layer over probe tags so CI and CLI users
//! can select buyer-facing scenarios without memorizing tag combinations.

#[derive(Debug, Clone, Copy)]
pub struct ProbeProfile {
    pub name: &'static str,
    pub description: &'static str,
    pub tags: &'static [&'static str],
}

const PROFILES: &[ProbeProfile] = &[
    ProbeProfile {
        name: "ci-artifacts",
        description: "Poisoned CI artifacts such as SARIF, JUnit, SBOM, cache logs, and job summaries",
        tags: &["ci-artifact", "sarif", "junit", "sbom", "cache", "job-summary"],
    },
    ProbeProfile {
        name: "github-actions",
        description: "GitHub Actions runtime, OIDC, and workflow artifact abuse",
        tags: &["github-actions", "oidc", "job-summary", "token-theft", "ci-artifact"],
    },
    ProbeProfile {
        name: "azure-devops",
        description: "Azure Pipelines artifacts, Azure CLI tokens, and incident-driven credential theft",
        tags: &["azure", "azure-devops", "cloud", "ci-artifact", "token-theft"],
    },
    ProbeProfile {
        name: "package-publish",
        description: "Package publishing and dependency bootstrap abuse across npm, PyPI, Maven, Gradle, Docker, Cargo, Composer, and Ruby",
        tags: &[
            "supply-chain",
            "npm",
            "pypi",
            "maven",
            "gradle",
            "docker",
            "cargo",
            "composer",
            "gem",
        ],
    },
    ProbeProfile {
        name: "cloud-deploy",
        description: "Cloud deployment credentials, kubeconfig handling, and infrastructure secrets",
        tags: &["cloud", "aws", "gcp", "azure", "terraform", "kubeconfig", "docker"],
    },
    ProbeProfile {
        name: "credential-theft",
        description: "Token theft, support bundles, and credential harvesting workflows",
        tags: &[
            "credential-theft",
            "token-theft",
            "support-bundle",
            "diagnostics",
            "kubeconfig",
        ],
    },
];

pub fn known_profiles() -> &'static [ProbeProfile] {
    PROFILES
}

pub fn normalize_profiles(names: &[String]) -> Result<Vec<String>, String> {
    let mut normalized = names
        .iter()
        .map(|name| name.trim())
        .filter(|name| !name.is_empty())
        .map(|name| name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();

    let unknown = normalized
        .iter()
        .filter(|name| profile_by_name(name).is_none())
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(format!(
            "Unknown profile(s): {}. Valid profiles: {}",
            unknown.join(", "),
            known_profiles()
                .iter()
                .map(|profile| profile.name)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    Ok(normalized)
}

pub fn expand_profile_tags(names: &[String]) -> Result<Vec<String>, String> {
    let normalized = normalize_profiles(names)?;
    let mut tags = normalized
        .iter()
        .flat_map(|name| {
            profile_by_name(name)
                .into_iter()
                .flat_map(|profile| profile.tags.iter().copied())
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    tags.sort();
    tags.dedup();
    Ok(tags)
}

fn profile_by_name(name: &str) -> Option<&'static ProbeProfile> {
    known_profiles()
        .iter()
        .find(|profile| profile.name.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_profiles_rejects_unknown_values() {
        let err = normalize_profiles(&["unknown".into()]).unwrap_err();
        assert!(err.contains("Unknown profile"));
        assert!(err.contains("github-actions"));
    }

    #[test]
    fn expand_profile_tags_deduplicates_tags() {
        let tags = expand_profile_tags(&["github-actions".into(), "ci-artifacts".into()]).unwrap();
        assert!(tags.contains(&"ci-artifact".into()));
        assert!(tags.contains(&"job-summary".into()));
        assert_eq!(
            tags.iter()
                .filter(|tag| tag.as_str() == "ci-artifact")
                .count(),
            1
        );
    }
}
