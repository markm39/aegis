//! Fallback `ProcessBackend` with no OS-level sandboxing.

use aegis_types::{AegisConfig, AegisError};

use crate::backend::SandboxBackend;

/// Default deny-list patterns for sensitive environment variables.
const DEFAULT_ENV_DENY_PATTERNS: &[&str] = &[
    "*_KEY",
    "*_SECRET",
    "*_TOKEN",
    "*_PASSWORD",
    "*_CREDENTIAL*",
    "AWS_*",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AZURE_*_KEY",
    "DATABASE_URL",
    "DB_PASSWORD",
    "PRIVATE_KEY",
    "SSH_*_KEY",
];

/// Filter sensitive environment variables before process spawn.
///
/// Removes variables matching common secret patterns from the inherited
/// environment. Uses glob-style patterns for flexibility.
///
/// If `deny_patterns` is empty, the built-in default patterns are used.
pub fn sanitize_env(env: &[(String, String)], deny_patterns: &[String]) -> Vec<(String, String)> {
    let patterns: Vec<String> = if deny_patterns.is_empty() {
        DEFAULT_ENV_DENY_PATTERNS
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        deny_patterns.to_vec()
    };

    env.iter()
        .filter(|(key, _)| !matches_any_pattern(key, &patterns))
        .cloned()
        .collect()
}

/// Check if a key matches any of the given glob patterns.
fn matches_any_pattern(key: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pat| glob_match(key, pat))
}

/// Simple glob matching: `*` matches any sequence of characters, `?` matches
/// exactly one character. Matching is case-insensitive for env var names.
fn glob_match(key: &str, pattern: &str) -> bool {
    let key_upper = key.to_uppercase();
    let pat_upper = pattern.to_uppercase();
    glob_match_bytes(key_upper.as_bytes(), pat_upper.as_bytes())
}

/// Recursive byte-level glob matcher.
fn glob_match_bytes(text: &[u8], pattern: &[u8]) -> bool {
    let mut t = 0;
    let mut p = 0;
    let mut star_p = usize::MAX;
    let mut star_t = 0;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            t += 1;
            p += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star_p = p;
            star_t = t;
            p += 1;
        } else if star_p != usize::MAX {
            p = star_p + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }

    p == pattern.len()
}

/// Fallback backend with no OS-level sandboxing.
///
/// Runs commands directly as child processes. Useful for platforms
/// where Seatbelt or other isolation mechanisms are unavailable.
pub struct ProcessBackend;

impl SandboxBackend for ProcessBackend {
    fn prepare(&self, config: &AegisConfig) -> Result<(), AegisError> {
        // Ensure the sandbox directory exists
        std::fs::create_dir_all(&config.sandbox_dir).map_err(|e| {
            AegisError::SandboxError(format!(
                "failed to create sandbox dir {}: {e}",
                config.sandbox_dir.display()
            ))
        })?;

        tracing::debug!(
            sandbox_dir = %config.sandbox_dir.display(),
            "process backend prepared (no OS-level isolation)"
        );

        Ok(())
    }

    fn exec(
        &self,
        command: &str,
        args: &[String],
        config: &AegisConfig,
    ) -> Result<std::process::ExitStatus, AegisError> {
        tracing::info!(
            command,
            sandbox_dir = %config.sandbox_dir.display(),
            "running command without OS-level sandboxing"
        );

        let status = std::process::Command::new(command)
            .args(args)
            .current_dir(&config.sandbox_dir)
            .status()
            .map_err(|e| {
                AegisError::SandboxError(format!("failed to run command '{command}': {e}"))
            })?;

        Ok(status)
    }

    fn spawn_and_wait(
        &self,
        command: &str,
        args: &[String],
        config: &AegisConfig,
        env: &[(&str, &str)],
    ) -> Result<(u32, std::process::ExitStatus), AegisError> {
        tracing::info!(
            command,
            sandbox_dir = %config.sandbox_dir.display(),
            "spawning command without OS-level sandboxing"
        );

        let mut cmd = std::process::Command::new(command);
        cmd.args(args).current_dir(&config.sandbox_dir);
        for (key, val) in env {
            cmd.env(key, val);
        }

        let mut child = cmd.spawn().map_err(|e| {
            AegisError::SandboxError(format!("failed to spawn command '{command}': {e}"))
        })?;

        let pid = child.id();

        let status = child.wait().map_err(|e| {
            AegisError::SandboxError(format!("failed to wait for command '{command}': {e}"))
        })?;

        Ok((pid, status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::IsolationConfig;

    // ---- env sanitization tests ----

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn sanitize_env_strips_aws_vars() {
        let input = env(&[
            ("AWS_ACCESS_KEY_ID", "AKIA1234"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("HOME", "/home/user"),
        ]);
        let result = sanitize_env(&input, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "HOME");
    }

    #[test]
    fn sanitize_env_strips_github_token() {
        let input = env(&[("GITHUB_TOKEN", "ghp_abc"), ("PATH", "/usr/bin")]);
        let result = sanitize_env(&input, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "PATH");
    }

    #[test]
    fn sanitize_env_strips_key_suffix_pattern() {
        let input = env(&[
            ("API_KEY", "abc"),
            ("SOME_SECRET", "xyz"),
            ("MY_TOKEN", "tok"),
            ("NORMAL_VAR", "ok"),
        ]);
        let result = sanitize_env(&input, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "NORMAL_VAR");
    }

    #[test]
    fn sanitize_env_custom_patterns() {
        let input = env(&[
            ("CUSTOM_CRED", "val"),
            ("NORMAL", "ok"),
            ("MY_SPECIAL", "secret"),
        ]);
        let patterns = vec!["CUSTOM_*".into(), "MY_SPECIAL".into()];
        let result = sanitize_env(&input, &patterns);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "NORMAL");
    }

    #[test]
    fn sanitize_env_preserves_non_sensitive() {
        let input = env(&[
            ("HOME", "/home/user"),
            ("PATH", "/usr/bin"),
            ("SHELL", "/bin/bash"),
            ("TERM", "xterm"),
        ]);
        let result = sanitize_env(&input, &[]);
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn sanitize_env_empty_input() {
        let result = sanitize_env(&[], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn glob_match_star_prefix() {
        assert!(glob_match("API_KEY", "*_KEY"));
        assert!(glob_match("MY_KEY", "*_KEY"));
        assert!(!glob_match("KEYRING", "*_KEY"));
    }

    #[test]
    fn glob_match_star_suffix() {
        assert!(glob_match("AWS_ACCESS_KEY_ID", "AWS_*"));
        assert!(glob_match("AWS_SECRET", "AWS_*"));
        assert!(!glob_match("NOTAWS_FOO", "AWS_*"));
    }

    #[test]
    fn glob_match_question_mark() {
        assert!(glob_match("AB", "A?"));
        assert!(!glob_match("ABC", "A?"));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("GITHUB_TOKEN", "GITHUB_TOKEN"));
        assert!(!glob_match("GITHUB_TOKENS", "GITHUB_TOKEN"));
    }

    #[test]
    fn glob_match_case_insensitive() {
        assert!(glob_match("github_token", "GITHUB_TOKEN"));
        assert!(glob_match("Api_Key", "*_KEY"));
    }

    // ---- original process backend tests ----

    #[test]
    fn process_backend_runs_command_successfully() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config =
            crate::test_helpers::test_config(dir.path().to_path_buf(), IsolationConfig::Process);

        let backend = ProcessBackend;
        backend.prepare(&config).expect("prepare failed");

        let status = backend
            .exec("echo", &["hello".to_string()], &config)
            .expect("failed to run echo");

        assert!(status.success());
    }

    #[test]
    fn process_backend_spawn_and_wait_returns_real_pid() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config =
            crate::test_helpers::test_config(dir.path().to_path_buf(), IsolationConfig::Process);

        let backend = ProcessBackend;
        backend.prepare(&config).expect("prepare failed");

        let (pid, status) = backend
            .spawn_and_wait("echo", &["hello".to_string()], &config, &[])
            .expect("spawn_and_wait failed");

        assert!(pid > 0, "should return a real PID, got {pid}");
        assert!(status.success());
    }

    #[test]
    fn process_backend_spawn_and_wait_passes_env() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let config =
            crate::test_helpers::test_config(dir.path().to_path_buf(), IsolationConfig::Process);
        let output_path = dir.path().join("env_output.txt");

        let backend = ProcessBackend;
        backend.prepare(&config).expect("prepare failed");

        let output_str = output_path.display().to_string();
        let script = format!("printenv AEGIS_TEST_VAR > {output_str}");

        let (pid, status) = backend
            .spawn_and_wait(
                "sh",
                &["-c".to_string(), script],
                &config,
                &[("AEGIS_TEST_VAR", "test_value_42")],
            )
            .expect("spawn_and_wait failed");

        assert!(pid > 0);
        assert!(status.success());

        let content = std::fs::read_to_string(&output_path).expect("failed to read output");
        assert_eq!(content.trim(), "test_value_42");
    }

    #[test]
    fn process_backend_prepare_creates_sandbox_dir() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let sandbox_dir = dir.path().join("nested").join("sandbox");
        let config =
            crate::test_helpers::test_config(sandbox_dir.clone(), IsolationConfig::Process);

        let backend = ProcessBackend;
        backend.prepare(&config).expect("prepare failed");

        assert!(sandbox_dir.exists());
    }
}
