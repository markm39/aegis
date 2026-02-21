//! Docker container sandbox backend.
//!
//! Runs commands inside hardened Docker containers with:
//! - All capabilities dropped (`--cap-drop=ALL`)
//! - No new privileges (`--security-opt=no-new-privileges`)
//! - Network deny by default (`--network=none`)
//! - Read-only root filesystem (`--read-only`)
//! - Size-limited tmpfs for `/tmp`
//! - PID, memory, and CPU limits
//! - Workspace mounted read-only by default

use aegis_types::{AegisConfig, AegisError, DockerSandboxConfig, IsolationConfig};
use std::process::Command;

use crate::backend::SandboxBackend;

/// Docker container sandbox backend.
///
/// Executes commands inside ephemeral Docker containers with
/// security-hardened defaults. The container is automatically removed
/// after execution (`--rm`).
pub struct DockerBackend;

impl DockerBackend {
    /// Create a new DockerBackend.
    pub fn new() -> Self {
        Self
    }

    /// Extract the DockerSandboxConfig from the AegisConfig isolation field.
    ///
    /// Falls back to default config if isolation is not Docker variant.
    fn docker_config(config: &AegisConfig) -> DockerSandboxConfig {
        match &config.isolation {
            IsolationConfig::Docker(cfg) => cfg.clone(),
            _ => DockerSandboxConfig::default(),
        }
    }

    /// Build the `docker run` command with all security flags.
    ///
    /// This is the core of the Docker backend. The command includes:
    /// - `--rm` for auto-cleanup
    /// - `--cap-drop=ALL` to drop all Linux capabilities
    /// - `--security-opt=no-new-privileges` to prevent privilege escalation
    /// - `--read-only` for read-only root filesystem
    /// - `--network=<mode>` for network isolation
    /// - `--tmpfs /tmp:size=<limit>` for writable temp space
    /// - `--pids-limit=<n>` to prevent fork bombs
    /// - `--memory=<limit>` for memory limits
    /// - `--cpus=<n>` for CPU limits
    /// - `-v workspace:/workspace:<ro|rw>` for workspace mount
    fn build_command(
        &self,
        user_command: &str,
        args: &[String],
        config: &AegisConfig,
        env: &[(&str, &str)],
    ) -> Result<Command, AegisError> {
        let docker_cfg = Self::docker_config(config);

        // Validate inputs before building the command
        validate_image_name(&docker_cfg.image)?;
        validate_workspace_path(&config.sandbox_dir.to_string_lossy())?;
        validate_network_mode(&docker_cfg.network)?;

        let mut cmd = Command::new("docker");
        cmd.arg("run");

        // Auto-cleanup
        cmd.arg("--rm");

        // Security: drop ALL capabilities
        cmd.arg("--cap-drop=ALL");

        // Security: prevent privilege escalation
        cmd.arg("--security-opt=no-new-privileges");

        // Security: read-only root filesystem
        cmd.arg("--read-only");

        // Network isolation
        cmd.arg(format!("--network={}", docker_cfg.network));

        // Writable /tmp with size limit
        cmd.arg("--tmpfs");
        cmd.arg(format!("/tmp:size={}", docker_cfg.tmpfs_size));

        // Resource limits: PID
        cmd.arg(format!("--pids-limit={}", docker_cfg.pids_limit));

        // Resource limits: memory
        cmd.arg(format!("--memory={}", docker_cfg.memory));

        // Resource limits: CPU
        cmd.arg(format!("--cpus={}", docker_cfg.cpus));

        // Workspace mount
        let mount_mode = if docker_cfg.workspace_writable {
            "rw"
        } else {
            "ro"
        };
        let workspace_path = config.sandbox_dir.to_string_lossy();
        cmd.arg("-v");
        cmd.arg(format!("{workspace_path}:/workspace:{mount_mode}"));

        // Working directory inside container
        cmd.arg("-w");
        cmd.arg("/workspace");

        // Extra mounts (always read-only for security)
        for mount in &docker_cfg.extra_mounts {
            validate_mount_spec(mount)?;
            cmd.arg("-v");
            cmd.arg(format!("{mount}:ro"));
        }

        // Environment variables
        for (key, val) in env {
            cmd.arg("-e");
            cmd.arg(format!("{key}={val}"));
        }

        // Image name
        cmd.arg(&docker_cfg.image);

        // User command and arguments
        cmd.arg(user_command);
        cmd.args(args);

        Ok(cmd)
    }
}

impl Default for DockerBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxBackend for DockerBackend {
    fn prepare(&self, config: &AegisConfig) -> Result<(), AegisError> {
        let docker_cfg = Self::docker_config(config);

        // Validate image name before any Docker operations
        validate_image_name(&docker_cfg.image)?;

        // Check Docker daemon is running
        let status = Command::new("docker")
            .arg("info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| {
                AegisError::SandboxError(format!(
                    "failed to check Docker daemon (is Docker installed?): {e}"
                ))
            })?;

        if !status.success() {
            return Err(AegisError::SandboxError(
                "Docker daemon is not running. Start Docker and try again.".into(),
            ));
        }

        // Check if the image exists locally, pull if needed
        let inspect = Command::new("docker")
            .args(["image", "inspect", &docker_cfg.image])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|e| {
                AegisError::SandboxError(format!("failed to inspect Docker image: {e}"))
            })?;

        if !inspect.success() {
            tracing::info!(image = %docker_cfg.image, "pulling Docker image");
            let pull = Command::new("docker")
                .args(["pull", &docker_cfg.image])
                .status()
                .map_err(|e| {
                    AegisError::SandboxError(format!("failed to pull Docker image: {e}"))
                })?;

            if !pull.success() {
                return Err(AegisError::SandboxError(format!(
                    "failed to pull Docker image '{}'. Verify the image name and your network connection.",
                    docker_cfg.image
                )));
            }
        }

        // Ensure the sandbox directory exists
        std::fs::create_dir_all(&config.sandbox_dir).map_err(|e| {
            AegisError::SandboxError(format!(
                "failed to create sandbox dir {}: {e}",
                config.sandbox_dir.display()
            ))
        })?;

        tracing::debug!(
            image = %docker_cfg.image,
            network = %docker_cfg.network,
            "Docker sandbox prepared"
        );

        Ok(())
    }

    fn exec(
        &self,
        command: &str,
        args: &[String],
        config: &AegisConfig,
    ) -> Result<std::process::ExitStatus, AegisError> {
        let docker_cfg = Self::docker_config(config);

        tracing::info!(
            command,
            image = %docker_cfg.image,
            "running command in Docker sandbox"
        );

        let mut cmd = self.build_command(command, args, config, &[])?;

        let status = if docker_cfg.timeout_secs > 0 {
            let child = cmd.spawn().map_err(|e| {
                AegisError::SandboxError(format!("failed to spawn Docker container: {e}"))
            })?;
            wait_with_timeout(child, docker_cfg.timeout_secs)?
        } else {
            cmd.status().map_err(|e| {
                AegisError::SandboxError(format!("failed to run Docker container: {e}"))
            })?
        };

        Ok(status)
    }

    fn spawn_and_wait(
        &self,
        command: &str,
        args: &[String],
        config: &AegisConfig,
        env: &[(&str, &str)],
    ) -> Result<(u32, std::process::ExitStatus), AegisError> {
        let docker_cfg = Self::docker_config(config);

        tracing::info!(
            command,
            image = %docker_cfg.image,
            "spawning command in Docker sandbox"
        );

        let mut cmd = self.build_command(command, args, config, env)?;

        let mut child = cmd.spawn().map_err(|e| {
            AegisError::SandboxError(format!("failed to spawn Docker container: {e}"))
        })?;

        let pid = child.id();

        let status = if docker_cfg.timeout_secs > 0 {
            wait_with_timeout(child, docker_cfg.timeout_secs)?
        } else {
            child.wait().map_err(|e| {
                AegisError::SandboxError(format!("failed to wait for Docker container: {e}"))
            })?
        };

        Ok((pid, status))
    }
}

/// Wait for a child process with a timeout, killing it if exceeded.
fn wait_with_timeout(
    mut child: std::process::Child,
    timeout_secs: u64,
) -> Result<std::process::ExitStatus, AegisError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    // Kill the container process
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(AegisError::SandboxError(format!(
                        "Docker container exceeded timeout of {timeout_secs}s and was killed"
                    )));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                return Err(AegisError::SandboxError(format!(
                    "failed to wait for Docker container: {e}"
                )));
            }
        }
    }
}

/// Validate a Docker image name to prevent shell injection.
///
/// Allowed characters: alphanumeric, hyphens, dots, colons, slashes, underscores, @.
/// This covers standard image references like `ubuntu:22.04`,
/// `registry.example.com/my-image:latest`, and `library/python:3.11-slim`.
pub fn validate_image_name(image: &str) -> Result<(), AegisError> {
    if image.is_empty() {
        return Err(AegisError::SandboxError(
            "Docker image name cannot be empty".into(),
        ));
    }

    if image.len() > 256 {
        return Err(AegisError::SandboxError(
            "Docker image name exceeds maximum length of 256 characters".into(),
        ));
    }

    for ch in image.chars() {
        if !ch.is_alphanumeric()
            && ch != '-'
            && ch != '.'
            && ch != ':'
            && ch != '/'
            && ch != '_'
            && ch != '@'
        {
            return Err(AegisError::SandboxError(format!(
                "Docker image name contains invalid character {ch:?}. \
                 Only alphanumeric, hyphens, dots, colons, slashes, underscores, and @ are allowed."
            )));
        }
    }

    // Reject image names that start with special characters
    if image.starts_with('-') || image.starts_with('.') || image.starts_with(':') {
        return Err(AegisError::SandboxError(format!(
            "Docker image name cannot start with {:?}",
            &image[..1]
        )));
    }

    Ok(())
}

/// Validate a workspace path to prevent directory traversal and injection.
///
/// Rejects null bytes, newlines, and `..` path components.
pub fn validate_workspace_path(path: &str) -> Result<(), AegisError> {
    if path.is_empty() {
        return Err(AegisError::SandboxError(
            "workspace path cannot be empty".into(),
        ));
    }

    // Reject null bytes (could truncate the path in C-level syscalls)
    if path.contains('\0') {
        return Err(AegisError::SandboxError(
            "workspace path contains null byte -- possible injection attempt".into(),
        ));
    }

    // Reject newlines (could inject additional arguments)
    if path.contains('\n') || path.contains('\r') {
        return Err(AegisError::SandboxError(
            "workspace path contains newline -- possible injection attempt".into(),
        ));
    }

    // Reject paths with ".." components to prevent traversal
    for component in std::path::Path::new(path).components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(AegisError::SandboxError(
                "workspace path contains '..' traversal component".into(),
            ));
        }
    }

    Ok(())
}

/// Validate a network mode string.
///
/// Allowed values: "none", "bridge", "host" (dangerous but explicit),
/// or a custom network name matching `[a-zA-Z0-9_-]+`.
fn validate_network_mode(network: &str) -> Result<(), AegisError> {
    if network.is_empty() {
        return Err(AegisError::SandboxError(
            "network mode cannot be empty".into(),
        ));
    }

    for ch in network.chars() {
        if !ch.is_alphanumeric() && ch != '-' && ch != '_' {
            return Err(AegisError::SandboxError(format!(
                "network mode contains invalid character {ch:?}. \
                 Only alphanumeric, hyphens, and underscores are allowed."
            )));
        }
    }

    Ok(())
}

/// Validate a mount specification string (host_path:container_path format).
fn validate_mount_spec(mount: &str) -> Result<(), AegisError> {
    if mount.contains('\0') || mount.contains('\n') || mount.contains('\r') {
        return Err(AegisError::SandboxError(format!(
            "mount spec contains invalid character: {mount:?}"
        )));
    }
    Ok(())
}

/// Build Docker `run` arguments with security flags from the given config.
///
/// Exposed for testing so that tests can inspect the constructed command
/// without actually running Docker.
pub fn build_docker_args(
    user_command: &str,
    args: &[String],
    config: &AegisConfig,
    env: &[(&str, &str)],
) -> Result<Vec<String>, AegisError> {
    let docker_cfg = DockerBackend::docker_config(config);

    validate_image_name(&docker_cfg.image)?;
    validate_workspace_path(&config.sandbox_dir.to_string_lossy())?;
    validate_network_mode(&docker_cfg.network)?;

    let mut result = Vec::new();
    result.push("run".to_string());
    result.push("--rm".to_string());
    result.push("--cap-drop=ALL".to_string());
    result.push("--security-opt=no-new-privileges".to_string());
    result.push("--read-only".to_string());
    result.push(format!("--network={}", docker_cfg.network));
    result.push("--tmpfs".to_string());
    result.push(format!("/tmp:size={}", docker_cfg.tmpfs_size));
    result.push(format!("--pids-limit={}", docker_cfg.pids_limit));
    result.push(format!("--memory={}", docker_cfg.memory));
    result.push(format!("--cpus={}", docker_cfg.cpus));

    let mount_mode = if docker_cfg.workspace_writable {
        "rw"
    } else {
        "ro"
    };
    let workspace_path = config.sandbox_dir.to_string_lossy();
    result.push("-v".to_string());
    result.push(format!("{workspace_path}:/workspace:{mount_mode}"));
    result.push("-w".to_string());
    result.push("/workspace".to_string());

    for mount in &docker_cfg.extra_mounts {
        validate_mount_spec(mount)?;
        result.push("-v".to_string());
        result.push(format!("{mount}:ro"));
    }

    for (key, val) in env {
        result.push("-e".to_string());
        result.push(format!("{key}={val}"));
    }

    result.push(docker_cfg.image.clone());
    result.push(user_command.to_string());
    for a in args {
        result.push(a.clone());
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::DockerSandboxConfig;
    use std::path::PathBuf;

    fn test_config_with_docker(docker_cfg: DockerSandboxConfig) -> AegisConfig {
        crate::test_helpers::test_config(
            PathBuf::from("/home/user/project"),
            IsolationConfig::Docker(docker_cfg),
        )
    }

    fn default_test_config() -> AegisConfig {
        test_config_with_docker(DockerSandboxConfig::default())
    }

    // ---- Command construction tests ----

    #[test]
    fn docker_command_construction() {
        let config = default_test_config();
        let args = build_docker_args("echo", &["hello".to_string()], &config, &[]).unwrap();

        // Must start with "run"
        assert_eq!(args[0], "run");

        // Must contain the user command and args
        let image_pos = args.iter().position(|a| a == "ubuntu:22.04").unwrap();
        assert_eq!(args[image_pos + 1], "echo");
        assert_eq!(args[image_pos + 2], "hello");
    }

    #[test]
    fn docker_security_flags_present() {
        let config = default_test_config();
        let args = build_docker_args("ls", &[], &config, &[]).unwrap();

        assert!(args.contains(&"--rm".to_string()), "must have --rm");
        assert!(
            args.contains(&"--cap-drop=ALL".to_string()),
            "must drop all capabilities"
        );
        assert!(
            args.contains(&"--security-opt=no-new-privileges".to_string()),
            "must have no-new-privileges"
        );
        assert!(
            args.contains(&"--read-only".to_string()),
            "must have read-only rootfs"
        );
    }

    #[test]
    fn network_isolation_none_default() {
        let config = default_test_config();
        let args = build_docker_args("ls", &[], &config, &[]).unwrap();

        assert!(
            args.contains(&"--network=none".to_string()),
            "default network must be 'none'"
        );
    }

    #[test]
    fn network_policy_mapping() {
        // Test bridge network
        let mut docker_cfg = DockerSandboxConfig::default();
        docker_cfg.network = "bridge".to_string();
        let config = test_config_with_docker(docker_cfg);
        let args = build_docker_args("ls", &[], &config, &[]).unwrap();
        assert!(args.contains(&"--network=bridge".to_string()));

        // Test custom network
        let mut docker_cfg = DockerSandboxConfig::default();
        docker_cfg.network = "my-custom-net".to_string();
        let config = test_config_with_docker(docker_cfg);
        let args = build_docker_args("ls", &[], &config, &[]).unwrap();
        assert!(args.contains(&"--network=my-custom-net".to_string()));
    }

    #[test]
    fn capability_dropping_applied() {
        let config = default_test_config();
        let args = build_docker_args("whoami", &[], &config, &[]).unwrap();

        // Security: ALL capabilities must be dropped
        assert!(
            args.contains(&"--cap-drop=ALL".to_string()),
            "ALL capabilities must be dropped unconditionally"
        );

        // Security: no-new-privileges must be set
        assert!(
            args.contains(&"--security-opt=no-new-privileges".to_string()),
            "no-new-privileges must be enforced"
        );
    }

    #[test]
    fn workspace_mount_readonly_default() {
        let config = default_test_config();
        let args = build_docker_args("ls", &[], &config, &[]).unwrap();

        let mount_arg = args
            .iter()
            .find(|a| a.contains(":/workspace:"))
            .expect("workspace mount must exist");
        assert!(
            mount_arg.ends_with(":ro"),
            "workspace must be mounted read-only by default, got: {mount_arg}"
        );
    }

    #[test]
    fn workspace_mount_writable_when_configured() {
        let mut docker_cfg = DockerSandboxConfig::default();
        docker_cfg.workspace_writable = true;
        let config = test_config_with_docker(docker_cfg);
        let args = build_docker_args("ls", &[], &config, &[]).unwrap();

        let mount_arg = args
            .iter()
            .find(|a| a.contains(":/workspace:"))
            .expect("workspace mount must exist");
        assert!(
            mount_arg.ends_with(":rw"),
            "workspace must be mounted read-write when configured, got: {mount_arg}"
        );
    }

    #[test]
    fn memory_and_cpu_limits() {
        let config = default_test_config();
        let args = build_docker_args("ls", &[], &config, &[]).unwrap();

        assert!(
            args.contains(&"--memory=512m".to_string()),
            "must have memory limit"
        );
        assert!(
            args.contains(&"--cpus=1".to_string()),
            "must have CPU limit"
        );
    }

    #[test]
    fn pids_limit_prevents_fork_bomb() {
        let config = default_test_config();
        let args = build_docker_args("ls", &[], &config, &[]).unwrap();

        assert!(
            args.contains(&"--pids-limit=256".to_string()),
            "must have PID limit to prevent fork bombs"
        );
    }

    #[test]
    fn tmpfs_size_limit() {
        let config = default_test_config();
        let args = build_docker_args("ls", &[], &config, &[]).unwrap();

        // Find the arg after --tmpfs
        let tmpfs_pos = args
            .iter()
            .position(|a| a == "--tmpfs")
            .expect("must have --tmpfs flag");
        let tmpfs_val = &args[tmpfs_pos + 1];
        assert_eq!(tmpfs_val, "/tmp:size=100m", "tmpfs must have size limit");
    }

    #[test]
    fn custom_resource_limits() {
        let mut docker_cfg = DockerSandboxConfig::default();
        docker_cfg.memory = "1g".to_string();
        docker_cfg.cpus = 2.5;
        docker_cfg.pids_limit = 512;
        docker_cfg.tmpfs_size = "200m".to_string();
        let config = test_config_with_docker(docker_cfg);
        let args = build_docker_args("ls", &[], &config, &[]).unwrap();

        assert!(args.contains(&"--memory=1g".to_string()));
        assert!(args.contains(&"--cpus=2.5".to_string()));
        assert!(args.contains(&"--pids-limit=512".to_string()));

        let tmpfs_pos = args.iter().position(|a| a == "--tmpfs").unwrap();
        assert_eq!(args[tmpfs_pos + 1], "/tmp:size=200m");
    }

    #[test]
    fn env_vars_passed_to_container() {
        let config = default_test_config();
        let env = vec![("MY_VAR", "hello"), ("OTHER", "world")];
        let args = build_docker_args("env", &[], &config, &env).unwrap();

        assert!(args.contains(&"-e".to_string()));
        assert!(args.contains(&"MY_VAR=hello".to_string()));
        assert!(args.contains(&"OTHER=world".to_string()));
    }

    // ---- Security validation tests ----

    #[test]
    fn image_name_validation_rejects_injection() {
        // Shell metacharacters
        assert!(validate_image_name("ubuntu; rm -rf /").is_err());
        assert!(validate_image_name("ubuntu$(whoami)").is_err());
        assert!(validate_image_name("ubuntu`id`").is_err());
        assert!(validate_image_name("ubuntu|cat /etc/passwd").is_err());
        assert!(validate_image_name("ubuntu && evil").is_err());
        assert!(validate_image_name("ubuntu\nmalicious").is_err());

        // Valid image names must pass
        assert!(validate_image_name("ubuntu:22.04").is_ok());
        assert!(validate_image_name("registry.example.com/my-image:latest").is_ok());
        assert!(validate_image_name("python:3.11-slim").is_ok());
        assert!(validate_image_name("ghcr.io/owner/repo:v1.0").is_ok());
        assert!(validate_image_name("image@sha256:abc123").is_ok());

        // Edge cases
        assert!(validate_image_name("").is_err());
        assert!(validate_image_name("-evil").is_err());
        assert!(validate_image_name(&"a".repeat(257)).is_err());
    }

    #[test]
    fn workspace_path_validation_rejects_traversal() {
        // Path traversal
        assert!(validate_workspace_path("/home/user/../../../etc/shadow").is_err());
        assert!(validate_workspace_path("/tmp/sandbox/../../etc").is_err());

        // Null bytes
        assert!(validate_workspace_path("/tmp/sand\0box").is_err());

        // Newlines
        assert!(validate_workspace_path("/tmp/sandbox\n-v /:/host:rw").is_err());
        assert!(validate_workspace_path("/tmp/sandbox\r\n-v /:/host:rw").is_err());

        // Valid paths
        assert!(validate_workspace_path("/home/user/project").is_ok());
        assert!(validate_workspace_path("/tmp/sandbox").is_ok());
        assert!(validate_workspace_path("relative/path").is_ok());
    }

    #[test]
    fn network_mode_validation() {
        assert!(validate_network_mode("none").is_ok());
        assert!(validate_network_mode("bridge").is_ok());
        assert!(validate_network_mode("host").is_ok());
        assert!(validate_network_mode("my-custom-net").is_ok());
        assert!(validate_network_mode("net_123").is_ok());

        // Invalid
        assert!(validate_network_mode("").is_err());
        assert!(validate_network_mode("none; rm -rf /").is_err());
        assert!(validate_network_mode("bridge\nmalicious").is_err());
    }

    #[test]
    fn extra_mounts_included() {
        let mut docker_cfg = DockerSandboxConfig::default();
        docker_cfg.extra_mounts = vec![
            "/data/models:/models".to_string(),
            "/data/cache:/cache".to_string(),
        ];
        let config = test_config_with_docker(docker_cfg);
        let args = build_docker_args("ls", &[], &config, &[]).unwrap();

        assert!(args.contains(&"/data/models:/models:ro".to_string()));
        assert!(args.contains(&"/data/cache:/cache:ro".to_string()));
    }

    #[test]
    fn mount_spec_rejects_injection() {
        assert!(validate_mount_spec("/data\0evil:/mount").is_err());
        assert!(validate_mount_spec("/data\nevil:/mount").is_err());
        assert!(validate_mount_spec("/data/safe:/mount").is_ok());
    }

    #[test]
    fn docker_config_defaults_sane() {
        let cfg = DockerSandboxConfig::default();
        assert_eq!(cfg.image, "ubuntu:22.04");
        assert_eq!(cfg.network, "none");
        assert_eq!(cfg.memory, "512m");
        assert_eq!(cfg.cpus, 1.0);
        assert_eq!(cfg.pids_limit, 256);
        assert_eq!(cfg.tmpfs_size, "100m");
        assert!(!cfg.workspace_writable);
        assert!(cfg.extra_mounts.is_empty());
        assert_eq!(cfg.timeout_secs, 300);
    }

    #[test]
    fn all_security_flags_present_in_default_config() {
        // This is the mandatory security property test.
        // Verify that a default Docker config produces a command with
        // ALL required security hardening flags.
        let config = default_test_config();
        let args = build_docker_args("true", &[], &config, &[]).unwrap();

        let required_flags = [
            "--rm",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--read-only",
            "--network=none",
        ];

        for flag in &required_flags {
            assert!(
                args.iter().any(|a| a == *flag),
                "SECURITY VIOLATION: required flag {flag} missing from Docker command"
            );
        }

        // Verify resource limits are present (DoS prevention)
        assert!(
            args.iter().any(|a| a.starts_with("--pids-limit=")),
            "SECURITY VIOLATION: PID limit missing"
        );
        assert!(
            args.iter().any(|a| a.starts_with("--memory=")),
            "SECURITY VIOLATION: memory limit missing"
        );
        assert!(
            args.iter().any(|a| a.starts_with("--cpus=")),
            "SECURITY VIOLATION: CPU limit missing"
        );

        // Verify workspace is read-only by default
        let mount = args
            .iter()
            .find(|a| a.contains(":/workspace:"))
            .expect("workspace mount missing");
        assert!(
            mount.ends_with(":ro"),
            "SECURITY VIOLATION: workspace must be read-only by default"
        );

        // Verify tmpfs has size limit
        let tmpfs_pos = args.iter().position(|a| a == "--tmpfs").unwrap();
        assert!(
            args[tmpfs_pos + 1].contains("size="),
            "SECURITY VIOLATION: tmpfs must have size limit"
        );
    }
}
