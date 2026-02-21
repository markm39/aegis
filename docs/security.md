# Aegis Security Model

Aegis enforces a zero-trust security model for AI agents. No agent action is implicitly trusted -- every file access, network connection, tool invocation, and process spawn is evaluated against Cedar policies before being allowed.

## Overview

The security model has four layers:

1. **Cedar policy engine** -- authorization decisions based on declarative policies
2. **OS-level sandbox** -- kernel-enforced isolation (Seatbelt on macOS, Docker on Linux)
3. **Hash-chained audit ledger** -- tamper-evident record of all actions and decisions
4. **PTY supervision** -- real-time interception and control of agent permission prompts

Each layer is independent. If one layer fails, the others continue to provide protection.

## Cedar Policy Language

Aegis uses [Cedar](https://www.cedarpolicy.com/), an authorization policy language created by Amazon and formally verified for correctness. Cedar policies are declarative rules that permit or forbid actions.

### Entity Model

The Aegis Cedar schema defines three entity types:

- **`Aegis::Agent`** -- the AI agent principal (identified by configuration name)
- **`Aegis::Resource`** -- the target of an action (file path, network host, tool name)
- **`Aegis::Action`** -- the type of operation being performed

### Action Types

| Action | Resource | Description |
|--------|----------|-------------|
| `FileRead` | File path | Reading a file |
| `FileWrite` | File path | Writing to a file |
| `FileDelete` | File path | Deleting a file |
| `DirCreate` | Directory path | Creating a directory |
| `DirList` | Directory path | Listing directory contents |
| `NetConnect` | Hostname | Opening a network connection |
| `ToolCall` | Tool name | Invoking an agent tool |
| `ProcessSpawn` | Command path | Spawning a subprocess |
| `ProcessExit` | Command path | Process exit event |
| `ApiUsage` | Provider name | AI API call with token usage |

### Policy Syntax

Cedar policies use `permit` and `forbid` statements:

```cedar
// Allow all agents to read files
permit(
    principal,
    action == Aegis::Action::"FileRead",
    resource
);

// Allow a specific agent to write files
permit(
    principal == Aegis::Agent::"my-agent",
    action == Aegis::Action::"FileWrite",
    resource
);

// Deny all network access
forbid(
    principal,
    action == Aegis::Action::"NetConnect",
    resource
);
```

### Key Properties

- **Default-deny**: If no `permit` policy matches an action, it is denied. You do not need explicit `forbid` rules to block things -- only add `permit` rules for what you want to allow.
- **Forbid overrides permit**: If both a `permit` and a `forbid` match the same action, the `forbid` wins. This makes it safe to write broad permits with targeted denials.
- **Resource conditions**: Use the `resource.path` attribute to restrict actions to specific paths:

```cedar
// Allow writes only within the project directory
permit(
    principal,
    action == Aegis::Action::"FileWrite",
    resource
)
when {
    resource.path like "/home/user/my-project/*"
};
```

### Policy File Location

Policy files are stored as `.cedar` files in the configuration's `policies/` directory:

```
~/.aegis/my-agent/policies/
  default.cedar     # Main policy
  network.cedar     # Network-specific rules (optional)
  sensitive.cedar   # Deny rules for sensitive paths (optional)
```

All `.cedar` files in the directory are loaded and combined into a single policy set. If the directory is empty or missing, the built-in `default-deny` policy is used.

### Built-in Policy Templates

Aegis ships with several policy templates you can use as starting points:

**default-deny** -- Blocks everything:
```cedar
forbid(principal, action, resource);
```

**allow-read-only** -- Permits reads and directory listings:
```cedar
permit(principal, action == Aegis::Action::"FileRead", resource);
permit(principal, action == Aegis::Action::"DirList", resource);
permit(principal, action == Aegis::Action::"ProcessSpawn", resource);
permit(principal, action == Aegis::Action::"ProcessExit", resource);
```

**permit-all** -- Allows everything (observe-only mode):
```cedar
permit(principal, action, resource);
```

### Hot Reloading

The policy engine supports `reload()` to pick up new policies from disk without restarting the daemon. Changed policies take effect on the next action evaluation.

## Audit Ledger Tamper Detection

The audit ledger is an append-only SQLite database with a SHA-256 hash chain.

### Hash Chain Structure

Each audit entry contains:

| Field | Description |
|-------|-------------|
| `entry_id` | Unique UUID for this entry |
| `timestamp` | When the action was evaluated |
| `action_id` | UUID of the action |
| `action_kind` | JSON-serialized action type and parameters |
| `principal` | Agent name that performed the action |
| `decision` | "Allow" or "Deny" |
| `reason` | Human-readable reason for the decision |
| `policy_id` | Cedar policy that produced the decision |
| `prev_hash` | SHA-256 hash of the previous entry |
| `entry_hash` | SHA-256 hash of this entry's contents |

The `entry_hash` is computed as:

```
SHA-256(entry_id || timestamp || action_id || action_kind || principal || decision || reason || prev_hash)
```

The first entry in the chain uses the sentinel value `"genesis"` as its `prev_hash`.

### Integrity Verification

Run integrity verification to detect any tampering:

```bash
aegis audit my-agent --verify
```

Verification walks the full chain from the first entry to the last, checking:

1. Each entry's stored `entry_hash` matches the recomputed hash of its contents.
2. Each entry's `prev_hash` equals the preceding entry's `entry_hash`.

If any entry has been modified, inserted, deleted, or reordered, the verification reports the exact position where the chain breaks.

### Session Tracking

Audit entries can be grouped into sessions. Each session records:

- Config name and command that was run
- Start and end timestamps
- Total actions and denied actions
- Policy hash at session start (for compliance snapshots)

### Policy Snapshots

When a session begins, the current policy files can be snapshotted. This creates a permanent record of which policies were in effect during each session, supporting compliance audits.

## Sandbox Profiles

### Seatbelt (macOS)

On macOS, Aegis uses `sandbox-exec` with a generated SBPL (Seatbelt Profile Language) profile. The profile starts with a default-deny stance:

```
(version 1)
(deny default)
```

Then selectively allows:

- **System reads**: `/usr`, `/bin`, `/sbin`, `/Library`, `/System` (read-only)
- **Sandbox directory**: Read/write access within the configured sandbox directory only
- **Process execution**: `process-exec`, `process-fork` for running commands
- **System primitives**: `sysctl-read`, `mach-lookup` for basic operation
- **Network**: Denied by default; allowed only when `allowed_network` rules are configured

The Cedar-to-SBPL compiler translates loaded Cedar policy rules into native Seatbelt directives. If your Cedar policy does not permit `FileWrite`, the Seatbelt profile will not contain write rules -- the kernel itself prevents writes even if the agent tries to bypass Aegis.

Custom SBPL overrides can be specified in the configuration:

```toml
[isolation]
type = "Seatbelt"
profile_overrides = "/path/to/custom.sb"
```

### Docker

For containerized isolation, Docker containers run with hardened security defaults:

| Setting | Value | Purpose |
|---------|-------|---------|
| `--cap-drop ALL` | Drop all capabilities | Minimal privilege |
| `--no-new-privileges` | Enabled | Prevent privilege escalation |
| Root filesystem | Read-only | Prevent persistent modifications |
| PID limit | 256 (default) | Prevent fork bombs |
| Memory limit | 512 MB (default) | Prevent memory exhaustion |
| Network mode | `none` (default) | No network access |
| `/tmp` mount | tmpfs, 100 MB | Temporary scratch space |

These security settings are enforced unconditionally and cannot be disabled through configuration. Configurable options include the Docker image, memory/CPU limits, network mode, extra mounts, and timeout.

```toml
[isolation]
type = "Docker"

[isolation.Docker]
image = "ubuntu:22.04"
network = "none"
memory = "512m"
cpus = 1.0
pids_limit = 256
tmpfs_size = "100m"
workspace_writable = false
timeout_secs = 300
```

### Process Isolation

When neither Seatbelt nor Docker is available, Aegis falls back to process-level isolation. This relies on the policy engine and observer for enforcement rather than kernel-level sandboxing. The agent process runs as a normal child process with filesystem monitoring providing visibility.

## Threat Model

### What Aegis Protects Against

**Unauthorized file access**: Cedar policies control which files an agent can read, write, or delete. The Seatbelt sandbox enforces this at the kernel level on macOS.

**Unauthorized network access**: Network connections are denied by default. The Seatbelt profile blocks network syscalls unless `allowed_network` rules are configured and Cedar policies permit `NetConnect`.

**Data exfiltration**: Combining file read restrictions with network deny policies prevents an agent from reading sensitive files and sending their contents to external servers.

**Audit log tampering**: The hash chain makes it detectable if anyone modifies, inserts, or deletes audit entries after the fact. Each entry's hash depends on every field of the entry plus the previous entry's hash.

**Privilege escalation**: Docker's `--no-new-privileges` and `--cap-drop ALL` prevent the agent from gaining additional system permissions. Seatbelt's kernel-level enforcement cannot be bypassed by the sandboxed process.

**Fork bombs and resource exhaustion**: Docker PID limits and memory limits prevent runaway processes. The Seatbelt sandbox limits process creation to within the sandbox directory.

**Subagent recursion**: Depth-based guardrails prevent agents from spawning unbounded chains of subagents. At depth >= 2, destructive actions (write, delete, spawn) are unconditionally denied. Subagent spawning is capped at a configurable depth limit.

**Non-UTF-8 path bypasses**: Paths containing non-UTF-8 bytes are denied during policy evaluation, preventing crafted paths from bypassing Cedar string-based policy rules.

### What Aegis Does NOT Protect Against

**Compromised host OS**: If the operating system itself is compromised, kernel-level sandboxing may be bypassed. Aegis assumes a trusted kernel.

**Side channels**: Aegis does not protect against timing side channels, speculative execution attacks, or other hardware-level vulnerabilities.

**Seatbelt bypass on older macOS**: Apple's `sandbox-exec` is technically deprecated (though still functional). Future macOS versions could change its behavior.

**Agent within sandbox**: If the agent finds a way to escape the sandbox (e.g., via a kernel vulnerability), Aegis cannot prevent subsequent actions. The audit trail would still record actions up to the escape point.

**Denial of service against Aegis itself**: A malicious agent could generate enormous volumes of actions to fill the audit database or exhaust alert webhooks. Rate limiting and cooldown timers on alerts partially mitigate this.

## Security Best Practices

1. **Start with default-deny** and add permits incrementally. Only allow the specific actions your agent needs.

2. **Use Seatbelt on macOS** (the default) for kernel-level enforcement. Cedar policies alone rely on the agent cooperating with the permission prompt system.

3. **Use path-specific policies** rather than blanket permits:
   ```cedar
   // Better: restrict writes to the project directory
   permit(
       principal == Aegis::Agent::"my-agent",
       action == Aegis::Action::"FileWrite",
       resource
   )
   when { resource.path like "/home/user/my-project/*" };
   ```

4. **Keep network deny by default**. Only add `allowed_network` rules for hosts your agent genuinely needs to contact (e.g., API endpoints).

5. **Verify audit integrity regularly**. Schedule periodic integrity checks as part of your compliance workflow.

6. **Use sessions** to scope audit entries. Begin a session before each agent run so you can query and report on activity per-session.

7. **Snapshot policies** when sessions start. This creates a permanent record of what rules were in effect, supporting post-incident analysis.

8. **Configure alert rules** for high-risk events (denials, writes to sensitive paths, network connections) to get immediate notification via webhooks or Telegram.
