/**
 * TypeScript types matching the Aegis daemon Rust API types.
 *
 * These types mirror the structures in:
 * - crates/aegis-control/src/command.rs (CommandResponse, PilotStatus)
 * - crates/aegis-control/src/daemon.rs (DaemonCommand, DaemonResponse, AgentStatus)
 * - crates/aegis-control/src/pending.rs (PendingRequest)
 */

/** Response envelope from all API endpoints. */
export interface CommandResponse {
  ok: boolean;
  message: string;
  data?: unknown;
}

/**
 * Agent status enum matching Rust AgentStatus.
 * The Rust enum uses serde tag+content, so JSON looks like:
 *   { "Running": { "pid": 12345 } }
 *   "Pending"
 *   { "Stopped": { "exit_code": 0 } }
 *   etc.
 */
export type AgentStatus =
  | "Pending"
  | "Stopping"
  | "Disabled"
  | { Running: { pid: number } }
  | { Stopped: { exit_code: number } }
  | { Crashed: { exit_code: number; restart_in_secs: number } }
  | { Failed: { exit_code: number; restart_count: number } };

/** Parsed agent info from the fleet list response. */
export interface AgentInfo {
  name: string;
  status: AgentStatus;
  pending_count: number;
  uptime_secs: number;
  driver: string;
  enabled: boolean;
}

/** Pilot-level status snapshot. */
export interface PilotStatus {
  command: string;
  pid: number;
  alive: boolean;
  uptime_secs: number;
  idle_secs: number;
  pending_count: number;
  approved: number;
  denied: number;
  nudges: number;
  adapter: string;
}

/** A pending permission request. */
export interface PendingRequest {
  id: string;
  raw_prompt: string;
  agent_name: string;
  risk_level: string | null;
  timeout_at: string;
  approval_count: number;
  require_approvals: number;
  delegated_to: string | null;
}

/** Agent context fields. */
export interface AgentContext {
  role: string | null;
  goal: string | null;
  context: string | null;
  task: string | null;
}

// ---------------------------------------------------------------------------
// Type guards for runtime validation
// ---------------------------------------------------------------------------

/** Validate that a value has the CommandResponse shape. */
export function isCommandResponse(v: unknown): v is CommandResponse {
  if (typeof v !== "object" || v === null) return false;
  const obj = v as Record<string, unknown>;
  return typeof obj["ok"] === "boolean" && typeof obj["message"] === "string";
}

/** Extract a human-readable status label from AgentStatus. */
export function statusLabel(status: AgentStatus): string {
  if (typeof status === "string") return status;
  if ("Running" in status) return "Running";
  if ("Stopped" in status) return "Stopped";
  if ("Crashed" in status) return "Crashed";
  if ("Failed" in status) return "Failed";
  return "Unknown";
}

/** Extract PID from AgentStatus if running. */
export function statusPid(status: AgentStatus): number | null {
  if (typeof status === "object" && "Running" in status) {
    return status.Running.pid;
  }
  return null;
}

/** Determine the severity class for a status. */
export function statusSeverity(
  status: AgentStatus,
): "ok" | "warn" | "error" | "neutral" {
  const label = statusLabel(status);
  switch (label) {
    case "Running":
      return "ok";
    case "Pending":
    case "Stopping":
      return "warn";
    case "Crashed":
    case "Failed":
      return "error";
    default:
      return "neutral";
  }
}
