/**
 * Status badge component for displaying agent status with color coding.
 *
 * Severity mapping:
 * - ok (green): Running
 * - warn (yellow): Pending, Stopping
 * - error (red): Crashed, Failed
 * - neutral (gray): Stopped, Disabled, Unknown
 */

import type { AgentStatus as AgentStatusType } from "../api/types";
import { statusLabel, statusSeverity } from "../api/types";
import styles from "./AgentStatus.module.css";

interface AgentStatusProps {
  status: AgentStatusType;
}

export function AgentStatus({ status }: AgentStatusProps) {
  const label = statusLabel(status);
  const severity = statusSeverity(status);

  return (
    <span className={`${styles.badge} ${styles[severity]}`}>{label}</span>
  );
}
