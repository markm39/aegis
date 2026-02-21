/**
 * Agent list table component.
 *
 * Displays all agents with their status, pending count, and uptime.
 * Rows are clickable and navigate to the agent detail page.
 *
 * All text content is rendered through React's built-in JSX text escaping,
 * ensuring agent names and other user-provided strings are safe from XSS.
 */

import { useNavigate } from "react-router-dom";

import type { AgentInfo } from "../api/types";
import { AgentStatus } from "./AgentStatus";
import styles from "./AgentTable.module.css";

interface AgentTableProps {
  agents: AgentInfo[];
}

/** Format seconds into a human-readable uptime string. */
function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  const hours = Math.floor(secs / 3600);
  const minutes = Math.floor((secs % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

export function AgentTable({ agents }: AgentTableProps) {
  const navigate = useNavigate();

  if (agents.length === 0) {
    return (
      <div className={styles.empty}>
        No agents configured. Add agents via the Aegis TUI or daemon.toml.
      </div>
    );
  }

  return (
    <table className={styles.table}>
      <thead>
        <tr>
          <th>Name</th>
          <th>Status</th>
          <th>Driver</th>
          <th>Pending</th>
          <th>Uptime</th>
        </tr>
      </thead>
      <tbody>
        {agents.map((agent) => (
          <tr
            key={agent.name}
            className={styles.row}
            onClick={() => navigate(`/agents/${encodeURIComponent(agent.name)}`)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                navigate(`/agents/${encodeURIComponent(agent.name)}`);
              }
            }}
          >
            <td className={styles.name}>{agent.name}</td>
            <td>
              <AgentStatus status={agent.status} />
            </td>
            <td>{agent.driver}</td>
            <td>
              {agent.pending_count > 0 ? (
                <span className={styles.pendingBadge}>
                  {agent.pending_count}
                </span>
              ) : (
                <span className={styles.zeroPending}>0</span>
              )}
            </td>
            <td>{formatUptime(agent.uptime_secs)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
