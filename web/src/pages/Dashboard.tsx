/**
 * Fleet dashboard page.
 *
 * Shows a table of all agents with status indicators.
 * Auto-refreshes every 5 seconds via React Query polling.
 */

import { Link } from "react-router-dom";

import { AgentTable } from "../components/AgentTable";
import { useAgents, usePending } from "../hooks/useAgents";
import styles from "./Dashboard.module.css";

export function Dashboard() {
  const { data: agents, isLoading, error } = useAgents();
  const { data: pending } = usePending();

  const pendingCount = pending?.length ?? 0;

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <h1 className={styles.title}>Aegis Fleet Dashboard</h1>
        <div className={styles.headerActions}>
          {pendingCount > 0 && (
            <Link to="/pending" className={styles.pendingLink}>
              {pendingCount} pending approval{pendingCount !== 1 ? "s" : ""}
            </Link>
          )}
        </div>
      </header>

      {isLoading && (
        <div className={styles.loading}>Loading agents...</div>
      )}

      {error && (
        <div className={styles.error}>
          <strong>Connection error:</strong> {error.message}
          <p className={styles.errorHint}>
            Ensure the Aegis daemon is running and the API URL is correct.
          </p>
        </div>
      )}

      {agents && <AgentTable agents={agents} />}

      <footer className={styles.footer}>
        <span className={styles.footerLabel}>
          {agents ? `${agents.length} agent${agents.length !== 1 ? "s" : ""}` : ""}
        </span>
        <span className={styles.footerLabel}>Auto-refresh: 5s</span>
      </footer>
    </div>
  );
}
