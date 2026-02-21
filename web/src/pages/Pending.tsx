/**
 * Pending approvals page.
 *
 * Lists all pending permission requests across all agents.
 * Each request shows the prompt text, risk level, and approve/deny buttons.
 *
 * All user-generated content (prompt text) is sanitized via escapeHtml().
 */

import { Link } from "react-router-dom";

import { useApproveRequest, useDenyRequest, usePending } from "../hooks/useAgents";
import { escapeHtml } from "../sanitize";
import styles from "./Pending.module.css";

export function Pending() {
  const { data: pending, isLoading, error } = usePending();
  const approveMutation = useApproveRequest();
  const denyMutation = useDenyRequest();

  return (
    <div className={styles.page}>
      <nav className={styles.breadcrumb}>
        <Link to="/">Dashboard</Link>
        <span className={styles.separator}>/</span>
        <span>Pending Approvals</span>
      </nav>

      <header className={styles.header}>
        <h1 className={styles.title}>Pending Approvals</h1>
        <span className={styles.count}>
          {pending ? pending.length : 0} pending
        </span>
      </header>

      {isLoading && (
        <div className={styles.loading}>Loading pending requests...</div>
      )}

      {error && (
        <div className={styles.error}>
          <strong>Error:</strong> {error.message}
        </div>
      )}

      {pending && pending.length === 0 && (
        <div className={styles.empty}>
          No pending approval requests. All clear.
        </div>
      )}

      {pending && pending.length > 0 && (
        <ul className={styles.list}>
          {pending.map((req) => (
            <li key={req.id} className={styles.item}>
              <div className={styles.itemHeader}>
                <Link
                  to={`/agents/${encodeURIComponent(req.agent_name)}`}
                  className={styles.agentLink}
                >
                  {req.agent_name}
                </Link>
                {req.risk_level && (
                  <span
                    className={`${styles.riskBadge} ${
                      req.risk_level === "critical" || req.risk_level === "high"
                        ? styles.riskHigh
                        : styles.riskDefault
                    }`}
                  >
                    {req.risk_level}
                  </span>
                )}
                <span className={styles.requestId}>
                  {req.id.slice(0, 8)}...
                </span>
              </div>
              <div className={styles.prompt}>
                {escapeHtml(req.raw_prompt)}
              </div>
              <div className={styles.itemMeta}>
                {req.delegated_to && (
                  <span>Delegated to: {req.delegated_to}</span>
                )}
                <span>
                  Approvals: {req.approval_count}/{req.require_approvals}
                </span>
              </div>
              <div className={styles.actions}>
                <button
                  className={`${styles.btn} ${styles.approveBtn}`}
                  onClick={() => approveMutation.mutate(req.id)}
                  disabled={approveMutation.isPending}
                >
                  Approve
                </button>
                <button
                  className={`${styles.btn} ${styles.denyBtn}`}
                  onClick={() => denyMutation.mutate({ id: req.id })}
                  disabled={denyMutation.isPending}
                >
                  Deny
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
