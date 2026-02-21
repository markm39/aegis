/**
 * Pending approvals page.
 *
 * Lists all pending permission requests across all agents.
 * Each request shows the prompt text, risk level, and approve/deny buttons.
 *
 * All user-generated content (prompt text) is sanitized via escapeHtml().
 */

import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";

import { useApproveRequest, useDenyRequest, usePending } from "../hooks/useAgents";
import { escapeHtml } from "../sanitize";
import styles from "./Pending.module.css";

export function Pending() {
  const { t } = useTranslation();
  const { data: pending, isLoading, error } = usePending();
  const approveMutation = useApproveRequest();
  const denyMutation = useDenyRequest();

  return (
    <div className={styles.page}>
      <nav className={styles.breadcrumb}>
        <Link to="/">{t("pending.breadcrumbDashboard")}</Link>
        <span className={styles.separator}>/</span>
        <span>{t("pending.breadcrumbPending")}</span>
      </nav>

      <header className={styles.header}>
        <h1 className={styles.title}>{t("pending.title")}</h1>
        <span className={styles.count}>
          {t("pending.count", { count: pending ? pending.length : 0 })}
        </span>
      </header>

      {isLoading && (
        <div className={styles.loading}>{t("pending.loadingRequests")}</div>
      )}

      {error && (
        <div className={styles.error}>
          <strong>{t("common.error")}:</strong> {error.message}
        </div>
      )}

      {pending && pending.length === 0 && (
        <div className={styles.empty}>
          {t("pending.noRequests")}
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
                  <span>{t("pending.delegatedTo", { name: req.delegated_to })}</span>
                )}
                <span>
                  {t("pending.approvalCount", {
                    current: req.approval_count,
                    required: req.require_approvals,
                  })}
                </span>
              </div>
              <div className={styles.actions}>
                <button
                  className={`${styles.btn} ${styles.approveBtn}`}
                  onClick={() => approveMutation.mutate(req.id)}
                  disabled={approveMutation.isPending}
                >
                  {t("common.approve")}
                </button>
                <button
                  className={`${styles.btn} ${styles.denyBtn}`}
                  onClick={() => denyMutation.mutate({ id: req.id })}
                  disabled={denyMutation.isPending}
                >
                  {t("common.deny")}
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
