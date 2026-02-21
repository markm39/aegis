/**
 * Fleet dashboard page.
 *
 * Shows a table of all agents with status indicators.
 * Auto-refreshes every 5 seconds via React Query polling.
 */

import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";

import { AgentTable } from "../components/AgentTable";
import { useAgents, usePending } from "../hooks/useAgents";
import styles from "./Dashboard.module.css";

export function Dashboard() {
  const { t } = useTranslation();
  const { data: agents, isLoading, error } = useAgents();
  const { data: pending } = usePending();

  const pendingCount = pending?.length ?? 0;

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <h1 className={styles.title}>{t("dashboard.title")}</h1>
        <div className={styles.headerActions}>
          {pendingCount > 0 && (
            <Link to="/pending" className={styles.pendingLink}>
              {t("dashboard.pendingApprovals", { count: pendingCount })}
            </Link>
          )}
        </div>
      </header>

      {isLoading && (
        <div className={styles.loading}>{t("dashboard.loadingAgents")}</div>
      )}

      {error && (
        <div className={styles.error}>
          <strong>{t("dashboard.connectionError")}</strong> {error.message}
          <p className={styles.errorHint}>
            {t("dashboard.connectionHint")}
          </p>
        </div>
      )}

      {agents && <AgentTable agents={agents} />}

      <footer className={styles.footer}>
        <span className={styles.footerLabel}>
          {agents ? t("dashboard.agentCount", { count: agents.length }) : ""}
        </span>
        <span className={styles.footerLabel}>{t("dashboard.autoRefresh")}</span>
      </footer>
    </div>
  );
}
