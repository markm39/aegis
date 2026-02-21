/**
 * Agent detail page.
 *
 * Shows detailed information for a single agent:
 * - Status header with name, status, uptime, PID
 * - Output log area (scrollable, monospace, HTML-escaped)
 * - Pending approvals section with approve/deny buttons
 * - Input send form
 *
 * Security: all agent output is sanitized via escapeHtml() before
 * rendering. React's JSX text nodes auto-escape, and we additionally
 * escape output lines that could contain HTML entities.
 */

import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams } from "react-router-dom";

import { AgentStatus } from "../components/AgentStatus";
import {
  useAgentContext,
  useAgentOutput,
  useAgents,
  useApproveRequest,
  useDenyRequest,
  usePending,
  useSendInput,
  useStartAgent,
  useStopAgent,
  useRestartAgent,
} from "../hooks/useAgents";
import { statusLabel, statusPid } from "../api/types";
import { escapeHtml } from "../sanitize";
import styles from "./AgentDetail.module.css";

export function AgentDetail() {
  const { t } = useTranslation();
  const { name } = useParams<{ name: string }>();
  const decodedName = name ? decodeURIComponent(name) : "";

  const { data: agents } = useAgents();
  const { data: context } = useAgentContext(decodedName);
  const { data: outputLines } = useAgentOutput(200);
  const { data: allPending } = usePending();

  const approveMutation = useApproveRequest();
  const denyMutation = useDenyRequest();
  const sendInputMutation = useSendInput();
  const startMutation = useStartAgent();
  const stopMutation = useStopAgent();
  const restartMutation = useRestartAgent();

  const [inputText, setInputText] = useState("");
  const outputEndRef = useRef<HTMLDivElement>(null);

  const agent = agents?.find((a) => a.name === decodedName);
  const agentPending = allPending?.filter((p) => p.agent_name === decodedName) ?? [];

  const handleSendInput = useCallback(() => {
    if (inputText.trim()) {
      sendInputMutation.mutate(inputText.trim());
      setInputText("");
    }
  }, [inputText, sendInputMutation]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        handleSendInput();
      }
    },
    [handleSendInput],
  );

  if (!decodedName) {
    return (
      <div className={styles.page}>
        <p>{t("agent.noName")}</p>
        <Link to="/">{t("agent.backToDashboard")}</Link>
      </div>
    );
  }

  return (
    <div className={styles.page}>
      <nav className={styles.breadcrumb}>
        <Link to="/">{t("agent.breadcrumbDashboard")}</Link>
        <span className={styles.separator}>/</span>
        <span>{decodedName}</span>
      </nav>

      {/* Agent info header */}
      <header className={styles.header}>
        <div className={styles.headerMain}>
          <h1 className={styles.agentName}>{decodedName}</h1>
          {agent && <AgentStatus status={agent.status} />}
        </div>
        <div className={styles.headerMeta}>
          {agent && (
            <>
              <span className={styles.meta}>
                {t("agent.pid")}: {statusPid(agent.status) ?? t("common.noData")}
              </span>
              <span className={styles.meta}>
                {t("agent.uptime")}: {formatUptime(agent.uptime_secs)}
              </span>
              <span className={styles.meta}>
                {t("agent.driver")}: {agent.driver}
              </span>
              <span className={styles.meta}>
                {t("agent.status")}: {statusLabel(agent.status)}
              </span>
            </>
          )}
        </div>
        <div className={styles.headerActions}>
          <button
            className={styles.actionBtn}
            onClick={() => startMutation.mutate(decodedName)}
            disabled={startMutation.isPending}
          >
            {t("common.start")}
          </button>
          <button
            className={styles.actionBtn}
            onClick={() => stopMutation.mutate(decodedName)}
            disabled={stopMutation.isPending}
          >
            {t("common.stop")}
          </button>
          <button
            className={styles.actionBtn}
            onClick={() => restartMutation.mutate(decodedName)}
            disabled={restartMutation.isPending}
          >
            {t("common.restart")}
          </button>
        </div>
      </header>

      {/* Agent context */}
      {context && (context.role || context.goal || context.task) && (
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>{t("agent.context")}</h2>
          <dl className={styles.contextList}>
            {context.role && (
              <>
                <dt>{t("agent.role")}</dt>
                <dd>{context.role}</dd>
              </>
            )}
            {context.goal && (
              <>
                <dt>{t("agent.goal")}</dt>
                <dd>{context.goal}</dd>
              </>
            )}
            {context.task && (
              <>
                <dt>{t("agent.task")}</dt>
                <dd>{context.task}</dd>
              </>
            )}
          </dl>
        </section>
      )}

      {/* Pending approvals */}
      {agentPending.length > 0 && (
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>
            {t("agent.pendingApprovals", { count: agentPending.length })}
          </h2>
          <ul className={styles.pendingList}>
            {agentPending.map((req) => (
              <li key={req.id} className={styles.pendingItem}>
                <div className={styles.pendingPrompt}>
                  {escapeHtml(req.raw_prompt)}
                </div>
                <div className={styles.pendingMeta}>
                  {req.risk_level && (
                    <span className={styles.riskBadge}>
                      {req.risk_level}
                    </span>
                  )}
                  <span>ID: {req.id.slice(0, 8)}</span>
                </div>
                <div className={styles.pendingActions}>
                  <button
                    className={`${styles.actionBtn} ${styles.approveBtn}`}
                    onClick={() => approveMutation.mutate(req.id)}
                    disabled={approveMutation.isPending}
                  >
                    {t("common.approve")}
                  </button>
                  <button
                    className={`${styles.actionBtn} ${styles.denyBtn}`}
                    onClick={() =>
                      denyMutation.mutate({ id: req.id })
                    }
                    disabled={denyMutation.isPending}
                  >
                    {t("common.deny")}
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Output log */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("agent.output")}</h2>
        <div className={styles.outputArea}>
          {outputLines && outputLines.length > 0 ? (
            outputLines.map((line, i) => (
              <div key={i} className={styles.outputLine}>
                {escapeHtml(line)}
              </div>
            ))
          ) : (
            <div className={styles.outputEmpty}>{t("agent.noOutput")}</div>
          )}
          <div ref={outputEndRef} />
        </div>
      </section>

      {/* Input form */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>{t("agent.sendInput")}</h2>
        <div className={styles.inputForm}>
          <input
            type="text"
            className={styles.inputField}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={t("agent.inputPlaceholder")}
            disabled={sendInputMutation.isPending}
          />
          <button
            className={styles.actionBtn}
            onClick={handleSendInput}
            disabled={!inputText.trim() || sendInputMutation.isPending}
          >
            {t("common.send")}
          </button>
        </div>
        {sendInputMutation.isError && (
          <div className={styles.inputError}>
            {t("agent.sendFailed", { message: sendInputMutation.error.message })}
          </div>
        )}
      </section>
    </div>
  );
}

function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  const hours = Math.floor(secs / 3600);
  const minutes = Math.floor((secs % 3600) / 60);
  return `${hours}h ${minutes}m`;
}
