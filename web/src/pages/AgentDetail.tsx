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
        <p>No agent name specified.</p>
        <Link to="/">Back to dashboard</Link>
      </div>
    );
  }

  return (
    <div className={styles.page}>
      <nav className={styles.breadcrumb}>
        <Link to="/">Dashboard</Link>
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
                PID: {statusPid(agent.status) ?? "N/A"}
              </span>
              <span className={styles.meta}>
                Uptime: {formatUptime(agent.uptime_secs)}
              </span>
              <span className={styles.meta}>
                Driver: {agent.driver}
              </span>
              <span className={styles.meta}>
                Status: {statusLabel(agent.status)}
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
            Start
          </button>
          <button
            className={styles.actionBtn}
            onClick={() => stopMutation.mutate(decodedName)}
            disabled={stopMutation.isPending}
          >
            Stop
          </button>
          <button
            className={styles.actionBtn}
            onClick={() => restartMutation.mutate(decodedName)}
            disabled={restartMutation.isPending}
          >
            Restart
          </button>
        </div>
      </header>

      {/* Agent context */}
      {context && (context.role || context.goal || context.task) && (
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>Context</h2>
          <dl className={styles.contextList}>
            {context.role && (
              <>
                <dt>Role</dt>
                <dd>{context.role}</dd>
              </>
            )}
            {context.goal && (
              <>
                <dt>Goal</dt>
                <dd>{context.goal}</dd>
              </>
            )}
            {context.task && (
              <>
                <dt>Task</dt>
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
            Pending Approvals ({agentPending.length})
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
                    Approve
                  </button>
                  <button
                    className={`${styles.actionBtn} ${styles.denyBtn}`}
                    onClick={() =>
                      denyMutation.mutate({ id: req.id })
                    }
                    disabled={denyMutation.isPending}
                  >
                    Deny
                  </button>
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* Output log */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Output</h2>
        <div className={styles.outputArea}>
          {outputLines && outputLines.length > 0 ? (
            outputLines.map((line, i) => (
              <div key={i} className={styles.outputLine}>
                {escapeHtml(line)}
              </div>
            ))
          ) : (
            <div className={styles.outputEmpty}>No output available.</div>
          )}
          <div ref={outputEndRef} />
        </div>
      </section>

      {/* Input form */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>Send Input</h2>
        <div className={styles.inputForm}>
          <input
            type="text"
            className={styles.inputField}
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a message to send to the agent..."
            disabled={sendInputMutation.isPending}
          />
          <button
            className={styles.actionBtn}
            onClick={handleSendInput}
            disabled={!inputText.trim() || sendInputMutation.isPending}
          >
            Send
          </button>
        </div>
        {sendInputMutation.isError && (
          <div className={styles.inputError}>
            Failed to send: {sendInputMutation.error.message}
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
