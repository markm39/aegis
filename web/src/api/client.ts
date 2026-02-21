/**
 * API client for the Aegis daemon HTTP control plane.
 *
 * Security measures:
 * - Auth token sent via Authorization: Bearer header, never in URL params
 * - X-Request-ID header on all state-changing (POST) requests
 * - Response structure validated before use
 * - No dynamic code execution of any kind
 */

import {
  type AgentContext,
  type AgentInfo,
  type CommandResponse,
  type PendingRequest,
  isCommandResponse,
} from "./types";

const AUTH_TOKEN_KEY = "aegis_auth_token";

/** Base URL for API requests. Defaults to http://localhost:3100. */
function getBaseUrl(): string {
  // Vite injects import.meta.env at build time. Fall back for test environments.
  try {
    return import.meta.env.VITE_API_URL || "http://localhost:3100";
  } catch {
    return "http://localhost:3100";
  }
}

/** Generate a random request ID for CSRF protection on POST requests. */
function generateRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---------------------------------------------------------------------------
// Token management
// ---------------------------------------------------------------------------

/** Store the auth token in localStorage. */
export function setAuthToken(token: string): void {
  localStorage.setItem(AUTH_TOKEN_KEY, token);
}

/** Retrieve the stored auth token. */
export function getAuthToken(): string | null {
  return localStorage.getItem(AUTH_TOKEN_KEY);
}

/** Clear the stored auth token (logout). */
export function clearAuthToken(): void {
  localStorage.removeItem(AUTH_TOKEN_KEY);
}

// ---------------------------------------------------------------------------
// Core request helpers
// ---------------------------------------------------------------------------

/** Build headers for a request. POST requests include X-Request-ID. */
function buildHeaders(method: "GET" | "POST"): HeadersInit {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  const token = getAuthToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  if (method === "POST") {
    headers["X-Request-ID"] = generateRequestId();
  }

  return headers;
}

/** Error thrown when the API returns an error response. */
export class ApiError extends Error {
  public readonly status: number;
  public readonly response: CommandResponse;

  constructor(status: number, response: CommandResponse) {
    super(response.message);
    this.name = "ApiError";
    this.status = status;
    this.response = response;
  }
}

/**
 * Perform a GET request to the API.
 * Validates that the response matches CommandResponse shape.
 */
async function apiGet(path: string): Promise<CommandResponse> {
  const url = `${getBaseUrl()}${path}`;
  const res = await fetch(url, {
    method: "GET",
    headers: buildHeaders("GET"),
  });

  const body: unknown = await res.json();

  if (!isCommandResponse(body)) {
    throw new ApiError(res.status, {
      ok: false,
      message: "Invalid response structure from server",
    });
  }

  if (!body.ok) {
    throw new ApiError(res.status, body);
  }

  return body;
}

/**
 * Perform a POST request to the API.
 * Includes X-Request-ID header for CSRF protection.
 * Validates that the response matches CommandResponse shape.
 */
async function apiPost(
  path: string,
  body?: unknown,
): Promise<CommandResponse> {
  const url = `${getBaseUrl()}${path}`;
  const res = await fetch(url, {
    method: "POST",
    headers: buildHeaders("POST"),
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  const responseBody: unknown = await res.json();

  if (!isCommandResponse(responseBody)) {
    throw new ApiError(res.status, {
      ok: false,
      message: "Invalid response structure from server",
    });
  }

  if (!responseBody.ok) {
    throw new ApiError(res.status, responseBody);
  }

  return responseBody;
}

// ---------------------------------------------------------------------------
// Fleet-level endpoints
// ---------------------------------------------------------------------------

/** GET /v1/agents - list all agents in the fleet. */
export async function listAgents(): Promise<AgentInfo[]> {
  const resp = await apiGet("/v1/agents");
  if (!Array.isArray(resp.data)) {
    return [];
  }
  return resp.data as AgentInfo[];
}

/** GET /v1/agents/:name/context - get agent context. */
export async function getAgentContext(name: string): Promise<AgentContext> {
  const resp = await apiGet(`/v1/agents/${encodeURIComponent(name)}/context`);
  return (resp.data ?? { role: null, goal: null, context: null, task: null }) as AgentContext;
}

/** POST /v1/agents/:name/start - start an agent. */
export async function startAgent(name: string): Promise<CommandResponse> {
  return apiPost(`/v1/agents/${encodeURIComponent(name)}/start`);
}

/** POST /v1/agents/:name/stop - stop an agent. */
export async function stopAgent(name: string): Promise<CommandResponse> {
  return apiPost(`/v1/agents/${encodeURIComponent(name)}/stop`);
}

/** POST /v1/agents/:name/restart - restart an agent. */
export async function restartAgent(name: string): Promise<CommandResponse> {
  return apiPost(`/v1/agents/${encodeURIComponent(name)}/restart`);
}

// ---------------------------------------------------------------------------
// Pilot-level endpoints (single-agent or fleet-proxied)
// ---------------------------------------------------------------------------

/** GET /v1/status - get pilot status (includes pending info). */
export async function getStatus(): Promise<CommandResponse> {
  return apiGet("/v1/status");
}

/** GET /v1/output - get recent agent output lines. */
export async function getOutput(lines?: number): Promise<string[]> {
  const query = lines !== undefined ? `?lines=${lines}` : "";
  const resp = await apiGet(`/v1/output${query}`);
  if (!Array.isArray(resp.data)) {
    return [];
  }
  return resp.data as string[];
}

/** GET /v1/pending - get pending permission requests. */
export async function listPending(): Promise<PendingRequest[]> {
  const resp = await apiGet("/v1/pending");
  // The pending endpoint returns status which includes pending data
  if (resp.data && typeof resp.data === "object" && !Array.isArray(resp.data)) {
    const data = resp.data as Record<string, unknown>;
    if (Array.isArray(data["pending"])) {
      return data["pending"] as PendingRequest[];
    }
  }
  if (Array.isArray(resp.data)) {
    return resp.data as PendingRequest[];
  }
  return [];
}

/** POST /v1/pending/:id/approve - approve a pending request. */
export async function approveRequest(id: string): Promise<CommandResponse> {
  return apiPost(`/v1/pending/${encodeURIComponent(id)}/approve`);
}

/** POST /v1/pending/:id/deny - deny a pending request. */
export async function denyRequest(
  id: string,
  reason?: string,
): Promise<CommandResponse> {
  return apiPost(`/v1/pending/${encodeURIComponent(id)}/deny`, reason ? { reason } : undefined);
}

/** POST /v1/input - send text input to agent stdin. */
export async function sendInput(text: string): Promise<CommandResponse> {
  return apiPost("/v1/input", { text });
}

/** POST /v1/config/reload - reload daemon configuration. */
export async function reloadConfig(): Promise<CommandResponse> {
  return apiPost("/v1/config/reload");
}
