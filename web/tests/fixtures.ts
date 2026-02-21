/**
 * Custom Playwright test fixtures for Aegis E2E tests.
 *
 * Provides:
 * - mockApi: intercepts all /v1/* API calls with configurable responses
 * - Auth token pre-configured in localStorage
 * - Pre-built mock data matching the Aegis API types
 */

import { test as base, type Page, type Route } from "@playwright/test";

// ---------------------------------------------------------------------------
// Mock data matching aegis-control API response shapes
// ---------------------------------------------------------------------------

export interface MockAgent {
  name: string;
  status: string | Record<string, unknown>;
  pending_count: number;
  uptime_secs: number;
  driver: string;
  enabled: boolean;
}

export interface MockPendingRequest {
  id: string;
  raw_prompt: string;
  agent_name: string;
  risk_level: string | null;
  timeout_at: string;
  approval_count: number;
  require_approvals: number;
  delegated_to: string | null;
}

/** Three agents in various states for standard mock scenarios. */
export const MOCK_AGENTS: MockAgent[] = [
  {
    name: "claude-1",
    status: { Running: { pid: 12345 } },
    pending_count: 2,
    uptime_secs: 3600,
    driver: "claude_code",
    enabled: true,
  },
  {
    name: "codex-agent",
    status: "Pending",
    pending_count: 0,
    uptime_secs: 120,
    driver: "generic",
    enabled: true,
  },
  {
    name: "test-agent",
    status: { Stopped: { exit_code: 0 } },
    pending_count: 1,
    uptime_secs: 0,
    driver: "claude_code",
    enabled: false,
  },
];

/** Three pending requests with varying risk levels. */
export const MOCK_PENDING: MockPendingRequest[] = [
  {
    id: "aaaaaaaa-1111-2222-3333-444444444444",
    raw_prompt: "Execute: rm -rf /tmp/build",
    agent_name: "claude-1",
    risk_level: "high",
    timeout_at: "2026-02-21T12:00:00Z",
    approval_count: 0,
    require_approvals: 1,
    delegated_to: null,
  },
  {
    id: "bbbbbbbb-1111-2222-3333-444444444444",
    raw_prompt: "Read file: /etc/passwd",
    agent_name: "claude-1",
    risk_level: "critical",
    timeout_at: "2026-02-21T12:00:00Z",
    approval_count: 0,
    require_approvals: 1,
    delegated_to: null,
  },
  {
    id: "cccccccc-1111-2222-3333-444444444444",
    raw_prompt: "List directory: ./src",
    agent_name: "test-agent",
    risk_level: "low",
    timeout_at: "2026-02-21T12:00:00Z",
    approval_count: 1,
    require_approvals: 2,
    delegated_to: "admin",
  },
];

/** Sample output lines for agent detail view. */
export const MOCK_OUTPUT_LINES: string[] = [
  "Starting task...",
  "Reading project structure",
  "Found 42 files to analyze",
  "Processing src/main.rs",
  "Analysis complete.",
];

/** Agent context for the detail view. */
export const MOCK_AGENT_CONTEXT = {
  role: "Code reviewer",
  goal: "Review pull request #42",
  context: null,
  task: "Check for security vulnerabilities",
};

// ---------------------------------------------------------------------------
// API response builder
// ---------------------------------------------------------------------------

function okResponse(data?: unknown) {
  return {
    ok: true,
    message: "ok",
    data,
  };
}

function errorResponse(message: string) {
  return {
    ok: false,
    message,
  };
}

// ---------------------------------------------------------------------------
// Mock API handler
// ---------------------------------------------------------------------------

export interface MockApiOptions {
  agents?: MockAgent[] | null;
  pending?: MockPendingRequest[] | null;
  output?: string[] | null;
  context?: Record<string, unknown> | null;
  /** If true, all GET endpoints return 500 errors. */
  errorMode?: boolean;
}

/**
 * Set up route interception for all Aegis API endpoints.
 * Returns a tracker object for verifying which endpoints were called.
 */
export async function setupMockApi(
  page: Page,
  options: MockApiOptions = {},
) {
  const {
    agents = MOCK_AGENTS,
    pending = MOCK_PENDING,
    output = MOCK_OUTPUT_LINES,
    context = MOCK_AGENT_CONTEXT,
    errorMode = false,
  } = options;

  const calls: { method: string; url: string; headers: Record<string, string>; body?: unknown }[] = [];

  async function recordCall(route: Route) {
    const request = route.request();
    const allHeaders = await request.allHeaders();
    let body: unknown = undefined;
    try {
      body = request.postDataJSON();
    } catch {
      // No body or not JSON
    }
    calls.push({
      method: request.method(),
      url: request.url(),
      headers: allHeaders,
      body,
    });
  }

  // GET /v1/agents
  await page.route("**/v1/agents", async (route) => {
    if (route.request().method() !== "GET") {
      await route.fallback();
      return;
    }
    await recordCall(route);
    if (errorMode) {
      await route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify(errorResponse("Internal server error")),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(okResponse(agents)),
    });
  });

  // GET /v1/agents/:name/context
  await page.route("**/v1/agents/*/context", async (route) => {
    await recordCall(route);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(okResponse(context)),
    });
  });

  // POST /v1/agents/:name/start
  await page.route("**/v1/agents/*/start", async (route) => {
    await recordCall(route);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(okResponse()),
    });
  });

  // POST /v1/agents/:name/stop
  await page.route("**/v1/agents/*/stop", async (route) => {
    await recordCall(route);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(okResponse()),
    });
  });

  // POST /v1/agents/:name/restart
  await page.route("**/v1/agents/*/restart", async (route) => {
    await recordCall(route);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(okResponse()),
    });
  });

  // GET /v1/pending
  await page.route("**/v1/pending", async (route) => {
    if (route.request().method() === "GET") {
      await recordCall(route);
      if (errorMode) {
        await route.fulfill({
          status: 500,
          contentType: "application/json",
          body: JSON.stringify(errorResponse("Internal server error")),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(okResponse(pending)),
      });
      return;
    }
    await route.fallback();
  });

  // POST /v1/pending/:id/approve
  await page.route("**/v1/pending/*/approve", async (route) => {
    await recordCall(route);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(okResponse()),
    });
  });

  // POST /v1/pending/:id/deny
  await page.route("**/v1/pending/*/deny", async (route) => {
    await recordCall(route);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(okResponse()),
    });
  });

  // GET /v1/output
  await page.route("**/v1/output*", async (route) => {
    await recordCall(route);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(okResponse(output)),
    });
  });

  // POST /v1/input
  await page.route("**/v1/input", async (route) => {
    await recordCall(route);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(okResponse()),
    });
  });

  return {
    /** All recorded API calls in order. */
    calls,
    /** Filter calls by URL pattern. */
    callsTo(pattern: string) {
      return calls.filter((c) => c.url.includes(pattern));
    },
    /** Filter calls by HTTP method and URL pattern. */
    callsMatching(method: string, pattern: string) {
      return calls.filter(
        (c) => c.method === method && c.url.includes(pattern),
      );
    },
  };
}

// ---------------------------------------------------------------------------
// Custom test fixture
// ---------------------------------------------------------------------------

const AUTH_TOKEN = "test-auth-token-e2e-1234567890";

type AegisFixtures = {
  /** Set up mock API routes and auth token before each test. */
  mockApi: Awaited<ReturnType<typeof setupMockApi>>;
};

/**
 * Extended Playwright test with Aegis-specific fixtures.
 *
 * Usage:
 *   import { test, expect } from "./fixtures";
 *   test("my test", async ({ page, mockApi }) => { ... });
 */
export const test = base.extend<AegisFixtures>({
  mockApi: async ({ page }, use) => {
    // Set auth token in localStorage before navigating
    await page.addInitScript((token) => {
      localStorage.setItem("aegis_auth_token", token);
    }, AUTH_TOKEN);

    const api = await setupMockApi(page);
    await use(api);
  },
});

export { expect } from "@playwright/test";
export { AUTH_TOKEN };
