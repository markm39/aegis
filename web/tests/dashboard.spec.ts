/**
 * Dashboard page E2E tests.
 *
 * Covers: page load, agent rendering, auto-refresh polling,
 * navigation, pending count badges, empty state, error state.
 */

import {
  test,
  expect,
  setupMockApi,
  MOCK_AGENTS,
  MOCK_PENDING,
} from "./fixtures";

test.describe("Dashboard", () => {
  test("page loads with title and agent table visible", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/");

    // Title should render the translated "Aegis Fleet Dashboard"
    await expect(page.locator("h1")).toContainText("Aegis Fleet Dashboard");

    // Agent table should be present
    await expect(page.locator("table")).toBeVisible();
  });

  test("shows all agents with status badges", async ({ page, mockApi }) => {
    await page.goto("/");

    // Wait for agent rows to appear (3 agents in mock data)
    const rows = page.locator("table tbody tr");
    await expect(rows).toHaveCount(3);

    // Verify each agent name is displayed
    for (const agent of MOCK_AGENTS) {
      await expect(page.getByText(agent.name)).toBeVisible();
    }

    // Verify status badges exist -- Running, Pending, Stopped
    await expect(page.getByText("Running")).toBeVisible();
    await expect(page.getByText("Pending")).toBeVisible();
    await expect(page.getByText("Stopped")).toBeVisible();
  });

  test("auto-refreshes agent data after polling interval", async ({
    page,
  }) => {
    // Set up mock with call tracking
    const api = await setupMockApi(page);

    await page.addInitScript(() => {
      localStorage.setItem("aegis_auth_token", "test-token");
    });

    await page.goto("/");

    // Wait for initial load
    await expect(page.locator("table tbody tr")).toHaveCount(3);

    const initialAgentCalls = api.callsTo("/v1/agents").length;

    // Wait for at least one more polling cycle (React Query polls every 5s)
    await page.waitForTimeout(6_000);

    const laterAgentCalls = api.callsTo("/v1/agents").length;
    expect(laterAgentCalls).toBeGreaterThan(initialAgentCalls);
  });

  test("clicking agent row navigates to detail page", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/");

    // Wait for table to render
    await expect(page.locator("table tbody tr")).toHaveCount(3);

    // Click the first agent row (claude-1)
    await page.locator("table tbody tr").first().click();

    // Should navigate to the agent detail page
    await expect(page).toHaveURL(/\/agents\/claude-1/);
  });

  test("shows pending count badge for agents with pending requests", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/");
    await expect(page.locator("table tbody tr")).toHaveCount(3);

    // claude-1 has pending_count: 2, so there should be a "2" badge
    const claude1Row = page.locator("table tbody tr").first();
    await expect(claude1Row).toContainText("2");

    // The header should show a pending approvals link when there are pending items
    // MOCK_PENDING has 3 items, so "3 pending approvals" should appear
    await expect(page.getByText(/pending approval/)).toBeVisible();
  });

  test("shows empty state message when no agents", async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.setItem("aegis_auth_token", "test-token");
    });

    await setupMockApi(page, { agents: [] });

    await page.goto("/");

    // Should show the "no agents" empty state message
    await expect(page.getByText(/No agents configured/)).toBeVisible();
  });

  test("shows error state on API failure", async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.setItem("aegis_auth_token", "test-token");
    });

    await setupMockApi(page, { errorMode: true });

    await page.goto("/");

    // React Query will retry, then show the error. Wait for it.
    await expect(page.getByText(/Connection error/)).toBeVisible({
      timeout: 15_000,
    });
  });
});
