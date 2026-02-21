/**
 * Pending approvals page E2E tests.
 *
 * Covers: page load, request rendering, approve/deny actions,
 * risk level badges, empty state.
 */

import {
  test,
  expect,
  setupMockApi,
  MOCK_PENDING,
} from "./fixtures";

test.describe("Pending Approvals", () => {
  test("page loads with title", async ({ page, mockApi }) => {
    await page.goto("/pending");

    await expect(page.locator("h1")).toContainText("Pending Approvals");
  });

  test("shows all pending requests", async ({ page, mockApi }) => {
    await page.goto("/pending");

    // Each pending request displays its prompt text
    await expect(
      page.getByText("Execute: rm -rf /tmp/build"),
    ).toBeVisible();
    await expect(page.getByText("Read file: /etc/passwd")).toBeVisible();
    await expect(page.getByText("List directory: ./src")).toBeVisible();

    // Should show count header "3 pending"
    await expect(page.getByText("3 pending")).toBeVisible();
  });

  test("approve button sends POST to correct endpoint", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/pending");

    // Wait for requests to render
    await expect(
      page.getByText("Execute: rm -rf /tmp/build"),
    ).toBeVisible();

    // Click the first Approve button
    const approveButtons = page.getByRole("button", { name: "Approve" });
    await approveButtons.first().click();

    // Verify API call
    const approveCalls = mockApi.callsMatching("POST", "/approve");
    expect(approveCalls.length).toBeGreaterThanOrEqual(1);
    // First pending request ID starts with "aaaaaaaa"
    expect(approveCalls[0]!.url).toContain("aaaaaaaa");
  });

  test("deny button sends POST to correct endpoint", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/pending");

    await expect(
      page.getByText("Execute: rm -rf /tmp/build"),
    ).toBeVisible();

    // Click the first Deny button
    const denyButtons = page.getByRole("button", { name: "Deny" });
    await denyButtons.first().click();

    // Verify API call
    const denyCalls = mockApi.callsMatching("POST", "/deny");
    expect(denyCalls.length).toBeGreaterThanOrEqual(1);
  });

  test("displays risk level badges with correct values", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/pending");

    // The three pending requests have risk levels: high, critical, low
    await expect(page.getByText("high")).toBeVisible();
    await expect(page.getByText("critical")).toBeVisible();
    await expect(page.getByText("low")).toBeVisible();
  });

  test("shows empty state when no pending requests", async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.setItem("aegis_auth_token", "test-token");
    });

    await setupMockApi(page, { pending: [] });

    await page.goto("/pending");

    await expect(
      page.getByText("No pending approval requests"),
    ).toBeVisible();
  });

  test("shows agent name as link to agent detail", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/pending");

    // Agent names should be links
    const agentLink = page.getByRole("link", { name: "claude-1" }).first();
    await expect(agentLink).toBeVisible();
    await expect(agentLink).toHaveAttribute("href", /\/agents\/claude-1/);
  });

  test("shows approval count progress", async ({ page, mockApi }) => {
    await page.goto("/pending");

    // The third pending request has approval_count: 1, require_approvals: 2
    // so it should show "Approvals: 1/2"
    await expect(page.getByText("Approvals: 1/2")).toBeVisible();
  });
});
