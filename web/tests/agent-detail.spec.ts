/**
 * Agent detail page E2E tests.
 *
 * Covers: agent info display, output log, approve/deny workflow,
 * input sending, start/stop controls.
 */

import {
  test,
  expect,
  setupMockApi,
  MOCK_AGENTS,
  MOCK_PENDING,
  MOCK_OUTPUT_LINES,
  MOCK_AGENT_CONTEXT,
} from "./fixtures";

test.describe("Agent Detail", () => {
  test("shows agent info header with name, status, and driver", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/agents/claude-1");

    // Agent name in heading
    await expect(page.locator("h1")).toContainText("claude-1");

    // Status badge should show "Running"
    await expect(page.getByText("Running")).toBeVisible();

    // Driver should be displayed
    await expect(page.getByText("claude_code")).toBeVisible();

    // PID should be displayed (12345 from mock)
    await expect(page.getByText("12345")).toBeVisible();
  });

  test("renders output log in monospace area", async ({ page, mockApi }) => {
    await page.goto("/agents/claude-1");

    // Wait for output section to render
    await expect(page.getByText("Output")).toBeVisible();

    // Verify output lines appear
    for (const line of MOCK_OUTPUT_LINES) {
      await expect(page.getByText(line)).toBeVisible();
    }
  });

  test("approve button sends API request with correct ID", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/agents/claude-1");

    // Wait for pending section to appear (claude-1 has 2 pending)
    await expect(page.getByText(/Pending Approvals/)).toBeVisible();

    // Click the first Approve button
    const approveButtons = page.getByRole("button", { name: "Approve" });
    await approveButtons.first().click();

    // Verify the approve API was called
    const approveCalls = mockApi.callsMatching("POST", "/v1/pending/");
    expect(approveCalls.length).toBeGreaterThanOrEqual(1);
    const approveCall = approveCalls.find((c) => c.url.includes("/approve"));
    expect(approveCall).toBeDefined();
    expect(approveCall!.url).toContain("aaaaaaaa");
  });

  test("deny button sends API request", async ({ page, mockApi }) => {
    await page.goto("/agents/claude-1");

    // Wait for pending section
    await expect(page.getByText(/Pending Approvals/)).toBeVisible();

    // Click the first Deny button
    const denyButtons = page.getByRole("button", { name: "Deny" });
    await denyButtons.first().click();

    // Verify the deny API was called
    const denyCalls = mockApi.callsMatching("POST", "/deny");
    expect(denyCalls.length).toBeGreaterThanOrEqual(1);
  });

  test("send input submits text via API", async ({ page, mockApi }) => {
    await page.goto("/agents/claude-1");

    // Find the input field
    const inputField = page.getByPlaceholder(
      "Type a message to send to the agent...",
    );
    await expect(inputField).toBeVisible();

    // Type a message and click Send
    await inputField.fill("run tests");
    await page.getByRole("button", { name: "Send" }).click();

    // Verify the input API was called
    const inputCalls = mockApi.callsMatching("POST", "/v1/input");
    expect(inputCalls.length).toBe(1);
    expect(inputCalls[0]!.body).toEqual({ text: "run tests" });
  });

  test("start and stop buttons call correct API endpoints", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/agents/claude-1");

    // Click Start
    await page.getByRole("button", { name: "Start" }).click();
    const startCalls = mockApi.callsMatching("POST", "/start");
    expect(startCalls.length).toBe(1);
    expect(startCalls[0]!.url).toContain("/agents/claude-1/start");

    // Click Stop
    await page.getByRole("button", { name: "Stop" }).click();
    const stopCalls = mockApi.callsMatching("POST", "/stop");
    expect(stopCalls.length).toBe(1);
    expect(stopCalls[0]!.url).toContain("/agents/claude-1/stop");
  });

  test("displays agent context section when available", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/agents/claude-1");

    // Context section should show role, goal, task
    await expect(page.getByText("Context")).toBeVisible();
    await expect(page.getByText("Code reviewer")).toBeVisible();
    await expect(page.getByText("Review pull request #42")).toBeVisible();
    await expect(
      page.getByText("Check for security vulnerabilities"),
    ).toBeVisible();
  });
});
