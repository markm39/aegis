/**
 * Security-focused E2E tests.
 *
 * Validates: auth headers, XSS prevention, CSP meta tag,
 * inline script absence, agent name sanitization, request IDs.
 */

import { test, expect, setupMockApi, AUTH_TOKEN } from "./fixtures";

test.describe("Security", () => {
  test("sends Bearer auth token in Authorization header", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/");

    // Wait for at least one API call
    await expect(page.locator("table")).toBeVisible();

    // Check that the agents API call included the auth header
    const agentCalls = mockApi.callsTo("/v1/agents");
    expect(agentCalls.length).toBeGreaterThan(0);
    expect(agentCalls[0]!.headers["authorization"]).toBe(
      `Bearer ${AUTH_TOKEN}`,
    );
  });

  test("XSS in agent output is escaped in DOM", async ({ page }) => {
    const xssPayload = '<script>alert("xss")</script>';

    await page.addInitScript(() => {
      localStorage.setItem("aegis_auth_token", "test-token");
    });

    await setupMockApi(page, {
      output: [xssPayload, "normal line"],
    });

    await page.goto("/agents/claude-1");

    // The script tag text should be visible as escaped text, not executed
    await expect(page.getByText("normal line")).toBeVisible();

    // Verify no actual <script> elements were injected into the DOM
    const scriptElements = await page.locator("script[src]").count();
    const inlineScripts = await page.evaluate(() => {
      return Array.from(document.querySelectorAll("script")).filter(
        (s) =>
          !s.src &&
          !s.type?.includes("module") &&
          s.textContent?.includes("alert"),
      ).length;
    });
    expect(inlineScripts).toBe(0);

    // The raw HTML should appear as text content, not as a rendered element
    const bodyHtml = await page.content();
    expect(bodyHtml).not.toContain("<script>alert");
  });

  test("CSP meta tag is present in page head", async ({ page, mockApi }) => {
    await page.goto("/");

    const cspMeta = page.locator(
      'meta[http-equiv="Content-Security-Policy"]',
    );
    await expect(cspMeta).toHaveCount(1);

    const cspContent = await cspMeta.getAttribute("content");
    expect(cspContent).toBeTruthy();
    // Verify key CSP directives
    expect(cspContent).toContain("default-src 'self'");
    expect(cspContent).toContain("script-src 'self'");
    expect(cspContent).toContain("object-src 'none'");
    expect(cspContent).toContain("frame-ancestors 'none'");
  });

  test("no inline scripts in page source", async ({ page, mockApi }) => {
    await page.goto("/");

    // Only the module script for Vite entry point should exist
    const allScripts = await page.locator("script").all();
    for (const script of allScripts) {
      const type = await script.getAttribute("type");
      const src = await script.getAttribute("src");
      const content = await script.textContent();

      // Scripts should either be type="module" with src, or empty
      if (content && content.trim().length > 0) {
        expect(type).toBe("module");
      }
    }
  });

  test("HTML in agent names is escaped in the DOM", async ({ page }) => {
    const maliciousAgent = {
      name: '<img src=x onerror="alert(1)">',
      status: { Running: { pid: 99999 } },
      pending_count: 0,
      uptime_secs: 60,
      driver: "generic",
      enabled: true,
    };

    await page.addInitScript(() => {
      localStorage.setItem("aegis_auth_token", "test-token");
    });

    await setupMockApi(page, { agents: [maliciousAgent] });

    await page.goto("/");

    // Wait for the table to render
    await expect(page.locator("table tbody tr")).toHaveCount(1);

    // The malicious name should appear as text, not as a rendered img element
    const imgCount = await page.locator("table img").count();
    expect(imgCount).toBe(0);

    // The text should be visible as escaped content
    const cellText = await page.locator("table tbody tr td").first().textContent();
    expect(cellText).toContain("<img");
  });

  test("X-Request-ID header present on POST requests", async ({
    page,
    mockApi,
  }) => {
    await page.goto("/agents/claude-1");

    // Trigger a POST by clicking Start
    await page.getByRole("button", { name: "Start" }).click();

    // Check that the POST call has X-Request-ID
    const postCalls = mockApi.callsMatching("POST", "/start");
    expect(postCalls.length).toBeGreaterThanOrEqual(1);
    const requestId = postCalls[0]!.headers["x-request-id"];
    expect(requestId).toBeTruthy();
    // Should be a 32-char hex string (16 bytes)
    expect(requestId).toMatch(/^[0-9a-f]{32}$/);
  });
});
