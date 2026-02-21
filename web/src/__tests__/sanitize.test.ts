/**
 * Tests for HTML sanitization utilities.
 *
 * These tests verify that agent output is properly escaped to prevent XSS.
 * This is a critical security boundary -- agent output can contain
 * arbitrary text including malicious HTML/script payloads.
 */

import { describe, expect, it } from "vitest";

import { escapeHtml, stripHtmlTags } from "../sanitize";

describe("escapeHtml", () => {
  it("escapes ampersands", () => {
    expect(escapeHtml("a & b")).toBe("a &amp; b");
  });

  it("escapes angle brackets", () => {
    expect(escapeHtml("<div>hello</div>")).toBe(
      "&lt;div&gt;hello&lt;&#x2F;div&gt;",
    );
  });

  it("escapes double quotes", () => {
    expect(escapeHtml('key="value"')).toBe("key=&quot;value&quot;");
  });

  it("escapes single quotes", () => {
    expect(escapeHtml("it's")).toBe("it&#x27;s");
  });

  it("escapes forward slashes", () => {
    expect(escapeHtml("path/to/file")).toBe("path&#x2F;to&#x2F;file");
  });

  it("escapes backticks", () => {
    expect(escapeHtml("use `code`")).toBe("use &#96;code&#96;");
  });

  it("returns empty string unchanged", () => {
    expect(escapeHtml("")).toBe("");
  });

  it("returns safe text unchanged", () => {
    expect(escapeHtml("hello world 123")).toBe("hello world 123");
  });

  it("escapes multiple entities in one string", () => {
    expect(escapeHtml('<img src="x" onerror="alert(1)">')).toBe(
      "&lt;img src=&quot;x&quot; onerror=&quot;alert(1)&quot;&gt;",
    );
  });

  // -----------------------------------------------------------------------
  // XSS prevention tests
  // -----------------------------------------------------------------------

  it("prevents script tag injection", () => {
    const malicious = '<script>document.cookie</script>';
    const escaped = escapeHtml(malicious);
    expect(escaped).not.toContain("<script>");
    expect(escaped).not.toContain("</script>");
    expect(escaped).toContain("&lt;script&gt;");
  });

  it("prevents event handler injection", () => {
    const malicious = '<img src=x onerror=alert(1)>';
    const escaped = escapeHtml(malicious);
    expect(escaped).not.toContain("<img");
    expect(escaped).toContain("&lt;img");
  });

  it("prevents javascript: URI injection", () => {
    const malicious = '<a href="javascript:alert(1)">click</a>';
    const escaped = escapeHtml(malicious);
    expect(escaped).not.toContain("<a ");
    expect(escaped).not.toContain("javascript:");
    // The colon is not escaped but the whole tag structure is broken
    expect(escaped).toContain("&lt;a href=&quot;javascript");
  });

  it("prevents nested encoding attacks", () => {
    const malicious = "&lt;script&gt;alert(1)&lt;/script&gt;";
    const escaped = escapeHtml(malicious);
    // The & in &lt; gets escaped to &amp;lt;
    expect(escaped).toContain("&amp;lt;");
  });

  it("handles null bytes safely", () => {
    const malicious = "hello\x00world";
    const escaped = escapeHtml(malicious);
    // Null byte preserved as-is (not a valid HTML entity attack vector)
    expect(escaped).toBe("hello\x00world");
  });

  it("handles unicode safely", () => {
    const input = "Hello \u{1F600} World";
    const escaped = escapeHtml(input);
    expect(escaped).toBe("Hello \u{1F600} World");
  });

  it("escapes very long strings", () => {
    const malicious = "<script>".repeat(10000);
    const escaped = escapeHtml(malicious);
    expect(escaped).not.toContain("<script>");
    expect(escaped.length).toBeGreaterThan(malicious.length);
  });
});

describe("stripHtmlTags", () => {
  it("strips simple tags", () => {
    expect(stripHtmlTags("<b>bold</b>")).toBe("bold");
  });

  it("strips self-closing tags", () => {
    expect(stripHtmlTags("text<br/>more")).toBe("textmore");
  });

  it("strips tags with attributes", () => {
    expect(stripHtmlTags('<a href="http://evil.com">click</a>')).toBe("click");
  });

  it("returns plain text unchanged", () => {
    expect(stripHtmlTags("hello world")).toBe("hello world");
  });

  it("handles empty string", () => {
    expect(stripHtmlTags("")).toBe("");
  });
});
