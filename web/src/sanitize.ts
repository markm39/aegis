/**
 * HTML sanitization utilities for agent output.
 *
 * Agent output can contain arbitrary text including HTML-like strings.
 * All agent output MUST be escaped before rendering to prevent XSS.
 *
 * React's JSX text nodes auto-escape, but we provide explicit escapeHtml()
 * for cases where output is processed as strings before rendering, and
 * as a defense-in-depth measure.
 */

/** Map of characters to their HTML entity replacements. */
const HTML_ESCAPE_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#x27;",
  "/": "&#x2F;",
  "`": "&#96;",
};

const HTML_ESCAPE_REGEX = /[&<>"'/`]/g;

/**
 * Escape HTML entities in a string to prevent XSS.
 *
 * Handles: & < > " ' / `
 *
 * This is a pure string transformation -- no DOM parsing or
 * dynamic code execution involved.
 */
export function escapeHtml(input: string): string {
  return input.replace(HTML_ESCAPE_REGEX, (char) => HTML_ESCAPE_MAP[char] ?? char);
}

/**
 * Strip all HTML tags from a string.
 * Used as an additional layer of defense for text-only display contexts.
 */
export function stripHtmlTags(input: string): string {
  return input.replace(/<[^>]*>/g, "");
}
