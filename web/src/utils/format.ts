/**
 * Locale-aware formatting utilities.
 *
 * All functions default to the current i18n language when no locale
 * is explicitly provided. Uses the standard Intl APIs for proper
 * locale-specific formatting.
 */

import i18n from "../i18n";

/** Get the current i18n language, defaulting to 'en'. */
function currentLocale(): string {
  return i18n.language || "en";
}

/**
 * Format a date using Intl.DateTimeFormat.
 *
 * @param date - Date string (ISO 8601) or Date object
 * @param locale - BCP 47 locale string; defaults to current i18n language
 * @returns Formatted date string
 */
export function formatDate(date: string | Date, locale?: string): string {
  const d = typeof date === "string" ? new Date(date) : date;
  const loc = locale ?? currentLocale();
  return new Intl.DateTimeFormat(loc, {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(d);
}

/**
 * Format a number using Intl.NumberFormat.
 *
 * @param n - The number to format
 * @param locale - BCP 47 locale string; defaults to current i18n language
 * @returns Formatted number string
 */
export function formatNumber(n: number, locale?: string): string {
  const loc = locale ?? currentLocale();
  return new Intl.NumberFormat(loc).format(n);
}

/**
 * Format a date as a relative time string (e.g., "5 minutes ago").
 *
 * Uses Intl.RelativeTimeFormat with automatic unit selection based
 * on the time difference.
 *
 * @param date - Date string (ISO 8601) or Date object
 * @param locale - BCP 47 locale string; defaults to current i18n language
 * @returns Relative time string
 */
export function formatRelativeTime(date: string | Date, locale?: string): string {
  const d = typeof date === "string" ? new Date(date) : date;
  const loc = locale ?? currentLocale();
  const now = Date.now();
  const diffMs = d.getTime() - now;
  const diffSecs = Math.round(diffMs / 1000);
  const absSecs = Math.abs(diffSecs);

  const rtf = new Intl.RelativeTimeFormat(loc, { numeric: "auto" });

  if (absSecs < 60) {
    return rtf.format(diffSecs, "second");
  }
  const diffMins = Math.round(diffMs / 60_000);
  const absMins = Math.abs(diffMins);
  if (absMins < 60) {
    return rtf.format(diffMins, "minute");
  }
  const diffHours = Math.round(diffMs / 3_600_000);
  const absHours = Math.abs(diffHours);
  if (absHours < 24) {
    return rtf.format(diffHours, "hour");
  }
  const diffDays = Math.round(diffMs / 86_400_000);
  return rtf.format(diffDays, "day");
}
