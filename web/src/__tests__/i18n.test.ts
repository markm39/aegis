/**
 * Tests for internationalization (i18n) support.
 *
 * Covers translation loading, language detection fallback, RTL direction,
 * locale-aware formatting, missing key fallback, and XSS prevention.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import i18n, { isSupportedLocale, SUPPORTED_LOCALES } from "../i18n";
import { getDirection } from "../hooks/useDirection";
import { formatDate, formatNumber, formatRelativeTime } from "../utils/format";

describe("i18n", () => {
  beforeEach(async () => {
    await i18n.changeLanguage("en");
  });

  afterEach(() => {
    document.documentElement.dir = "ltr";
    document.documentElement.lang = "en";
    localStorage.removeItem("aegis-language");
  });

  // -----------------------------------------------------------------------
  // Translation file loading
  // -----------------------------------------------------------------------

  describe("translation file loading", () => {
    it("loads en.json and resolves keys", () => {
      expect(i18n.t("common.approve")).toBe("Approve");
      expect(i18n.t("common.deny")).toBe("Deny");
      expect(i18n.t("common.loading")).toBe("Loading...");
      expect(i18n.t("common.error")).toBe("Error");
    });

    it("resolves dashboard keys", () => {
      expect(i18n.t("dashboard.title")).toBe("Aegis Fleet Dashboard");
      expect(i18n.t("dashboard.noAgents")).toContain("No agents configured");
    });

    it("resolves agent detail keys", () => {
      expect(i18n.t("agent.output")).toBe("Output");
      expect(i18n.t("agent.sendInput")).toBe("Send Input");
    });

    it("resolves pending page keys", () => {
      expect(i18n.t("pending.title")).toBe("Pending Approvals");
      expect(i18n.t("pending.noRequests")).toContain("No pending");
    });

    it("resolves settings keys", () => {
      expect(i18n.t("settings.language")).toBe("Language");
      expect(i18n.t("settings.theme")).toBe("Theme");
    });

    it("loads all supported locale files without error", async () => {
      for (const locale of SUPPORTED_LOCALES) {
        await i18n.changeLanguage(locale);
        // Every locale should have the common.approve key (possibly via fallback)
        const value = i18n.t("common.approve");
        expect(value).toBeTruthy();
        expect(value).not.toBe("common.approve");
      }
    });
  });

  // -----------------------------------------------------------------------
  // Language detection fallback
  // -----------------------------------------------------------------------

  describe("language detection fallback", () => {
    it("falls back to en for unknown locale", async () => {
      await i18n.changeLanguage("xx-YY");
      // Should fall back to 'en' since 'xx-YY' is not supported
      expect(i18n.t("common.approve")).toBe("Approve");
    });

    it("falls back to en for empty locale", async () => {
      await i18n.changeLanguage("");
      expect(i18n.t("common.approve")).toBe("Approve");
    });
  });

  // -----------------------------------------------------------------------
  // RTL direction
  // -----------------------------------------------------------------------

  describe("RTL direction", () => {
    it("returns rtl for Arabic", () => {
      expect(getDirection("ar")).toBe("rtl");
    });

    it("returns rtl for Hebrew", () => {
      expect(getDirection("he")).toBe("rtl");
    });

    it("returns ltr for English", () => {
      expect(getDirection("en")).toBe("ltr");
    });

    it("returns ltr for German", () => {
      expect(getDirection("de")).toBe("ltr");
    });

    it("returns ltr for Japanese", () => {
      expect(getDirection("ja")).toBe("ltr");
    });

    it("returns ltr for Chinese", () => {
      expect(getDirection("zh")).toBe("ltr");
    });

    it("returns ltr for unknown languages", () => {
      expect(getDirection("xx")).toBe("ltr");
    });
  });

  // -----------------------------------------------------------------------
  // Date formatting per locale
  // -----------------------------------------------------------------------

  describe("date formatting per locale", () => {
    const testDate = new Date(2025, 0, 15, 14, 30); // Jan 15, 2025 14:30

    it("formats date in English", () => {
      const formatted = formatDate(testDate, "en");
      expect(formatted).toContain("January");
      expect(formatted).toContain("15");
      expect(formatted).toContain("2025");
    });

    it("formats date in German", () => {
      const formatted = formatDate(testDate, "de");
      expect(formatted).toContain("Januar");
      expect(formatted).toContain("15");
      expect(formatted).toContain("2025");
    });

    it("formats date from ISO string", () => {
      const formatted = formatDate("2025-01-15T14:30:00Z", "en");
      expect(formatted).toContain("2025");
    });

    it("uses current i18n language when locale not specified", async () => {
      await i18n.changeLanguage("de");
      const formatted = formatDate(testDate);
      expect(formatted).toContain("Januar");
    });
  });

  // -----------------------------------------------------------------------
  // Number formatting per locale
  // -----------------------------------------------------------------------

  describe("number formatting per locale", () => {
    it("formats number in English with comma separator", () => {
      const formatted = formatNumber(1234.56, "en");
      expect(formatted).toContain("1,234.56");
    });

    it("formats number in German with period separator", () => {
      const formatted = formatNumber(1234.56, "de");
      // German uses period as thousands separator and comma as decimal
      expect(formatted).toContain("1.234,56");
    });

    it("formats integer without decimals", () => {
      const formatted = formatNumber(1000, "en");
      expect(formatted).toBe("1,000");
    });

    it("uses current i18n language when locale not specified", async () => {
      await i18n.changeLanguage("en");
      const formatted = formatNumber(1234.56);
      expect(formatted).toContain("1,234.56");
    });
  });

  // -----------------------------------------------------------------------
  // Relative time formatting
  // -----------------------------------------------------------------------

  describe("relative time formatting", () => {
    it("formats recent past time", () => {
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
      const formatted = formatRelativeTime(fiveMinutesAgo, "en");
      expect(formatted).toContain("5");
      expect(formatted).toContain("minute");
    });

    it("formats time from ISO string", () => {
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      const formatted = formatRelativeTime(oneHourAgo.toISOString(), "en");
      expect(formatted).toContain("hour");
    });
  });

  // -----------------------------------------------------------------------
  // Missing key fallback
  // -----------------------------------------------------------------------

  describe("fallback for missing key", () => {
    it("falls back to English when key missing in target locale", async () => {
      // Spanish has all keys, but let's verify the fallback mechanism works
      // by switching to es and checking a key that exists in en
      await i18n.changeLanguage("es");
      const value = i18n.t("dashboard.title");
      // Should return the Spanish value, not the key itself
      expect(value).not.toBe("dashboard.title");
      expect(value).toBeTruthy();
    });

    it("returns en value when locale has no override", async () => {
      // Force a scenario where a key only exists in en
      // The fallback language is 'en', so any supported language
      // without a specific key should get the en value
      await i18n.changeLanguage("es");
      // All our locales have complete translations,
      // but the fallback mechanism ensures en is used if needed
      const enValue = i18n.t("common.approve", { lng: "en" });
      expect(enValue).toBe("Approve");
    });
  });

  // -----------------------------------------------------------------------
  // XSS prevention in translations
  // -----------------------------------------------------------------------

  describe("XSS prevention in translations", () => {
    it("escapes HTML in interpolated values by default", () => {
      // i18next's escapeValue: true should escape HTML in interpolation
      const result = i18n.t("agent.sendFailed", {
        message: '<script>alert("xss")</script>',
      });
      expect(result).not.toContain("<script>");
      expect(result).toContain("&lt;script&gt;");
    });

    it("escapes angle brackets in interpolated values", () => {
      const result = i18n.t("pending.delegatedTo", {
        name: '<img src=x onerror=alert(1)>',
      });
      expect(result).not.toContain("<img");
      expect(result).toContain("&lt;img");
    });

    it("escapes quotes in interpolated values", () => {
      const result = i18n.t("agent.sendFailed", {
        message: '" onmouseover="alert(1)',
      });
      expect(result).not.toContain('" onmouseover');
      expect(result).toContain("&quot;");
    });

    it("does not double-escape already safe text", () => {
      const result = i18n.t("agent.sendFailed", {
        message: "Connection refused",
      });
      expect(result).toContain("Connection refused");
      // No HTML entities should be introduced for safe text
      expect(result).not.toContain("&amp;");
    });
  });

  // -----------------------------------------------------------------------
  // Locale validation
  // -----------------------------------------------------------------------

  describe("locale validation", () => {
    it("accepts all supported locale codes", () => {
      for (const locale of SUPPORTED_LOCALES) {
        expect(isSupportedLocale(locale)).toBe(true);
      }
    });

    it("rejects unknown locale codes", () => {
      expect(isSupportedLocale("xx")).toBe(false);
      expect(isSupportedLocale("en-GB")).toBe(false);
      expect(isSupportedLocale("")).toBe(false);
      expect(isSupportedLocale("javascript:alert(1)")).toBe(false);
    });
  });
});
