/**
 * i18next configuration for internationalization.
 *
 * Language detection order:
 * 1. localStorage key 'aegis-language'
 * 2. Browser navigator.language
 * 3. Fallback to 'en'
 *
 * Security: escapeValue is true (i18next default) to prevent XSS
 * through interpolated values. Do not disable this.
 */

import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

import ar from "./locales/ar.json";
import de from "./locales/de.json";
import en from "./locales/en.json";
import es from "./locales/es.json";
import fr from "./locales/fr.json";
import ja from "./locales/ja.json";
import zh from "./locales/zh.json";

/** All supported locale codes. */
export const SUPPORTED_LOCALES = ["en", "es", "fr", "de", "ja", "zh", "ar"] as const;
export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];

/** Human-readable native names for each supported locale. */
export const LOCALE_NAMES: Record<SupportedLocale, string> = {
  en: "English",
  es: "Espanol",
  fr: "Francais",
  de: "Deutsch",
  ja: "\u65e5\u672c\u8a9e",
  zh: "\u4e2d\u6587",
  ar: "\u0627\u0644\u0639\u0631\u0628\u064a\u0629",
};

/** localStorage key for persisted language preference. */
export const LANGUAGE_STORAGE_KEY = "aegis-language";

/** Check whether a string is a supported locale code. */
export function isSupportedLocale(code: string): code is SupportedLocale {
  return (SUPPORTED_LOCALES as readonly string[]).includes(code);
}

const resources = {
  en: { translation: en },
  es: { translation: es },
  fr: { translation: fr },
  de: { translation: de },
  ja: { translation: ja },
  zh: { translation: zh },
  ar: { translation: ar },
};

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: "en",
    supportedLngs: [...SUPPORTED_LOCALES],
    detection: {
      order: ["localStorage", "navigator"],
      lookupLocalStorage: LANGUAGE_STORAGE_KEY,
      caches: ["localStorage"],
    },
    interpolation: {
      // escapeValue: true is the default -- explicitly stated for security clarity.
      // This ensures interpolated values like {{name}} are HTML-escaped.
      escapeValue: true,
    },
    react: {
      useSuspense: false,
    },
  });

export default i18n;
