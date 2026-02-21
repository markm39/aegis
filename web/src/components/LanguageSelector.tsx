/**
 * Language selector dropdown component.
 *
 * Displays available languages with their native names. On change:
 * - Updates i18next language
 * - Persists choice to localStorage
 * - Updates document dir/lang attributes for RTL support
 *
 * Only accepts known locale codes to prevent injection of arbitrary values.
 */

import { useCallback } from "react";
import { useTranslation } from "react-i18next";

import {
  isSupportedLocale,
  LANGUAGE_STORAGE_KEY,
  LOCALE_NAMES,
  SUPPORTED_LOCALES,
} from "../i18n";
import { getDirection } from "../hooks/useDirection";

export function LanguageSelector() {
  const { i18n } = useTranslation();

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      const newLang = e.target.value;
      if (!isSupportedLocale(newLang)) {
        return;
      }
      i18n.changeLanguage(newLang);
      localStorage.setItem(LANGUAGE_STORAGE_KEY, newLang);
      document.documentElement.dir = getDirection(newLang);
      document.documentElement.lang = newLang;
    },
    [i18n],
  );

  return (
    <select
      value={i18n.language}
      onChange={handleChange}
      aria-label="Select language"
      style={{
        padding: "4px 8px",
        borderRadius: "4px",
        border: "1px solid #ccc",
        background: "#fff",
        fontSize: "14px",
        cursor: "pointer",
      }}
    >
      {SUPPORTED_LOCALES.map((code) => (
        <option key={code} value={code}>
          {LOCALE_NAMES[code]}
        </option>
      ))}
    </select>
  );
}
