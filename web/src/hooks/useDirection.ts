/**
 * Hook to manage text direction (LTR/RTL) based on the current i18n language.
 *
 * Sets document.documentElement.dir and document.documentElement.lang
 * whenever the language changes.
 *
 * RTL languages: Arabic (ar), Hebrew (he).
 */

import { useEffect } from "react";
import { useTranslation } from "react-i18next";

/** Languages that use right-to-left text direction. */
const RTL_LANGUAGES = new Set(["ar", "he"]);

export type Direction = "rtl" | "ltr";

/**
 * Returns the text direction for the current language and
 * keeps document attributes in sync.
 */
export function useDirection(): Direction {
  const { i18n } = useTranslation();
  const language = i18n.language;
  const direction: Direction = RTL_LANGUAGES.has(language) ? "rtl" : "ltr";

  useEffect(() => {
    document.documentElement.dir = direction;
    document.documentElement.lang = language;
  }, [direction, language]);

  return direction;
}

/**
 * Pure function to determine direction for a given language code.
 * Useful outside of React component context.
 */
export function getDirection(language: string): Direction {
  return RTL_LANGUAGES.has(language) ? "rtl" : "ltr";
}
