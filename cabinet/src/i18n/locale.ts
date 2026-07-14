// Locale resolution (spec `issuer-cabinet` — "Локализация кабинета") and
// lookup. Pure functions: no DOM, no `navigator`/`location` reads happen
// here — the caller passes in whatever it read, which is what makes this
// testable without a browser.

import { type Dict, type DictKey, en, ru } from "./dict.ts";

export type Locale = "ru" | "en";

const dictionaries: Record<Locale, Dict> = { en, ru };

/** Look up `key` in `locale`'s dictionary. */
export function t(locale: Locale, key: DictKey): string {
  return dictionaries[locale][key];
}

/**
 * The scenario "Кабинет в русской локали" resolves to `ru` when the browser
 * reports a language starting with `ru` (case-insensitive), matching the CLI
 * agent's own prefix rule (`docs/ru/issuer.md`, "Локализация"). Any other
 * value, or no value, falls back to English — the caller then applies the
 * domain default (see {@link domainDefaultLocale}) before this fallback.
 */
export function localeFromLanguageTag(tag: string | undefined | null): Locale | undefined {
  if (!tag) return undefined;
  return tag.trim().toLowerCase().startsWith("ru") ? "ru" : undefined;
}

/**
 * D13: default language by hosting domain — `*.ru` hosts (including
 * `issuer.tessera-access.ru`) default to Russian; everything else, including
 * `file://` self-hosted deployments, defaults via the browser-language and
 * English fallback instead.
 */
export function domainDefaultLocale(hostname: string): Locale | undefined {
  return hostname.toLowerCase().endsWith(".ru") ? "ru" : undefined;
}

/**
 * Resolve the effective locale, highest priority first: an explicit
 * operator choice (the in-UI switcher, persisted across the session) beats
 * the hosting domain's default, which beats the browser's reported
 * language, which falls back to English.
 */
export function resolveLocale(input: {
  explicit?: Locale | undefined;
  hostname: string;
  browserLanguage: string | undefined | null;
}): Locale {
  return (
    input.explicit ??
    domainDefaultLocale(input.hostname) ??
    localeFromLanguageTag(input.browserLanguage) ??
    "en"
  );
}
