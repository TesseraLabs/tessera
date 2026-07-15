// The fail-closed startup screen's text (spec-adjacent: a serverless SPA
// that fails silently on a blank page is worse than one that visibly says
// so). `ensureWasmReady()` can reject — CSP blocking `WebAssembly.instantiate`,
// a corrupt/missing `.wasm` artifact, an unsupported browser — and
// `ui/app.ts`'s `start()` must never leave `#app` empty on that path.
//
// This module holds only the pure "what to say" computation (locale + the
// core's technical error → localized title/detail), so it is unit-testable
// without a DOM. The actual `#app` replacement is a few lines of `el(...)`
// calls in `ui/app.ts`, which — like the rest of `ui/*.ts` — needs a real
// DOM and is exercised by the end-to-end run, not this unit suite.

import type { Locale } from "../i18n/locale.ts";
import { t } from "../i18n/locale.ts";

export interface StartupErrorText {
  title: string;
  detail: string;
}

/** Render the localized startup-failure text for `error` (usually `ensureWasmReady()`'s rejection). */
export function startupErrorText(locale: Locale, error: unknown): StartupErrorText {
  const technical = error instanceof Error ? error.message : String(error);
  return {
    title: t(locale, "startup_error_title"),
    detail: `${t(locale, "startup_error_detail")}: ${technical}`,
  };
}
