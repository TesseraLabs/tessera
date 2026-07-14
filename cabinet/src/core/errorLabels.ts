// Human-readable rendering of the `{ error, dimension? }` failures every
// WASM binding throws (see `crates/tessera_issuer_wasm/src/error.rs`). The
// `error` string is always the core's technical English message — this
// module adds only the localized dimension caption the spec asks for
// ("Ошибки {error, dimension} показывать человеко-понятно").

import type { Locale } from "../i18n/locale.ts";
import { t } from "../i18n/locale.ts";
import type { DictKey } from "../i18n/dict.ts";
import type { ApiError } from "../types.ts";

const dimensionKeys: Record<string, DictKey> = {
  require_tags: "dimension_require_tags",
  allow_roles: "dimension_allow_roles",
  max_level: "dimension_max_level",
  max_ttl: "dimension_max_ttl",
};

/**
 * Render an {@link ApiError} for display: the technical message verbatim,
 * plus a localized `(<dimension caption>)` suffix when the failure named an
 * envelope dimension.
 */
export function renderApiError(locale: Locale, error: ApiError): string {
  if (!error.dimension) return error.error;
  const key = dimensionKeys[error.dimension];
  const caption = key ? t(locale, key) : error.dimension;
  return `${error.error} (${caption})`;
}

/** Parse the JSON string a WASM binding throws into an {@link ApiError}. */
export function parseApiError(thrown: unknown): ApiError {
  if (typeof thrown === "string") {
    try {
      const parsed = JSON.parse(thrown) as unknown;
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        "error" in parsed &&
        typeof (parsed as { error: unknown }).error === "string"
      ) {
        const dimension = (parsed as { dimension?: unknown }).dimension;
        return {
          error: (parsed as { error: string }).error,
          ...(typeof dimension === "string" ? { dimension } : {}),
        };
      }
    } catch {
      // fall through to the generic message below
    }
    return { error: thrown };
  }
  return { error: String(thrown) };
}
